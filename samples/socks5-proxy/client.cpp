/* Copyright StrongLoop, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "defs.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* A connection is modeled as an abstraction on top of two simple state
 * machines, one for reading and one for writing.  Either state machine
 * is, when active, in one of three states: busy, done or stop; the fourth
 * and final state, dead, is an end state and only relevant when shutting
 * down the connection.  A short overview:
 *
 *                          busy                  done           stop
 *  ----------|---------------------------|--------------------|------|
 *  readable  | waiting for incoming data | have incoming data | idle |
 *  writable  | busy writing out data     | completed write    | idle |
 *
 * We could remove the done state from the writable state machine. For our
 * purposes, it's functionally equivalent to the stop state.
 *
 * When the connection with upstream has been established, the client_ctx
 * moves into a state where incoming data from the client is sent upstream
 * and vice versa, incoming data from upstream is sent to the client.  In
 * other words, we're just piping data back and forth.  See conn_cycle()
 * for details.
 *
 * An interesting deviation from libuv's I/O model is that reads are discrete
 * rather than continuous events.  In layman's terms, when a read operation
 * completes, the connection stops reading until further notice.
 *
 * The rationale for this approach is that we have to wait until the data
 * has been sent out again before we can reuse the read buffer.
 *
 * It also pleasingly unifies with the request model that libuv uses for
 * writes and everything else; libuv may switch to a request model for
 * reads in the future.
 */
enum conn_state {
  c_busy, /* Busy; waiting for incoming data or for a write to complete. */
  c_done, /* Done; read incoming data or write finished. */
  c_stop, /* Stopped. */
  c_dead
};

/* Session states. */
enum sess_state {
  s_handshake,      /* Wait for client handshake. */
  s_handshake_auth, /* Wait for client authentication data. */
  s_req_start,      /* Start waiting for request data. */
  s_req_parse,      /* Wait for request data. */
  s_req_lookup,     /* Wait for upstream hostname DNS lookup to complete. */
  s_req_connect,    /* Wait for uv_tcp_connect() to complete. */
  s_proxy_start,    /* Connected. Start piping data. */
  s_proxy,          /* Connected. Pipe data back and forth. */
  s_kill,           /* Tear down session. */
  s_almost_dead_0,  /* Waiting for finalizers to complete. */
  s_almost_dead_1,  /* Waiting for finalizers to complete. */
  s_almost_dead_2,  /* Waiting for finalizers to complete. */
  s_almost_dead_3,  /* Waiting for finalizers to complete. */
  s_almost_dead_4,  /* Waiting for finalizers to complete. */
  s_dead            /* Dead. Safe to free now. */
};

struct conn {
  unsigned char rdstate;
  unsigned char wrstate;
  unsigned int idle_timeout;
  struct client_ctx* client; /* Backlink to owning client context. */
  ssize_t result;
  uw::tcp tcp;
  uw::timer timer_handle; /* For detecting timeouts. */
  uw::write_req write_req;
  uw::getaddrinfo_req addrinfo_req;
  uw::connect_req connect_req;
  /* We only need one of these at a time so make them share memory. */
  union {
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr4;
    struct sockaddr addr;
    char buf[2048]; /* Scratch space. Used to read data into. */
  } t;

  void timer_reset();
  void getaddrinfo(const char* hostname);
  int connect();
  void read();
  void write(const void* data, unsigned int len);
  void close();
};

struct client_ctx {
  unsigned int state;
  server_ctx* sx; /* Backlink to owning server context. */
  s5_ctx parser;  /* The SOCKS protocol parser. */
  conn incoming;  /* Connection with the SOCKS client. */
  conn outgoing;  /* Connection with upstream. */

  void do_next();
  int do_handshake();
  int do_handshake_auth();
  int do_req_start();
  int do_req_parse();
  int do_req_lookup();
  int do_req_connect_start();
  int do_req_connect();
  int do_proxy_start();
  int do_proxy();
  int do_kill();
  int do_almost_dead();
};

static int conn_cycle(const char* who, conn* a, conn* b);
static void conn_alloc(uv_handle_t* handle, size_t size, uv_buf_t* buf);

client_ctx* client_new(server_ctx* sx) {
  auto cx = new client_ctx();
  CHECK(0 == cx->incoming.tcp.init(sx->loop));
  CHECK(0 == sx->tcp_handle.accept(cx->incoming.tcp.raw_stream()));
  return cx;
}

/* |incoming| has been initialized by server.c when this is called. */
void client_finish_init(server_ctx* sx, client_ctx* cx) {
  conn* incoming;
  conn* outgoing;

  cx->sx    = sx;
  cx->state = s_handshake;
  s5_init(&cx->parser);

  incoming               = &cx->incoming;
  incoming->client       = cx;
  incoming->result       = 0;
  incoming->rdstate      = c_stop;
  incoming->wrstate      = c_stop;
  incoming->idle_timeout = sx->idle_timeout;
  CHECK(0 == incoming->timer_handle.init(sx->loop));

  outgoing               = &cx->outgoing;
  outgoing->client       = cx;
  outgoing->result       = 0;
  outgoing->rdstate      = c_stop;
  outgoing->wrstate      = c_stop;
  outgoing->idle_timeout = sx->idle_timeout;
  CHECK(0 == outgoing->tcp.init(cx->sx->loop));
  CHECK(0 == outgoing->timer_handle.init(cx->sx->loop));

  /* Wait for the initial packet. */
  incoming->read();
}

/* This is the core state machine that drives the client <-> upstream proxy.
 * We move through the initial handshake and authentication steps first and
 * end up (if all goes well) in the proxy state where we're just proxying
 * data between the client and upstream.
 */
void client_ctx::do_next() {
  auto cx = this;
  int new_state;

  ASSERT(cx->state != s_dead);
  switch (cx->state) {
  case s_handshake: new_state = cx->do_handshake(); break;
  case s_handshake_auth: new_state = cx->do_handshake_auth(); break;
  case s_req_start: new_state = cx->do_req_start(); break;
  case s_req_parse: new_state = cx->do_req_parse(); break;
  case s_req_lookup: new_state = cx->do_req_lookup(); break;
  case s_req_connect: new_state = cx->do_req_connect(); break;
  case s_proxy_start: new_state = cx->do_proxy_start(); break;
  case s_proxy: new_state = cx->do_proxy(); break;
  case s_kill: new_state = cx->do_kill(); break;
  case s_almost_dead_0:
  case s_almost_dead_1:
  case s_almost_dead_2:
  case s_almost_dead_3:
  case s_almost_dead_4: new_state = cx->do_almost_dead(); break;
  default: UNREACHABLE();
  }
  cx->state = new_state;

  if (cx->state == s_dead) {
    if (DEBUG_CHECKS) {
      memset(&cx->parser, -1, sizeof(cx->parser));
      memset(&cx->state, -1, sizeof(cx->state));
      memset(&cx->sx, -1, sizeof(cx->sx));
      // TODO
    }
    delete cx;
  }
}

int client_ctx::do_handshake() {
  auto cx = this;
  unsigned int methods;
  conn* incoming;
  s5_ctx* parser;
  uint8_t* data;
  size_t size;
  s5_err err;

  parser   = &cx->parser;
  incoming = &cx->incoming;
  ASSERT(incoming->rdstate == c_done);
  ASSERT(incoming->wrstate == c_stop);
  incoming->rdstate = c_stop;

  if (incoming->result < 0) {
    pr_err("read error: %s", uv_strerror(incoming->result));
    return cx->do_kill();
  }

  data = (uint8_t*)incoming->t.buf;
  size = (size_t)incoming->result;
  err  = s5_parse(parser, &data, &size);
  if (err == s5_ok) {
    incoming->read();
    return s_handshake; /* Need more data. */
  }

  if (size != 0) {
    /* Could allow a round-trip saving shortcut here if the requested auth
     * method is S5_AUTH_NONE (provided unauthenticated traffic is allowed.)
     * Requires client support however.
     */
    pr_err("junk in handshake");
    return cx->do_kill();
  }

  if (err != s5_auth_select) {
    pr_err("handshake error: %s", s5_strerror(err));
    return cx->do_kill();
  }

  methods = s5_auth_methods(parser);
  if ((methods & S5_AUTH_NONE) && can_auth_none(cx->sx, cx)) {
    s5_select_auth(parser, S5_AUTH_NONE);
    incoming->write("\5\0", 2); /* No auth required. */
    return s_req_start;
  }

  if ((methods & S5_AUTH_PASSWD) && can_auth_passwd(cx->sx, cx)) {
    /* TODO(bnoordhuis) Implement username/password auth. */
  }

  incoming->write("\5\377", 2); /* No acceptable auth. */
  return s_kill;
}

/* TODO(bnoordhuis) Implement username/password auth. */
int client_ctx::do_handshake_auth() {
  auto cx = this;
  UNREACHABLE();
  return cx->do_kill();
}

int client_ctx::do_req_start() {
  auto cx = this;
  conn* incoming;

  incoming = &cx->incoming;
  ASSERT(incoming->rdstate == c_stop);
  ASSERT(incoming->wrstate == c_done);
  incoming->wrstate = c_stop;

  if (incoming->result < 0) {
    pr_err("write error: %s", uv_strerror(incoming->result));
    return cx->do_kill();
  }

  incoming->read();
  return s_req_parse;
}

int client_ctx::do_req_parse() {
  auto cx = this;
  conn* incoming;
  conn* outgoing;
  s5_ctx* parser;
  uint8_t* data;
  size_t size;
  s5_err err;

  parser   = &cx->parser;
  incoming = &cx->incoming;
  outgoing = &cx->outgoing;
  ASSERT(incoming->rdstate == c_done);
  ASSERT(incoming->wrstate == c_stop);
  ASSERT(outgoing->rdstate == c_stop);
  ASSERT(outgoing->wrstate == c_stop);
  incoming->rdstate = c_stop;

  if (incoming->result < 0) {
    pr_err("read error: %s", uv_strerror(incoming->result));
    return cx->do_kill();
  }

  data = (uint8_t*)incoming->t.buf;
  size = (size_t)incoming->result;
  err  = s5_parse(parser, &data, &size);
  if (err == s5_ok) {
    incoming->read();
    return s_req_parse; /* Need more data. */
  }

  if (size != 0) {
    pr_err("junk in request %u", (unsigned)size);
    return cx->do_kill();
  }

  if (err != s5_exec_cmd) {
    pr_err("request error: %s", s5_strerror(err));
    return cx->do_kill();
  }

  if (parser->cmd == s5_cmd_tcp_bind) {
    /* Not supported but relatively straightforward to implement. */
    pr_warn("BIND requests are not supported.");
    return cx->do_kill();
  }

  if (parser->cmd == s5_cmd_udp_assoc) {
    /* Not supported.  Might be hard to implement because libuv has no
     * functionality for detecting the MTU size which the RFC mandates.
     */
    pr_warn("UDP ASSOC requests are not supported.");
    return cx->do_kill();
  }
  ASSERT(parser->cmd == s5_cmd_tcp_connect);

  if (parser->atyp == s5_atyp_host) {
    outgoing->getaddrinfo((const char*)parser->daddr);
    return s_req_lookup;
  }

  if (parser->atyp == s5_atyp_ipv4) {
    memset(&outgoing->t.addr4, 0, sizeof(outgoing->t.addr4));
    outgoing->t.addr4.sin_family = AF_INET;
    outgoing->t.addr4.sin_port   = htons(parser->dport);
    memcpy(&outgoing->t.addr4.sin_addr, parser->daddr,
        sizeof(outgoing->t.addr4.sin_addr));
  } else if (parser->atyp == s5_atyp_ipv6) {
    memset(&outgoing->t.addr6, 0, sizeof(outgoing->t.addr6));
    outgoing->t.addr6.sin6_family = AF_INET6;
    outgoing->t.addr6.sin6_port   = htons(parser->dport);
    memcpy(&outgoing->t.addr6.sin6_addr, parser->daddr,
        sizeof(outgoing->t.addr6.sin6_addr));
  } else {
    UNREACHABLE();
  }

  return cx->do_req_connect_start();
}

int client_ctx::do_req_lookup() {
  auto cx = this;
  s5_ctx* parser;
  conn* incoming;
  conn* outgoing;

  parser   = &cx->parser;
  incoming = &cx->incoming;
  outgoing = &cx->outgoing;
  ASSERT(incoming->rdstate == c_stop);
  ASSERT(incoming->wrstate == c_stop);
  ASSERT(outgoing->rdstate == c_stop);
  ASSERT(outgoing->wrstate == c_stop);

  if (outgoing->result < 0) {
    /* TODO(bnoordhuis) Escape control characters in parser->daddr. */
    pr_err("lookup error for \"%s\": %s", parser->daddr,
        uv_strerror(outgoing->result));
    /* Send back a 'Host unreachable' reply. */
    incoming->write("\5\4\0\1\0\0\0\0\0\0", 10);
    return s_kill;
  }

  /* Don't make assumptions about the offset of sin_port/sin6_port. */
  switch (outgoing->t.addr.sa_family) {
  case AF_INET: outgoing->t.addr4.sin_port = htons(parser->dport); break;
  case AF_INET6: outgoing->t.addr6.sin6_port = htons(parser->dport); break;
  default: UNREACHABLE();
  }

  return cx->do_req_connect_start();
}

/* Assumes that cx->outgoing.t.sa contains a valid AF_INET/AF_INET6 address. */
int client_ctx::do_req_connect_start() {
  auto cx = this;
  conn* incoming;
  conn* outgoing;
  int err;

  incoming = &cx->incoming;
  outgoing = &cx->outgoing;
  ASSERT(incoming->rdstate == c_stop);
  ASSERT(incoming->wrstate == c_stop);
  ASSERT(outgoing->rdstate == c_stop);
  ASSERT(outgoing->wrstate == c_stop);

  if (!can_access(cx->sx, cx, &outgoing->t.addr)) {
    pr_warn("connection not allowed by ruleset");
    /* Send a 'Connection not allowed by ruleset' reply. */
    incoming->write("\5\2\0\1\0\0\0\0\0\0", 10);
    return s_kill;
  }

  err = outgoing->connect();
  if (err != 0) {
    pr_err("connect error: %s\n", uv_strerror(err));
    return cx->do_kill();
  }

  return s_req_connect;
}

int client_ctx::do_req_connect() {
  auto cx = this;
  const struct sockaddr_in6* in6;
  const struct sockaddr_in* in;
  char addr_storage[sizeof(*in6)];
  conn* incoming;
  conn* outgoing;
  uint8_t* buf;
  int addrlen;

  incoming = &cx->incoming;
  outgoing = &cx->outgoing;
  ASSERT(incoming->rdstate == c_stop);
  ASSERT(incoming->wrstate == c_stop);
  ASSERT(outgoing->rdstate == c_stop);
  ASSERT(outgoing->wrstate == c_stop);

  /* Build and send the reply.  Not very pretty but gets the job done. */
  buf = (uint8_t*)incoming->t.buf;
  if (outgoing->result == 0) {
    /* The RFC mandates that the SOCKS server must include the local port
     * and address in the reply.  So that's what we do.
     */
    addrlen = sizeof(addr_storage);
    CHECK(
        0
        == outgoing->tcp.getsockname((struct sockaddr*)addr_storage, &addrlen));
    buf[0] = 5; /* Version. */
    buf[1] = 0; /* Success. */
    buf[2] = 0; /* Reserved. */
    if (addrlen == sizeof(*in)) {
      buf[3] = 1; /* IPv4. */
      in     = (const struct sockaddr_in*)&addr_storage;
      memcpy(buf + 4, &in->sin_addr, 4);
      memcpy(buf + 8, &in->sin_port, 2);
      incoming->write(buf, 10);
    } else if (addrlen == sizeof(*in6)) {
      buf[3] = 4; /* IPv6. */
      in6    = (const struct sockaddr_in6*)&addr_storage;
      memcpy(buf + 4, &in6->sin6_addr, 16);
      memcpy(buf + 20, &in6->sin6_port, 2);
      incoming->write(buf, 22);
    } else {
      UNREACHABLE();
    }
    return s_proxy_start;
  } else {
    pr_err("upstream connection error: %s\n", uv_strerror(outgoing->result));
    /* Send a 'Connection refused' reply. */
    incoming->write("\5\5\0\1\0\0\0\0\0\0", 10);
    return s_kill;
  }

  UNREACHABLE();
  return s_kill;
}

int client_ctx::do_proxy_start() {
  auto cx = this;
  conn* incoming;
  conn* outgoing;

  incoming = &cx->incoming;
  outgoing = &cx->outgoing;
  ASSERT(incoming->rdstate == c_stop);
  ASSERT(incoming->wrstate == c_done);
  ASSERT(outgoing->rdstate == c_stop);
  ASSERT(outgoing->wrstate == c_stop);
  incoming->wrstate = c_stop;

  if (incoming->result < 0) {
    pr_err("write error: %s", uv_strerror(incoming->result));
    return cx->do_kill();
  }

  incoming->read();
  outgoing->read();
  return s_proxy;
}

/* Proxy incoming data back and forth. */
int client_ctx::do_proxy() {
  auto cx = this;
  if (conn_cycle("client", &cx->incoming, &cx->outgoing)) {
    return cx->do_kill();
  }

  if (conn_cycle("upstream", &cx->outgoing, &cx->incoming)) {
    return cx->do_kill();
  }

  return s_proxy;
}

int client_ctx::do_kill() {
  auto cx = this;
  int new_state;

  if (cx->state >= s_almost_dead_0) {
    return cx->state;
  }

  /* Try to cancel the request. The callback still runs but if the
   * cancellation succeeded, it gets called with status=UV_ECANCELED.
   */
  new_state = s_almost_dead_1;
  if (cx->state == s_req_lookup) {
    new_state = s_almost_dead_0;
    cx->outgoing.connect_req.cancel(); // TODO
  }

  cx->incoming.close();
  cx->outgoing.close();
  return new_state;
}

int client_ctx::do_almost_dead() {
  auto cx = this;
  ASSERT(cx->state >= s_almost_dead_0);
  return cx->state + 1; /* Another finalizer completed. */
}

static int conn_cycle(const char* who, conn* a, conn* b) {
  if (a->result < 0) {
    if (a->result != UV_EOF) {
      pr_err("%s error: %s", who, uv_strerror(a->result));
    }
    return -1;
  }

  if (b->result < 0) {
    return -1;
  }

  if (a->wrstate == c_done) {
    a->wrstate = c_stop;
  }

  /* The logic is as follows: read when we don't write and write when we don't
   * read.  That gives us back-pressure handling for free because if the peer
   * sends data faster than we consume it, TCP congestion control kicks in.
   */
  if (a->wrstate == c_stop) {
    if (b->rdstate == c_stop) {
      b->read();
    } else if (b->rdstate == c_done) {
      a->write(b->t.buf, b->result);
      b->rdstate = c_stop; /* Triggers the call to conn_read() above. */
    }
  }

  return 0;
}

void conn::timer_reset() {
  auto c = this;
  CHECK(0 == c->timer_handle.start(c->idle_timeout, 0, [c] {
    c->result = UV_ETIMEDOUT;
    c->client->do_next();
  }));
}

void conn::getaddrinfo(const char* hostname) {
  auto c = this;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  CHECK(0
        == c->addrinfo_req.getaddrinfo(c->client->sx->loop, hostname, NULL,
            &hints, [c](int status, uw::addrinfo_ptr ai) {
              c->result = status;

              if (status == 0) {
                /* FIXME(bnoordhuis) Should try all addresses. */
                if (ai->ai_family == AF_INET) {
                  c->t.addr4 = *(const struct sockaddr_in*)ai->ai_addr;
                } else if (ai->ai_family == AF_INET6) {
                  c->t.addr6 = *(const struct sockaddr_in6*)ai->ai_addr;
                } else {
                  UNREACHABLE();
                }
              }

              c->client->do_next();
            }));
  c->timer_reset();
}

/* Assumes that c->t.sa contains a valid AF_INET or AF_INET6 address. */
int conn::connect() {
  auto c = this;
  ASSERT(c->t.addr.sa_family == AF_INET || c->t.addr.sa_family == AF_INET6);
  c->timer_reset();
  return c->tcp.connect(&c->connect_req, &c->t.addr, [c](int status) {
    if (status == UV_ECANCELED) {
      return; /* Handle has been closed. */
    }

    c->result = status;
    c->client->do_next();
  });
}

void conn::read() {
  auto c = this;
  CHECK(
      0
      == c->tcp.read_start(conn_alloc, [c](ssize_t nread, const uv_buf_t* buf) {
           ASSERT(c->t.buf == buf->base);
           ASSERT(c->rdstate == c_busy);
           c->rdstate = c_done;
           c->result  = nread;

           c->tcp.read_stop();
           c->client->do_next();
         }));
  ASSERT(c->rdstate == c_stop);
  c->rdstate = c_busy;
  c->timer_reset();
}

static void conn_alloc(uv_handle_t* handle, size_t size, uv_buf_t* buf) {
  (void)size;
  auto h  = uw::cast_from_uv<uw::tcp*>(handle);
  conn* c = CONTAINER_OF(h, conn, tcp);
  ASSERT(c->rdstate == c_busy);
  buf->base = c->t.buf;
  buf->len  = sizeof(c->t.buf);
}

void conn::write(const void* data, unsigned int len) {
  auto c = this;
  uv_buf_t buf;

  ASSERT(c->wrstate == c_stop || c->wrstate == c_done);
  c->wrstate = c_busy;

  /* It's okay to cast away constness here, uv_write() won't modify the
   * memory.
   */
  buf.base = (char*)data;
  buf.len  = len;

  CHECK(0 == c->tcp.write(&c->write_req, &buf, 1, [c](int status) {
    if (status == UV_ECANCELED) {
      return; /* Handle has been closed. */
    }

    c->wrstate = c_done;
    c->result  = status;
    c->client->do_next();
  }));
  c->timer_reset();
}

void conn::close() {
  auto c = this;
  ASSERT(c->rdstate != c_dead);
  ASSERT(c->wrstate != c_dead);
  c->rdstate = c_dead;
  c->wrstate = c_dead;

  c->tcp.close([c] { c->client->do_next(); });
  c->timer_handle.close([c] { c->client->do_next(); });
}
