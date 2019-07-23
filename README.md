**UW** is a single-header C++11 wrapper of [libuv](https://github.com/libuv/libuv). 
 
# Usage

## handle
``` cpp
#include <iostream>
#include <uw.hpp>

int main() {
    uv_loop_t loop;
    uw::loop l(&loop);
    l.init();

    uw::timer timer;
    timer.init(l.raw());

    int i = 0;
    timer.start(100, 500, [&]() {
        std::cout << i << std::endl;
        if (++i > 3) {
            timer.stop();
            timer.close();
        }
    });

    l.run();
    l.close();

    return 0;
}
```

## request
``` cpp
#include <iostream>
#include <uw.hpp>

int main() {
    auto l = uw::loop::get_default();

    sockaddr sa{};
    int err = uv_ip4_addr("127.0.0.1", 12345, (sockaddr_in*)&sa);
    if (err) return 1;

    auto client = l.resource<uw::tcp>();

    uw::connect_req req;
    err = client->connect(&req, &sa, [client](int status) {
        std::cout << "connect " << (status ? uv_strerror(status) : "ok")
                  << std::endl;
        client->close();
    });
    if (err) return 1;

    l.run();
    l.close();

    return 0;
}
```

# design overview

``` cpp

namespace detail {
struct callback_base {
  virtual ~callback_base() = default;
};

template <class F>
struct callback : callback_base {
  explicit callback(F f) : f_(std::move(f)) {}

  template <class... A>
  void invoke(A&&... a) {
    f_(std::forward<A>(a)...);
  }

  F f_;
};

template <size_t N, class Sub>
struct tag;

template <class Sub>
struct callback_holder {
  callback_holder() = default;

  callback_holder(const callback_holder&) = delete;
  /*...*/

  template <class F, class Tag = tag<0, Sub>>
  void make_callback(F f) {
    get_cb<Tag>().reset(new callback<F>(std::move(f)));
  }

  template <class F, class Tag = tag<0, Sub>, class... A>
  void invoke_callback(A&&... a) {
    auto& cb = get_cb<Tag>();
    assert(cb);
    static_cast<callback<F>&>(*cb).invoke(std::forward<A>(a)...);
  }

private:
  size_t next_cb_id() {
    static size_t id = 0;
    return id++;
  }

  template <class Tag>
  std::unique_ptr<callback_base>& get_cb() {
    static size_t id = next_cb_id();
    if (id >= cb_.size()) cb_.resize(id + 1);
    return cb_[id];
  }

  std::vector<std::unique_ptr<callback_base>> cb_;
};

} // namespace detail

template <class Sub, class Handle>
struct handle : private Handle, protected detail::callback_holder<Sub> {
  Handle* raw() { return static_cast<Handle*>(this); }
  const Handle* raw() const { return static_cast<const Handle*>(this); }

  uv_handle_t* raw_handle() { return cast_to_uv<uv_handle_t*>(this); }
  const uv_handle_t* raw_handle() const {
    return cast_to_uv<const uv_handle_t*>(this);
  }
  /*...*/
  int is_closing() const { return uv_is_closing(raw_handle()); }

  void close() { uv_close(raw_handle(), nullptr); }

  template <class F>
  void close(F cb) {
    using tag = detail::tag<0, handle>;
    this->template make_callback<F, tag>(std::move(cb));
    uv_close(raw_handle(), [](uv_handle_t* h) {
      auto self = cast_from_uv<handle*>(h);
      self->template invoke_callback<F, tag>();
    });
  }
};

template <class Sub, class Req>
struct req : private Req, protected detail::callback_holder<Sub> {
  Req* raw() { return static_cast<Req*>(this); }
  const Req* raw() const { return static_cast<const Req*>(this); }

  uv_req_t* raw_req() { return cast_to_uv<uv_req_t*>(this); }
  const uv_req_t* raw_req() const { return cast_to_uv<const uv_req_t*>(this); }
  /*...*/
  int cancel() { return uv_cancel(raw_req()); }
};

template <class Sub, class Handle>
struct stream : handle<Sub, Handle> {
  uv_stream_t* raw_stream() { return cast_to_uv<uv_stream_t*>(this); }
  const uv_stream_t* raw_stream() const {
    return cast_to_uv<const uv_stream_t*>(this);
  }

  int accept(uv_stream_t* client) { return uv_accept(raw_stream(), client); }

  /*...*/
  template <class F>
  int listen(int backlog, F cb) {
    using tag = detail::tag<1, stream>;
    this->template make_callback<F, tag>(std::move(cb));
    return uv_listen(raw_stream(), backlog, [](uv_stream_t* h, int status) {
      auto self = cast_from_uv<stream*>(h);
      self->template invoke_callback<F, tag>(status);
    });
  }
};

struct connect_req : req<connect_req, uv_connect_t> {
  template <class F>
  int connect(uv_tcp_t* tcp, const struct sockaddr* addr, F cb) {
    this->make_callback(std::move(cb));
    return uv_tcp_connect(raw(), tcp, addr, [](uv_connect_t* h, int status) {
      auto self = cast_from_uv<connect_req*>(h);
      self->invoke_callback<F>(status);
    });
  }
  /*...*/
};

struct tcp : stream<tcp, uv_tcp_t> {
  int init(uv_loop_t* loop) { return uv_tcp_init(loop, raw()); }
  int init(uv_loop_t* loop, int flags) {
    return uv_tcp_init_ex(loop, raw(), flags);
  }
  int bind(const struct sockaddr* addr, unsigned int flags) {
    return uv_tcp_bind(raw(), addr, flags);
  }
  /*...*/
  template <class F>
  int connect(uw::connect_req* req, const struct sockaddr* addr, F cb) {
    return req->connect(raw(), addr, std::move(cb));
  }
};
```

# other C++ wrapper of libuv

Some of idea/design especially `uw::detail::callback_holder` comes from 
[uvw](https://github.com/skypjack/uvw) and [uvpp](https://github.com/larroy/uvpp),
but uw is more simple and easier to use.

# TODO

- [ ] allocator
- [ ] other libuv utilities
- [ ] example, test and document


