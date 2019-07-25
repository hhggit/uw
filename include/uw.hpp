//  Copyright 2019 hhggit.
//
//  Distributed under the Boost Software License, Version 1.0.
//
//  See accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt

#ifndef UW_UW_HPP
#define UW_UW_HPP

#include <cassert>
#include <memory>
#include <type_traits>
#include <vector>

#include <uv.h>

namespace uw {

struct loop;

// Handle types
template <class, class>
struct handle;
template <class, class>
struct stream;
struct tcp;
struct udp;
struct pipe;
struct tty;
struct poll;
struct timer;
struct prepare;
struct check;
struct idle;
struct async;
struct process;
struct fs_event;
struct fs_poll;

// Request types
template <class, class>
struct req;
struct getaddrinfo_req;
struct getnameinfo_req;
struct shutdown_req;
struct write_req;
struct connect_req;
struct udp_send_req;
struct fs_req;
struct work_req;

namespace detail {
template <class B, class D>
struct is_base_of : std::false_type {};

template <class T>
struct is_base_of<T, T> : std::true_type {};

#define XX(HANDLE, handle)                                                     \
  template <>                                                                  \
  struct is_base_of<uv_handle_t, uv_##handle##_t> : std::true_type {};
UV_HANDLE_TYPE_MAP(XX)
#undef XX

#define XX(REQ, req)                                                           \
  template <>                                                                  \
  struct is_base_of<uv_req_t, uv_##req##_t> : std::true_type {};
UV_REQ_TYPE_MAP(XX)
#undef XX

template <>
struct is_base_of<uv_stream_t, uv_tcp_t> : std::true_type {};
template <>
struct is_base_of<uv_stream_t, uv_pipe_t> : std::true_type {};
template <>
struct is_base_of<uv_stream_t, uv_tty_t> : std::true_type {};

template <class T, class U>
struct has_same_cvrp
    : std::integral_constant<bool,
          std::is_const<T>::value == std::is_const<U>::value
              && std::is_volatile<T>::value == std::is_volatile<U>::value
              && std::is_lvalue_reference<T>::value
                     == std::is_lvalue_reference<U>::value
              && std::is_rvalue_reference<T>::value
                     == std::is_rvalue_reference<U>::value
              && std::is_pointer<T>::value == std::is_pointer<U>::value> {};

template <class T>
using remove_cvrp_t = typename std::remove_cv<typename std::remove_reference<
    typename std::remove_pointer<T>::type>::type>::type;

template <class T, class U>
struct apply_cvrp {
  using type = U;
};

template <class T, class U>
using apply_cvrp_t = typename apply_cvrp<T, U>::type;

template <class T, class U>
struct apply_cvrp<T*, U> : std::add_pointer<apply_cvrp_t<T, U>> {};
template <class T, class U>
struct apply_cvrp<T&, U> : std::add_lvalue_reference<apply_cvrp_t<T, U>> {};
template <class T, class U>
struct apply_cvrp<T&&, U> : std::add_rvalue_reference<apply_cvrp_t<T, U>> {};
template <class T, class U>
struct apply_cvrp<const T, U> : std::add_const<apply_cvrp_t<T, U>> {};
template <class T, class U>
struct apply_cvrp<volatile T, U> : std::add_volatile<apply_cvrp_t<T, U>> {};
template <class T, class U>
struct apply_cvrp<const volatile T, U> : std::add_cv<apply_cvrp_t<T, U>> {};

template <class T, class U>
T safe_cast(U h) {
  static_assert(has_same_cvrp<T, U>::value, "");
  using t = remove_cvrp_t<T>;
  using u = remove_cvrp_t<U>;
  static_assert(is_base_of<t, u>::value, "");
  return reinterpret_cast<T>(h);
}

template <class T, class U>
T unsafe_cast(U h) {
  static_assert(has_same_cvrp<T, U>::value, "");
  using t = remove_cvrp_t<T>;
  using u = remove_cvrp_t<U>;
  static_assert(is_base_of<t, u>::value || is_base_of<u, t>::value, "");
  return reinterpret_cast<T>(h);
}

}; // namespace detail

template <class UW, class UV>
UW cast_from_uv(UV from) {
  using raw_type = typename std::remove_pointer<decltype(
      std::declval<detail::remove_cvrp_t<UW>>().raw())>::type;
  // static_cast<UW*>(raw_type*) WON'T work if raw_type is a private base of UW.
  // we can use reinterpret_cast ONLY IF raw_type is first base of UW.
  return reinterpret_cast<UW>(
      detail::unsafe_cast<detail::apply_cvrp_t<UW, raw_type>>(from));
}

template <class UV, class UW>
UV cast_to_uv(UW* from) {
  return detail::safe_cast<UV>(from->raw());
}
template <class UV, class UW>
UV cast_to_uv(UW& from) {
  return detail::safe_cast<UV>(*from.raw());
}

struct loop {
  explicit loop(uv_loop_t* h) : h_(h) {}
  static loop get_default() { return loop{uv_default_loop()}; }

  uv_loop_t* raw() { return h_; }
  const uv_loop_t* raw() const { return h_; }

  template <class T, class... A>
  std::shared_ptr<T> resource(A&&... a) {
    auto p = std::make_shared<T>();
    if (p->init(raw(), std::forward<A>(a)...) != 0) p.reset();
    return p;
  }

  int init() { return uv_loop_init(h_); }
  int close() { return uv_loop_close(h_); }

  static size_t size() { return uv_loop_size(); }
  int alive() const { return uv_loop_alive(h_); }
  template <class... Ts>
  int configure(uv_loop_option&& opt, Ts&&... ts) {
    return uv_loop_configure(
        h_, std::forward<uv_loop_option>(opt), std::forward<Ts>(ts)...);
  }
  int fork() { return uv_loop_fork(h_); }

  int run(uv_run_mode mode = UV_RUN_DEFAULT) { return uv_run(h_, mode); }
  void stop() { return uv_stop(h_); }

  void update_time() { return uv_update_time(h_); }
  uint64_t now() const { return uv_now(h_); }

  int backend_fd() const { return uv_backend_fd(h_); };
  int backend_timeout() const { return uv_backend_timeout(h_); }

  void walk(uv_walk_cb cb, void* arg) { return uv_walk(h_, cb, arg); }

  void print_all_handles(FILE* stream) {
    return uv_print_all_handles(h_, stream);
  }
  void print_all_active_handles(FILE* stream) {
    return uv_print_active_handles(h_, stream);
  }

  void* get_data() const { return uv_loop_get_data(h_); }
  void set_data(void* data) { return uv_loop_set_data(h_, data); }

private:
  uv_loop_t* h_;
};

namespace detail {

struct callback {
  template <class F>
  explicit callback(F f)
      : ptr_(new F(std::move(f))),
        deleter_([](void* p) { delete reinterpret_cast<F*>(p); }) {}

  ~callback() {
    assert((bool)ptr_ == (bool)deleter_);
    if (ptr_) deleter_(ptr_);
  }

  callback()                = default;
  callback(const callback&) = delete;
  callback& operator=(const callback&) = delete;
  callback(callback&& other) noexcept {
    ptr_           = other.ptr_;
    deleter_       = other.deleter_;
    other.deleter_ = nullptr;
    other.ptr_     = nullptr;
  }
  callback& operator=(callback&& other) noexcept {
    assert(&other != this);
    assert((bool)ptr_ == (bool)deleter_);
    if (ptr_) deleter_(ptr_);
    ptr_           = other.ptr_;
    deleter_       = other.deleter_;
    other.deleter_ = nullptr;
    other.ptr_     = nullptr;
    return *this;
  }

  void* ptr_              = nullptr;
  void (*deleter_)(void*) = nullptr;
};

template <size_t N, class Sub>
struct tag;

template <bool OneShot = false>
struct reset_if {
  static void call(callback& temp, callback& holder) {
    if (!holder.ptr_) holder = std::move(temp);
  }
};
template <>
struct reset_if<true> {
  static void call(callback&, callback&) {}
};

template <class Sub, bool OneShot = false>
struct callback_holder {
  callback_holder() = default;

  callback_holder(const callback_holder&) = delete;
  callback_holder& operator=(const callback_holder&) = delete;

  callback_holder(callback_holder&&) = delete;
  callback_holder& operator=(callback_holder&&) = delete;

  template <class F, class Tag = tag<0, Sub>>
  void make_callback(F f) {
    get_cb<Tag>() = callback(std::move(f));
  }

  template <class F, class Tag = tag<0, Sub>,
      class InvokePolicy = reset_if<OneShot>, class... A>
  void invoke_callback(A&&... a) {
    auto& holder = get_cb<Tag>();
    assert(holder.ptr_);

    // user may change holder in F so we must extend lifetime
    callback temp(std::move(holder));
    assert(temp.ptr_ && !holder.ptr_);

    (*reinterpret_cast<F*>(temp.ptr_))(std::forward<A>(a)...);

    InvokePolicy::call(temp, holder);
  }

private:
  size_t next_cb_id() {
    static size_t id = 0;
    return id++;
  }

  template <class Tag>
  callback& get_cb() {
    static size_t id = next_cb_id();
    if (id >= cb_.size()) cb_.resize(id + 1);
    return cb_[id];
  }

  std::vector<callback> cb_;
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

  void ref() { return uv_ref(raw_handle()); }
  void unref() { return uv_unref(raw_handle()); }
  int has_ref() const { return uv_has_ref(raw_handle()); }

  static size_t size(uv_handle_type t) { return uv_handle_size(t); }
  uv_handle_type get_type() const { return uv_handle_get_type(raw_handle()); }
  static const char* type_name(uv_handle_type t) {
    return uv_handle_type_name(t);
  }
  uv_loop_t* get_loop() { return uv_handle_get_loop(raw_handle()); }
  void* get_data() const { return uv_handle_get_data(raw_handle()); }
  void set_data(void* data) { uv_handle_set_data(raw_handle(), data); }

  int is_active() const { return uv_is_active(raw_handle()); }

  int send_buffer_size(int* value) {
    return uv_send_buffer_size(raw_handle(), value);
  }

  int recv_buffer_size(int* value) {
    return uv_recv_buffer_size(raw_handle(), value);
  }

  int fileno(uv_os_fd_t* fd) const { return uv_fileno(raw_handle(), fd); }

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
struct req : private Req, protected detail::callback_holder<Sub, true> {
  Req* raw() { return static_cast<Req*>(this); }
  const Req* raw() const { return static_cast<const Req*>(this); }

  uv_req_t* raw_req() { return cast_to_uv<uv_req_t*>(this); }
  const uv_req_t* raw_req() const { return cast_to_uv<const uv_req_t*>(this); }

  static size_t size(uv_req_type t) { return uv_req_size(t); }
  void* get_data() const { return uv_req_get_data(raw_req()); }
  void set_data(void* data) { return uv_req_set_data(raw_req(), data); }
  uv_req_type get_type() const { return uv_req_get_type(raw_req()); }
  static const char* type_name(uv_req_type t) { return uv_req_type_name(t); }
  const char* type_name() const { return type_name(get_type()); }

  int cancel() { return uv_cancel(raw_req()); }
};

struct shutdown_req : req<shutdown_req, uv_shutdown_t> {
  template <class F>
  int shutdown(uv_stream_t* stream, F cb) {
    this->make_callback(std::move(cb));
    return uv_shutdown(raw(), stream, [](uv_shutdown_t* h, int status) {
      auto self = cast_from_uv<shutdown_req*>(h);
      self->invoke_callback<F>(status);
    });
  }
};

struct write_req : req<write_req, uv_write_t> {
  template <class F>
  int write(
      uv_stream_t* stream, const uv_buf_t bufs[], unsigned int nbufs, F cb) {
    this->make_callback(std::move(cb));
    return uv_write(raw(), stream, bufs, nbufs, [](uv_write_t* h, int status) {
      auto self = cast_from_uv<write_req*>(h);
      self->invoke_callback<F>(status);
    });
  }
  template <class F>
  int write(uv_stream_t* stream, const uv_buf_t bufs[], unsigned int nbufs,
      uv_stream_t* send_handle, F cb) {
    using tag = detail::tag<1, write_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_write2(
        raw(), stream, bufs, nbufs, send_handle, [](uv_write_t* h, int status) {
          auto self = cast_from_uv<write_req*>(h);
          self->invoke_callback<F, tag>(status);
        });
  }
};

template <class Sub, class Handle>
struct stream : handle<Sub, Handle> {
  uv_stream_t* raw_stream() { return cast_to_uv<uv_stream_t*>(this); }
  const uv_stream_t* raw_stream() const {
    return cast_to_uv<const uv_stream_t*>(this);
  }

  size_t get_write_queue_size() const {
    return uv_stream_get_write_queue_size(raw_stream());
  }

  int accept(uv_stream_t* client) { return uv_accept(raw_stream(), client); }

  int read_stop() { return uv_read_stop(raw_stream()); }

  int try_write(const uv_buf_t bufs[], unsigned int nbufs) {
    return uv_try_write(raw_stream(), bufs, nbufs);
  }

  int is_readable() const { return uv_is_readable(raw_stream()); }
  int is_writable() const { return uv_is_writable(raw_stream()); }

  int set_blocking(int blocking) {
    return uv_stream_set_blocking(raw_stream(), blocking);
  }

  template <class F>
  int listen(int backlog, F cb) {
    using tag = detail::tag<1, stream>;
    this->template make_callback<F, tag>(std::move(cb));
    return uv_listen(raw_stream(), backlog, [](uv_stream_t* h, int status) {
      auto self = cast_from_uv<stream*>(h);
      self->template invoke_callback<F, tag>(status);
    });
  }

  template <class F>
  int read_start(uv_alloc_cb alloc_cb, F read_cb) {
    using tag = detail::tag<0, stream>;
    this->template make_callback<F, tag>(std::move(read_cb));
    return uv_read_start(raw_stream(), alloc_cb,
        [](uv_stream_t* h, ssize_t n, const uv_buf_t* b) {
          auto self = cast_from_uv<stream*>(h);
          self->template invoke_callback<F, tag>(n, b);
        });
  }

  template <class F>
  int shutdown(shutdown_req* req, F cb) {
    return req->shutdown(raw_stream(), std::move(cb));
  }

  template <class F>
  int write(write_req* req, const uv_buf_t bufs[], unsigned int nbufs, F cb) {
    return req->write(raw_stream(), bufs, nbufs, std::move(cb));
  }

  template <class F>
  int write(write_req* req, const uv_buf_t bufs[], unsigned int nbufs,
      uv_stream_t* send_handle, F cb) {
    return req->write(raw_stream(), bufs, nbufs, send_handle, std::move(cb));
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

  template <class F>
  void connect(uv_pipe_t* pipe, const char* name, F cb) {
    using tag = detail::tag<1, connect_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_pipe_connect(raw(), pipe, name, [](uv_connect_t* h, int status) {
      auto self = cast_from_uv<connect_req*>(h);
      self->invoke_callback<F, tag>(status);
    });
  }
};

struct tcp : stream<tcp, uv_tcp_t> {
  int init(uv_loop_t* loop) { return uv_tcp_init(loop, raw()); }
  int init(uv_loop_t* loop, int flags) {
    return uv_tcp_init_ex(loop, raw(), flags);
  }
  int init_ex(uv_loop_t* loop, int flags) {
    return uv_tcp_init_ex(loop, raw(), flags);
  }
  int open(uv_os_sock_t sock) { return uv_tcp_open(raw(), sock); }
  int nodelay(int enable) { return uv_tcp_nodelay(raw(), enable); }
  int keepalive(int enable, unsigned int delay) {
    return uv_tcp_keepalive(raw(), enable, delay);
  }
  int simultaneous_accepts(int enable) {
    return uv_tcp_simultaneous_accepts(raw(), enable);
  }
  int bind(const struct sockaddr* addr, unsigned int flags) {
    return uv_tcp_bind(raw(), addr, flags);
  }
  int getsockname(struct sockaddr* name, int* namelen) const {
    return uv_tcp_getsockname(raw(), name, namelen);
  }
  int getpeername(struct sockaddr* name, int* namelen) const {
    return uv_tcp_getpeername(raw(), name, namelen);
  }

  template <class F>
  int connect(uw::connect_req* req, const struct sockaddr* addr, F cb) {
    return req->connect(raw(), addr, std::move(cb));
  }
};

struct udp_send_req : req<udp_send_req, uv_udp_send_t> {
  template <class F>
  int send(uv_udp_t* udp, const uv_buf_t bufs[], unsigned int nbufs,
      const struct sockaddr* addr, F cb) {
    this->make_callback(std::move(cb));
    return uv_udp_send(
        raw(), udp, bufs, nbufs, addr, [](uv_udp_send_t* h, int status) {
          auto self = cast_from_uv<udp_send_req*>(h);
          self->invoke_callback<F>(status);
        });
  }
};

struct udp : handle<udp, uv_udp_t> {
  int init(uv_loop_t* loop) { return uv_udp_init(loop, raw()); }
  int init(uv_loop_t* loop, int flags) {
    return uv_udp_init_ex(loop, raw(), flags);
  }
  int init_ex(uv_loop_t* loop, int flags) {
    return uv_udp_init_ex(loop, raw(), flags);
  }
  int open(uv_os_sock_t sock) { return uv_udp_open(raw(), sock); }
  int bind(const struct sockaddr* addr, unsigned int flags) {
    return uv_udp_bind(raw(), addr, flags);
  }
  int connect(const struct sockaddr* addr) {
    return uv_udp_connect(raw(), addr);
  }
  int getsockname(struct sockaddr* name, int* namelen) const {
    return uv_udp_getsockname(raw(), name, namelen);
  }
  int getpeername(struct sockaddr* name, int* namelen) const {
    return uv_udp_getpeername(raw(), name, namelen);
  }

  int set_membership(const char* multicast_addr, const char* interface_addr,
      uv_membership membership) {
    return uv_udp_set_membership(
        raw(), multicast_addr, interface_addr, membership);
  }
  int set_multicast_loop(int on) {
    return uv_udp_set_multicast_loop(raw(), on);
  }
  int set_multicast_ttl(int ttl) {
    return uv_udp_set_multicast_ttl(raw(), ttl);
  }
  int set_multicast_interface(const char* interface_addr) {
    return uv_udp_set_multicast_interface(raw(), interface_addr);
  }
  int set_broadcast(int on) { return uv_udp_set_broadcast(raw(), on); }
  int set_ttl(int ttl) { return uv_udp_set_ttl(raw(), ttl); }
  int try_send(
      const uv_buf_t bufs[], unsigned int nbufs, const struct sockaddr* addr) {
    return uv_udp_try_send(raw(), bufs, nbufs, addr);
  }
  int recv_stop() { return uv_udp_recv_stop(raw()); }
  size_t get_send_queue_size() const {
    return uv_udp_get_send_queue_size(raw());
  }

  template <class F>
  int send(udp_send_req* req, const uv_buf_t bufs[], unsigned int nbufs,
      const struct sockaddr* addr, F cb) {
    return req->send(raw(), bufs, nbufs, addr, std::move(cb));
  }

  template <class F>
  int recv_start(uv_alloc_cb alloc_cb, F recv_cb) {
    this->make_callback(std::move(recv_cb));
    return uv_udp_recv_start(raw(), alloc_cb,
        [](uv_udp_t* h, ssize_t nread, const uv_buf_t* buf,
            const struct sockaddr* addr, unsigned flags) {
          auto self = cast_from_uv<udp*>(h);
          self->invoke_callback<F>(nread, buf, addr, flags);
        });
  }
};

struct tty : stream<tty, uv_tty_t> {
  int init(uv_loop_t* loop, uv_file fd, int readable) {
    return uv_tty_init(loop, raw(), fd, readable);
  }
  int set_mode(uv_tty_mode_t mode) { return uv_tty_set_mode(raw(), mode); }
  static int reset_mode() { return uv_tty_reset_mode(); }
  int get_winsize(int* width, int* height) {
    return uv_tty_get_winsize(raw(), width, height);
  }
};

struct pipe : stream<pipe, uv_pipe_t> {
  int init(uv_loop_t* loop, int ipc) { return uv_pipe_init(loop, raw(), ipc); }
  int open(uv_file file) { return uv_pipe_open(raw(), file); }
  int bind(const char* name) { return uv_pipe_bind(raw(), name); }
  int getsockname(char* buffer, size_t* size) const {
    return uv_pipe_getsockname(raw(), buffer, size);
  }
  int getpeername(char* buffer, size_t* size) const {
    return uv_pipe_getpeername(raw(), buffer, size);
  }
  void pending_instances(int count) { uv_pipe_pending_instances(raw(), count); }
  int pending_count() { return uv_pipe_pending_count(raw()); }
  uv_handle_type pending_type() { return uv_pipe_pending_type(raw()); }
  int chmod(int flags) { return uv_pipe_chmod(raw(), flags); }

  template <class F>
  void connect(uw::connect_req* req, const char* name, F cb) {
    return req->connect(raw(), name, std::move(cb));
  }
};

struct poll : handle<poll, uv_poll_t> {
  int init(uv_loop_t* loop, int fd) { return uv_poll_init(loop, raw(), fd); }
  int init_socket(uv_loop_t* loop, uv_os_sock_t socket) {
    return uv_poll_init_socket(loop, raw(), socket);
  }
  int stop() { return uv_poll_stop(raw()); }

  template <class F>
  int start(int events, F cb) {
    this->make_callback(std::move(cb));
    return uv_poll_start(
        raw(), events, [](uv_poll_t* h, int status, int events) {
          auto self = cast_from_uv<poll*>(h);
          self->invoke_callback<F>(status, events);
        });
  }
};

struct prepare : handle<prepare, uv_prepare_t> {
  int init(uv_loop_t* loop) { return uv_prepare_init(loop, raw()); }
  int stop() { return uv_prepare_stop(raw()); }

  template <class F>
  int start(F cb) {
    this->make_callback(std::move(cb));
    return uv_prepare_start(raw(), [](uv_prepare_t* h) {
      auto self = cast_from_uv<prepare*>(h);
      self->invoke_callback<F>();
    });
  }
};

struct check : handle<check, uv_check_t> {
  int init(uv_loop_t* loop) { return uv_check_init(loop, raw()); }
  int stop() { return uv_check_stop(raw()); }

  template <class F>
  int start(F cb) {
    this->make_callback(std::move(cb));
    return uv_check_start(raw(), [](uv_check_t* h) {
      auto self = cast_from_uv<check*>(h);
      self->invoke_callback<F>();
    });
  }
};

struct idle : handle<idle, uv_idle_t> {
  int init(uv_loop_t* loop) { return uv_idle_init(loop, raw()); }
  int stop() { return uv_idle_stop(raw()); }

  template <class F>
  int start(F cb) {
    this->make_callback(std::move(cb));
    return uv_idle_start(raw(), [](uv_idle_t* h) {
      auto self = cast_from_uv<idle*>(h);
      self->invoke_callback<F>();
    });
  }
};

struct async : handle<async, uv_async_t> {
  int send() { return uv_async_send(raw()); }

  template <class F>
  int init(uv_loop_t* loop, F cb) {
    this->make_callback(std::move(cb));
    return uv_async_init(loop, raw(), [](uv_async_t* h) {
      auto self = cast_from_uv<async*>(h);
      self->invoke_callback<F>();
    });
  }
};

struct timer : handle<timer, uv_timer_t> {
  int init(uv_loop_t* loop) { return uv_timer_init(loop, raw()); }
  int stop() { return uv_timer_stop(raw()); }
  int again() { return uv_timer_again(raw()); }
  void set_repeat(uint64_t repeat) { uv_timer_set_repeat(raw(), repeat); }
  uint64_t get_repeat() { return uv_timer_get_repeat(raw()); }

  template <class F>
  int start(uint64_t timeout, uint64_t repeat, F cb) {
    this->make_callback(std::move(cb));
    return uv_timer_start(raw(),
        [](uv_timer_t* h) {
          auto self = cast_from_uv<timer*>(h);
          self->invoke_callback<F>();
        },
        timeout, repeat);
  }
};

namespace detail {
struct addrinfo_deleter {
  constexpr addrinfo_deleter() noexcept = default;
  void operator()(struct addrinfo* ai) const { uv_freeaddrinfo(ai); }
};
} // namespace detail
using addrinfo_ptr = std::unique_ptr<struct addrinfo, detail::addrinfo_deleter>;

struct getaddrinfo_req : req<getaddrinfo_req, uv_getaddrinfo_t> {
  int getaddrinfo(uv_loop_t* loop, const char* node, const char* service,
      const struct addrinfo* hints, addrinfo_ptr& res) {
    auto r = uv_getaddrinfo(loop, raw(), nullptr, node, service, hints);
    res.reset(raw()->addrinfo);
    return r;
  }
  template <class F>
  int getaddrinfo(uv_loop_t* loop, const char* node, const char* service,
      const struct addrinfo* hints, F cb) {
    this->make_callback(std::move(cb));
    return uv_getaddrinfo(loop, raw(),
        [](uv_getaddrinfo_t* h, int status, struct addrinfo* res) {
          auto self = cast_from_uv<getaddrinfo_req*>(h);
          self->invoke_callback<F>(status, addrinfo_ptr(res));
        },
        node, service, hints);
  }
};

struct getnameinfo_req : req<getnameinfo_req, uv_getnameinfo_t> {
  int getnameinfo(uv_loop_t* loop, const struct sockaddr* addr, int flags) {
    return uv_getnameinfo(loop, raw(), nullptr, addr, flags);
  }
  template <class F>
  int getnameinfo(
      uv_loop_t* loop, const struct sockaddr* addr, int flags, F cb) {
    this->make_callback(std::move(cb));
    return uv_getnameinfo(loop, raw(),
        [](uv_getnameinfo_t* h, int status, const char* hostname,
            const char* service) {
          auto self = cast_from_uv<getnameinfo_req*>(h);
          self->invoke_callback<F>(status, hostname, service);
        },
        addr, flags);
  }
};

struct process : handle<process, uv_process_t> {
  int init(uv_loop_t* loop, const uv_process_options_t* options) {
    return uv_spawn(loop, raw(), options);
  }
  int spawn(uv_loop_t* loop, const uv_process_options_t* options) {
    return uv_spawn(loop, raw(), options);
  }
  int kill(int signum) { return uv_process_kill(raw(), signum); }
  uv_pid_t get_pid() const { return uv_process_get_pid(raw()); }
};

struct work_req : req<work_req, uv_work_t> {
  template <class F, class F2>
  int queue_work(uv_loop_t* loop, F work_cb, F2 after_work_cb) {
    using tag2 = detail::tag<1, work_req>;
    this->make_callback(std::move(work_cb));
    this->make_callback<F2, tag2>(std::move(after_work_cb));
    return uv_queue_work(loop, raw(),
        [](uv_work_t* h) {
          auto self = cast_from_uv<work_req*>(h);
          self->invoke_callback<F>();
        },
        [](uv_work_t* h, int status) {
          auto self = cast_from_uv<work_req*>(h);
          self->invoke_callback<F2, tag2>(status);
        });
  }
};

struct fs_req : req<fs_req, uv_fs_t> {
  uv_fs_type get_fs_type() const { return uv_fs_get_type(raw()); }
  ssize_t get_result() const { return uv_fs_get_result(raw()); }
  void* get_ptr() const { return uv_fs_get_ptr(raw()); }
  const char* get_path() const { return uv_fs_get_path(raw()); }
  uv_stat_t* get_statbuf() { return uv_fs_get_statbuf(raw()); }

  void req_cleanup() { return uv_fs_req_cleanup(raw()); }
  template <class F>
  int close(uv_loop_t* loop, uv_file file, F cb) {
    using tag = detail::tag<UV_FS_CLOSE, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_close(loop, raw(), [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int open(uv_loop_t* loop, const char* path, int flags, int mode, F cb) {
    using tag = detail::tag<UV_FS_OPEN, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_open(loop, raw(), path, flags, mode, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int read(uv_loop_t* loop, uv_file file, const uv_buf_t bufs[],
      unsigned int nbufs, int64_t offset, F cb) {
    using tag = detail::tag<UV_FS_READ, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_read(loop, raw(), file, bufs, nbufs, offset, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int unlink(uv_loop_t* loop, const char* path, F cb) {
    using tag = detail::tag<UV_FS_UNLINK, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_unlink(loop, raw(), path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int write(uv_loop_t* loop, uv_file file, const uv_buf_t bufs[],
      unsigned int nbufs, int64_t offset, F cb) {
    using tag = detail::tag<UV_FS_WRITE, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_write(loop, raw(), file, bufs, nbufs, offset, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }

  template <class F>
  int copyfile(uv_loop_t* loop, const char* path, const char* new_path,
      int flags, F cb) {
    using tag = detail::tag<UV_FS_COPYFILE, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_copyfile(loop, raw(), path, new_path, flags, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int mkdir(uv_loop_t* loop, const char* path, int mode, F cb) {
    using tag = detail::tag<UV_FS_MKDIR, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_mkdir(loop, raw(), path, mode, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int mkdtemp(uv_loop_t* loop, const char* tpl, F cb) {
    using tag = detail::tag<UV_FS_MKDTEMP, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_mkdtemp(loop, raw(), tpl, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int rmdir(uv_loop_t* loop, const char* path, F cb) {
    using tag = detail::tag<UV_FS_RMDIR, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_rmdir(loop, raw(), path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int scandir(uv_loop_t* loop, const char* path, int flags, F cb) {
    using tag = detail::tag<UV_FS_SCANDIR, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_scandir(loop, raw(), path, flags, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  int scandir_next(uv_dirent_t* ent) { return uv_fs_scandir_next(raw(), ent); }
  template <class F>
  int opendir(uv_loop_t* loop, const char* path, F cb) {
    using tag = detail::tag<UV_FS_OPENDIR, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_opendir(loop, raw(), path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int readdir(uv_loop_t* loop, uv_dir_t* dir, F cb) {
    using tag = detail::tag<UV_FS_READDIR, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_readdir(loop, raw(), dir, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int closedir(uv_loop_t* loop, uv_dir_t* dir, F cb) {
    using tag = detail::tag<UV_FS_CLOSEDIR, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_closedir(loop, raw(), dir, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int stat(uv_loop_t* loop, const char* path, F cb) {
    using tag = detail::tag<UV_FS_STAT, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_stat(loop, raw(), path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int fstat(uv_loop_t* loop, uv_file file, F cb) {
    using tag = detail::tag<UV_FS_FSTAT, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_fstat(loop, raw(), file, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int rename(uv_loop_t* loop, const char* path, const char* new_path, F cb) {
    using tag = detail::tag<UV_FS_RENAME, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_rename(loop, raw(), path, new_path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int fsync(uv_loop_t* loop, uv_file file, F cb) {
    using tag = detail::tag<UV_FS_FSYNC, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_fsync(loop, raw(), file, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int fdatasync(uv_loop_t* loop, uv_file file, F cb) {
    using tag = detail::tag<UV_FS_FDATASYNC, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_fdatasync(loop, raw(), file, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int ftruncate(uv_loop_t* loop, uv_file file, int64_t offset, F cb) {
    using tag = detail::tag<UV_FS_FTRUNCATE, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_ftruncate(loop, raw(), file, offset, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int sendfile(uv_loop_t* loop, uv_file out_fd, uv_file in_fd,
      int64_t in_offset, size_t length, F cb) {
    using tag = detail::tag<UV_FS_SENDFILE, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_sendfile(
        loop, raw(), out_fd, in_fd, in_offset, length, [](uv_fs_t* h) {
          auto self = cast_from_uv<fs_req*>(h);
          self->invoke_callback<F, tag>();
        });
  }
  template <class F>
  int access(uv_loop_t* loop, const char* path, int mode, F cb) {
    using tag = detail::tag<UV_FS_ACCESS, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_access(loop, raw(), path, mode, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int chmod(uv_loop_t* loop, const char* path, int mode, F cb) {
    using tag = detail::tag<UV_FS_CHMOD, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_template(loop, raw(), path, mode, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int utime(
      uv_loop_t* loop, const char* path, double atime, double mtime, F cb) {
    using tag = detail::tag<UV_FS_UTIME, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_utime(loop, raw(), path, atime, mtime, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int futime(uv_loop_t* loop, uv_file file, double atime, double mtime, F cb) {
    using tag = detail::tag<UV_FS_FUTIME, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_futime(loop, raw(), file, atime, mtime, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int lstat(uv_loop_t* loop, const char* path, F cb) {
    using tag = detail::tag<UV_FS_LSTAT, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_lstat(loop, raw(), path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int link(uv_loop_t* loop, const char* path, const char* new_path, F cb) {
    using tag = detail::tag<UV_FS_LINK, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_link(loop, raw(), path, new_path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }

  template <class F>
  int symlink(uv_loop_t* loop, const char* path, const char* new_path,
      int flags, F cb) {
    using tag = detail::tag<UV_FS_SYMLINK, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_symlink(loop, raw(), path, new_path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int readlink(uv_loop_t* loop, const char* path, F cb) {
    using tag = detail::tag<UV_FS_READLINK, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_readlink(loop, raw(), path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int realpath(uv_loop_t* loop, const char* path, F cb) {
    using tag = detail::tag<UV_FS_REALPATH, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_realpath(loop, raw(), path, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int fchmod(uv_loop_t* loop, uv_file file, int mode, F cb) {
    using tag = detail::tag<UV_FS_FCHMOD, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_fchmod(loop, raw(), file, mode, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int chown(
      uv_loop_t* loop, const char* path, uv_uid_t uid, uv_gid_t gid, F cb) {
    using tag = detail::tag<UV_FS_CHOWN, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_chown(loop, raw(), path, uid, gid, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int fchown(uv_loop_t* loop, uv_file file, uv_uid_t uid, uv_gid_t gid, F cb) {
    using tag = detail::tag<UV_FS_FCHOWN, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_fchown(loop, raw(), file, uid, gid, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }
  template <class F>
  int lchown(
      uv_loop_t* loop, const char* path, uv_uid_t uid, uv_gid_t gid, F cb) {
    using tag = detail::tag<UV_FS_LCHOWN, fs_req>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_fs_lchown(loop, raw(), path, uid, gid, [](uv_fs_t* h) {
      auto self = cast_from_uv<fs_req*>(h);
      self->invoke_callback<F, tag>();
    });
  }

  int close(uv_file file) { return uv_fs_close(nullptr, raw(), file, nullptr); }
  int open(const char* path, int flags, int mode) {
    return uv_fs_open(nullptr, raw(), path, flags, mode, nullptr);
  }
  int read(
      uv_file file, const uv_buf_t bufs[], unsigned int nbufs, int64_t offset) {
    return uv_fs_read(nullptr, raw(), file, bufs, nbufs, offset, nullptr);
  }
  int unlink(const char* path) {
    return uv_fs_unlink(nullptr, raw(), path, nullptr);
  }
  int write(
      uv_file file, const uv_buf_t bufs[], unsigned int nbufs, int64_t offset) {
    return uv_fs_write(nullptr, raw(), file, bufs, nbufs, offset, nullptr);
  }
  int copyfile(const char* path, const char* new_path, int flags) {
    return uv_fs_copyfile(nullptr, raw(), path, new_path, flags, nullptr);
  }
  int mkdir(const char* path, int mode) {
    return uv_fs_mkdir(nullptr, raw(), path, mode, nullptr);
  }
  int mkdtemp(const char* tpl) {
    return uv_fs_mkdtemp(nullptr, raw(), tpl, nullptr);
  }
  int rmdir(const char* path) {
    return uv_fs_rmdir(nullptr, raw(), path, nullptr);
  }
  int scandir(const char* path, int flags) {
    return uv_fs_scandir(nullptr, raw(), path, flags, nullptr);
  }
  int opendir(const char* path) {
    return uv_fs_opendir(nullptr, raw(), path, nullptr);
  }
  int readdir(uv_dir_t* dir) {
    return uv_fs_readdir(nullptr, raw(), dir, nullptr);
  }
  int closedir(uv_dir_t* dir) {
    return uv_fs_closedir(nullptr, raw(), dir, nullptr);
  }
  int stat(const char* path) {
    return uv_fs_stat(nullptr, raw(), path, nullptr);
  }
  int fstat(uv_file file) { return uv_fs_fstat(nullptr, raw(), file, nullptr); }
  int rename(const char* path, const char* new_path) {
    return uv_fs_rename(nullptr, raw(), path, new_path, nullptr);
  }
  int fsync(uv_file file) { return uv_fs_fsync(nullptr, raw(), file, nullptr); }
  int fdatasync(uv_file file) {
    return uv_fs_fdatasync(nullptr, raw(), file, nullptr);
  }
  int ftruncate(uv_file file, int64_t offset) {
    return uv_fs_ftruncate(nullptr, raw(), file, offset, nullptr);
  }
  int sendfile(
      uv_file out_fd, uv_file in_fd, int64_t in_offset, size_t length) {
    return uv_fs_sendfile(
        nullptr, raw(), out_fd, in_fd, in_offset, length, nullptr);
  }
  int access(const char* path, int mode) {
    return uv_fs_access(nullptr, raw(), path, mode, nullptr);
  }
  int chmod(const char* path, int mode) {
    return uv_fs_chmod(nullptr, raw(), path, mode, nullptr);
  }
  int utime(const char* path, double atime, double mtime) {
    return uv_fs_utime(nullptr, raw(), path, atime, mtime, nullptr);
  }
  int futime(uv_file file, double atime, double mtime) {
    return uv_fs_futime(nullptr, raw(), file, atime, mtime, nullptr);
  }
  int lstat(const char* path) {
    return uv_fs_lstat(nullptr, raw(), path, nullptr);
  }
  int link(const char* path, const char* new_path) {
    return uv_fs_link(nullptr, raw(), path, new_path, nullptr);
  }
  int symlink(const char* path, const char* new_path, int flags) {
    return uv_fs_symlink(nullptr, raw(), path, new_path, flags, nullptr);
  }
  int readlink(const char* path) {
    return uv_fs_readlink(nullptr, raw(), path, nullptr);
  }
  int realpath(const char* path) {
    return uv_fs_realpath(nullptr, raw(), path, nullptr);
  }
  int fchmod(uv_file file, int mode) {
    return uv_fs_fchmod(nullptr, raw(), file, mode, nullptr);
  }
  int chown(const char* path, uv_uid_t uid, uv_gid_t gid) {
    return uv_fs_chown(nullptr, raw(), path, uid, gid, nullptr);
  }
  int fchown(uv_file file, uv_uid_t uid, uv_gid_t gid) {
    return uv_fs_fchown(nullptr, raw(), file, uid, gid, nullptr);
  }
  int lchown(const char* path, uv_uid_t uid, uv_gid_t gid) {
    return uv_fs_lchown(nullptr, raw(), path, uid, gid, nullptr);
  }
};

struct fs_poll : handle<fs_poll, uv_fs_poll_t> {
  int init(uv_loop_t* loop) { return uv_fs_poll_init(loop, raw()); }
  int stop() { return uv_fs_poll_stop(raw()); }
  int getpath(char* buffer, size_t* size) {
    return uv_fs_poll_getpath(raw(), buffer, size);
  }

  template <class F>
  int start(const char* path, unsigned int interval, F cb) {
    this->make_callback(std::move(cb));
    return uv_fs_poll_start(raw(),
        [](uv_fs_poll_t* h, int status, const uv_stat_t* prev,
            const uv_stat_t* curr) {
          auto self = cast_from_uv<fs_poll*>(h);
          self->invoke_callback<F>(status, prev, curr);
        },
        path, interval);
  }
};

struct fs_event : handle<fs_event, uv_fs_event_t> {
  int init(uv_loop_t* loop) { return uv_fs_event_init(loop, raw()); }
  int stop() { return uv_fs_event_stop(raw()); }
  int getpath(char* buffer, size_t* size) {
    return uv_fs_event_getpath(raw(), buffer, size);
  }

  template <class F>
  int start(const char* path, unsigned int flags, F cb) {
    this->make_callback(std::move(cb));
    return uv_fs_event_start(raw(),
        [](uv_fs_event_t* h, int status, const uv_stat_t* prev,
            const uv_stat_t* curr) {
          auto self = cast_from_uv<fs_event*>(h);
          self->invoke_callback<F>(status, prev, curr);
        },
        path, flags);
  }
};

struct signal : handle<signal, uv_signal_t> {
  int init(uv_loop_t* loop) { return uv_signal_init(loop, raw()); }
  int stop() { return uv_signal_stop(raw()); }

  template <class F>
  int start(int signum, F cb) {
    this->make_callback(std::move(cb));
    return uv_signal_start(raw(),
        [](uv_signal_t* h, int signum) {
          auto self = cast_from_uv<signal*>(h);
          self->invoke_callback<F>(signum);
        },
        signum);
  }

  template <class F>
  int start_oneshot(int signum, F cb) {
    using tag = detail::tag<1, signal>;
    this->make_callback<F, tag>(std::move(cb));
    return uv_signal_start_oneshot(raw(),
        [](uv_signal_t* h, int signum) {
          auto self = cast_from_uv<signal*>(h);
          self->invoke_callback<F, tag, detail::reset_if<true>>(signum);
        },
        signum);
  }
};

} // namespace uw

#endif // UW_UW_HPP
