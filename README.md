**UW** is a single-header C++11 wrapper of [libuv](https://github.com/libuv/libuv).

# Usage

`uw::cast_frow_uv/uw::cast_to_uv` can be used cast uw type from/to libuv type.
And every uw type has a `raw()` method to get the native handle pointer.

## API map

libuv|uw
------------ | -------------|
|uv_HANDLE_t|HANDLE|
|uv_REQ_t|REQ_req|
|R uv_TYPE_op(uv_TYPE_t*, ...)|R TYPE::op(...)|
|R uv_TYPE_op(const uv_TYPE_t*, ...)|R TYPE::op(...) const|
|R uv_TYPE_op(...)|static R TYPE::op(...)|
|void (* uv_OP_cb)(uv_OP_t*,...)|R (* cb)(...) _or similar callable object_|
|...|...|
|uv_loop_t|loop|
|uv_loop_t* uv_default_loop(void)|static loop loop::get_default()|
|int uv_loop_init(uv_loop_t* loop)|int loop::init()|
|int uv_run(uv_loop_t*, uv_run_mode mode)|int loop::run(uv_run_mode mode = UV_RUN_DEFAULT)|
|...|...|
|uv_timer_t|timer|
|void (* uv_timer_cb)(uv_timer_t* handle)|R (* cb)() _or similar callable object_|
|int uv_timer_start(uv_timer_t* handle, uv_timer_cb cb, uint64_t timeout, uint64_t repeat)|int timer::start(uint64_t timeout, uint64_t repeat, F cb)|
|uv_connect_t|connect_req|
|void (* uv_connect_cb)(uv_connect_t* req, int status)|void (* cb)(int status) _or similar callable object_|
|int uv_tcp_connect(uv_connect_t* req, uv_tcp_t * handle, const struct sockaddr* addr, uv_connect_cb cb)|int connect_req::connect(uv_tcp_t* tcp, const struct sockaddr* addr, F cb)<br/>int tcp::connect(connect_req* req, const struct sockaddr* addr, F cb)|
|int uv_listen(uv_stream_t* stream, int backlog, uv_connection_cb cb)|int stream<...>::listen(int backlog, F cb)|
|int uv_fs_close(uv_loop_t* loop, uv_fs_t* req, uv_file file, uv_fs_cb cb)|int fs_req::close(uv_file file)<br/>int fs_req::close(uv_loop_t* loop, uv_file file, F cb)|
|...|...|


## handle example
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

## request example
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

struct callback {
  template <class F>
  explicit callback(F f)
      : ptr_(new F(std::move(f))),
        deleter_([](void* p) { delete reinterpret_cast<F*>(p); }) {}

  ~callback() {
    assert((bool)ptr_ == (bool)deleter_);
    if (ptr_) deleter_(ptr_);
  }
  /*...*/

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
  /*...*/
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
struct req : private Req, protected detail::callback_holder<Sub, true> {
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


