/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2015 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef TEMPLATE_H
#define TEMPLATE_H

#include "nghttp2_config.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <array>
#include <functional>
#include <typeinfo>

namespace nghttp2 {

template <typename T, typename... U>
typename std::enable_if<!std::is_array<T>::value, std::unique_ptr<T>>::type
make_unique(U &&... u) {
  return std::unique_ptr<T>(new T(std::forward<U>(u)...));
}

template <typename T>
typename std::enable_if<std::is_array<T>::value, std::unique_ptr<T>>::type
make_unique(size_t size) {
  return std::unique_ptr<T>(new typename std::remove_extent<T>::type[size]());
}

// std::forward is constexpr since C++14
template <typename... T>
constexpr std::array<
    typename std::decay<typename std::common_type<T...>::type>::type,
    sizeof...(T)>
make_array(T &&... t) {
  return std::array<
      typename std::decay<typename std::common_type<T...>::type>::type,
      sizeof...(T)>{{std::forward<T>(t)...}};
}

template <typename T, size_t N> constexpr size_t array_size(T(&)[N]) {
  return N;
}

template <typename T, size_t N> constexpr size_t str_size(T(&)[N]) {
  return N - 1;
}

// inspired by <http://blog.korfuri.fr/post/go-defer-in-cpp/>, but our
// template can take functions returning other than void.
template <typename F, typename... T> struct Defer {
  Defer(F &&f, T &&... t)
      : f(std::bind(std::forward<F>(f), std::forward<T>(t)...)) {}
  Defer(Defer &&o) : f(std::move(o.f)) {}
  ~Defer() { f(); }

  using ResultType = typename std::result_of<typename std::decay<F>::type(
      typename std::decay<T>::type...)>::type;
  std::function<ResultType()> f;
};

template <typename F, typename... T> Defer<F, T...> defer(F &&f, T &&... t) {
  return Defer<F, T...>(std::forward<F>(f), std::forward<T>(t)...);
}

template <typename T, typename F> bool test_flags(T t, F flags) {
  return (t & flags) == flags;
}

// doubly linked list of element T*.  T must have field T *dlprev and
// T *dlnext, which point to previous element and next element in the
// list respectively.
template <typename T> struct DList {
  DList() : head(nullptr), tail(nullptr) {}

  DList(const DList &) = delete;

  DList &operator=(const DList &) = delete;

  DList(DList &&other) : head(other.head), tail(other.tail) {
    other.head = other.tail = nullptr;
  }

  DList &operator=(DList &&other) {
    if (this == &other) {
      return *this;
    }
    head = other.head;
    tail = other.tail;
    other.head = other.tail = nullptr;
    return *this;
  }

  void append(T *t) {
    if (tail) {
      tail->dlnext = t;
      t->dlprev = tail;
      tail = t;
      return;
    }
    head = tail = t;
  }

  void remove(T *t) {
    auto p = t->dlprev;
    auto n = t->dlnext;
    if (p) {
      p->dlnext = n;
    }
    if (head == t) {
      head = n;
    }
    if (n) {
      n->dlprev = p;
    }
    if (tail == t) {
      tail = p;
    }
    t->dlprev = t->dlnext = nullptr;
  }

  bool empty() const { return head == nullptr; }

  T *head, *tail;
};

template <typename T> void dlist_delete_all(DList<T> &dl) {
  for (auto e = dl.head; e;) {
    auto next = e->dlnext;
    delete e;
    e = next;
  }
}

// User-defined literals for K, M, and G (powers of 1024)

constexpr unsigned long long operator"" _k(unsigned long long k) {
  return k * 1024;
}

constexpr unsigned long long operator"" _m(unsigned long long m) {
  return m * 1024 * 1024;
}

constexpr unsigned long long operator"" _g(unsigned long long g) {
  return g * 1024 * 1024 * 1024;
}

// User-defined literals for time, converted into double in seconds

constexpr double operator"" _h(unsigned long long h) { return h * 60 * 60; }

constexpr double operator"" _min(unsigned long long min) { return min * 60; }

// Returns a copy of NULL-terminated string [first, last).
template <typename InputIt>
std::unique_ptr<char[]> strcopy(InputIt first, InputIt last) {
  auto res = make_unique<char[]>(last - first + 1);
  *std::copy(first, last, res.get()) = '\0';
  return res;
}

// Returns a copy of NULL-terminated string |val|.
inline std::unique_ptr<char[]> strcopy(const char *val) {
  return strcopy(val, val + strlen(val));
}

// Returns a copy of val.c_str().
inline std::unique_ptr<char[]> strcopy(const std::string &val) {
  return strcopy(std::begin(val), std::end(val));
}

inline std::unique_ptr<char[]> strcopy(const std::unique_ptr<char[]> &val) {
  if (!val) {
    return nullptr;
  }
  return strcopy(val.get());
}

inline int run_app(std::function<int(int, char **)> app, int argc,
                   char **argv) {
  try {
    return app(argc, argv);
  } catch (const std::bad_alloc &) {
    fputs("Out of memory\n", stderr);
  } catch (const std::exception &x) {
    fprintf(stderr, "Caught %s:\n%s\n", typeid(x).name(), x.what());
  } catch (...) {
    fputs("Unknown exception caught\n", stderr);
  }
  return EXIT_FAILURE;
}

} // namespace nghttp2

#endif // TEMPLATE_H
