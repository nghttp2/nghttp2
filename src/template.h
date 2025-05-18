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
#include <algorithm>
#include <ostream>
#include <utility>
#include <span>
#include <string_view>

namespace nghttp2 {

template <typename T, size_t N> constexpr size_t array_size(T (&)[N]) {
  return N;
}

template <typename T, size_t N> constexpr size_t str_size(T (&)[N]) {
  return N - 1;
}

// inspired by <http://blog.korfuri.fr/post/go-defer-in-cpp/>, but our
// template can take functions returning other than void.
template <typename F, typename... T> struct Defer {
  Defer(F &&f, T &&...t)
    : f(std::bind(std::forward<F>(f), std::forward<T>(t)...)) {}
  Defer(Defer &&o) noexcept : f(std::move(o.f)) {}
  ~Defer() { f(); }

  using ResultType = std::invoke_result_t<F, T...>;
  std::function<ResultType()> f;
};

template <typename F, typename... T> Defer<F, T...> defer(F &&f, T &&...t) {
  return Defer<F, T...>(std::forward<F>(f), std::forward<T>(t)...);
}

template <typename T, typename F> bool test_flags(T t, F flags) {
  return (t & flags) == flags;
}

// doubly linked list of element T*.  T must have field T *dlprev and
// T *dlnext, which point to previous element and next element in the
// list respectively.
template <typename T> struct DList {
  DList() : head(nullptr), tail(nullptr), len(0) {}

  DList(const DList &) = delete;
  DList &operator=(const DList &) = delete;

  DList(DList &&other) noexcept
    : head{std::exchange(other.head, nullptr)},
      tail{std::exchange(other.tail, nullptr)},
      len{std::exchange(other.len, 0)} {}

  DList &operator=(DList &&other) noexcept {
    if (this == &other) {
      return *this;
    }
    head = std::exchange(other.head, nullptr);
    tail = std::exchange(other.tail, nullptr);
    len = std::exchange(other.len, 0);

    return *this;
  }

  void append(T *t) {
    ++len;
    if (tail) {
      tail->dlnext = t;
      t->dlprev = tail;
      tail = t;
      return;
    }
    head = tail = t;
  }

  void remove(T *t) {
    --len;
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

  size_t size() const { return len; }

  T *head, *tail;
  size_t len;
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

// hours
constexpr double operator"" _h(unsigned long long h) { return h * 60 * 60; }

// minutes
constexpr double operator"" _min(unsigned long long min) { return min * 60; }

// seconds
constexpr double operator"" _s(unsigned long long s) { return s; }

// milliseconds
constexpr double operator"" _ms(unsigned long long ms) { return ms / 1000.; }

// ImmutableString represents string that is immutable unlike
// std::string.  It has c_str() and size() functions to mimic
// std::string.  It manages buffer by itself.  Just like std::string,
// c_str() returns NULL-terminated string, but NULL character may
// appear before the final terminal NULL.
class ImmutableString {
public:
  using traits_type = std::char_traits<char>;
  using value_type = traits_type::char_type;
  using allocator_type = std::allocator<char>;
  using size_type = std::allocator_traits<allocator_type>::size_type;
  using difference_type =
    std::allocator_traits<allocator_type>::difference_type;
  using const_reference = const value_type &;
  using const_pointer = const value_type *;
  using const_iterator = const_pointer;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  constexpr ImmutableString() noexcept : len(0), base("") {}

  constexpr ImmutableString(const char *s, size_t slen)
    : len(slen), base(copystr(s, s + len)) {}

  constexpr explicit ImmutableString(const char *s)
    : len(traits_type::length(s)), base(copystr(s, s + len)) {}

  ImmutableString(std::nullptr_t) = delete;

  template <std::ranges::input_range R>
  requires(std::is_same_v<std::ranges::range_value_t<R>, value_type> &&
           !std::is_same_v<std::remove_cvref_t<R>, ImmutableString> &&
           !std::is_array_v<std::remove_cvref_t<R>>)
  constexpr explicit ImmutableString(R &&r)
    : len(std::ranges::distance(r)), base(copystr(std::forward<R>(r))) {}

  template <std::input_iterator I>
  requires(std::is_same_v<std::iter_value_t<I>, value_type>)
  constexpr ImmutableString(I first, I last)
    : len(std::ranges::distance(first, last)),
      base(copystr(std::move(first), std::move(last))) {}

  constexpr ImmutableString(const ImmutableString &other)
    : len(other.len), base(copystr(other)) {}

  constexpr ImmutableString(ImmutableString &&other) noexcept
    : len{std::exchange(other.len, 0)}, base{std::exchange(other.base, "")} {}

  constexpr ~ImmutableString() {
    if (len) {
      delete[] base;
    }
  }

  constexpr ImmutableString &operator=(const ImmutableString &other) {
    if (this == &other) {
      return *this;
    }
    if (len) {
      delete[] base;
    }
    len = other.len;
    base = copystr(other);
    return *this;
  }
  constexpr ImmutableString &operator=(ImmutableString &&other) noexcept {
    if (this == &other) {
      return *this;
    }
    if (len) {
      delete[] base;
    }
    len = std::exchange(other.len, 0);
    base = std::exchange(other.base, "");
    return *this;
  }

  constexpr const_iterator begin() const noexcept { return base; }
  constexpr const_iterator cbegin() const noexcept { return base; }

  constexpr const_iterator end() const noexcept { return base + len; }
  constexpr const_iterator cend() const noexcept { return base + len; }

  constexpr const_reverse_iterator rbegin() const noexcept {
    return const_reverse_iterator{base + len};
  }
  constexpr const_reverse_iterator crbegin() const noexcept {
    return const_reverse_iterator{base + len};
  }

  constexpr const_reverse_iterator rend() const noexcept {
    return const_reverse_iterator{base};
  }
  constexpr const_reverse_iterator crend() const noexcept {
    return const_reverse_iterator{base};
  }

  constexpr const_pointer c_str() const noexcept { return base; }
  constexpr const_pointer data() const noexcept { return base; }
  constexpr size_type size() const noexcept { return len; }
  constexpr bool empty() const noexcept { return len == 0; }
  constexpr const_reference operator[](size_type pos) const noexcept {
    return *(base + pos);
  }

private:
  template <std::input_iterator I>
  constexpr const char *copystr(I first, I last) {
    auto len = std::ranges::distance(first, last);
    if (len == 0) {
      return "";
    }
    auto res = new char[len + 1];
    *std::ranges::copy(first, last, res).out = '\0';
    return res;
  }

  template <std::ranges::input_range R> constexpr const char *copystr(R &&r) {
    return copystr(std::ranges::begin(r), std::ranges::end(r));
  }

  size_type len;
  const char *base;
};

inline bool operator==(const ImmutableString &lhs, const ImmutableString &rhs) {
  return std::ranges::equal(lhs, rhs);
}

inline std::ostream &operator<<(std::ostream &o, const ImmutableString &s) {
  return o.write(s.c_str(), s.size());
}

inline std::string &operator+=(std::string &lhs, const ImmutableString &rhs) {
  lhs.append(rhs.c_str(), rhs.size());
  return lhs;
}

constexpr ImmutableString operator""_is(const char *str, size_t len) {
  return {str, len};
}

// StringRef is a reference to a string owned by something else.  So
// it behaves like simple string, but it does not own pointer.  When
// it is default constructed, it has empty string.  You can freely
// copy or move around this struct, but never free its pointer.
class StringRef {
public:
  using traits_type = std::char_traits<char>;
  using value_type = traits_type::char_type;
  using allocator_type = std::allocator<char>;
  using size_type = std::allocator_traits<allocator_type>::size_type;
  using difference_type =
    std::allocator_traits<allocator_type>::difference_type;
  using const_reference = const value_type &;
  using const_pointer = const value_type *;
  using const_iterator = const_pointer;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  constexpr StringRef() noexcept : base(""), len(0) {}

  constexpr StringRef(const StringRef &other) noexcept = default;

  StringRef(std::nullptr_t) = delete;

  constexpr StringRef(const char *s) : base(s), len(traits_type::length(s)) {}

  constexpr StringRef(const char *s, size_t n) : base(s), len(n) {}

  constexpr StringRef(const std::string &s) : base(s.data()), len(s.size()) {}

  constexpr StringRef(const ImmutableString &s)
    : base(s.data()), len(s.size()) {}

  template <typename R>
  requires(std::ranges::contiguous_range<R> && std::ranges::sized_range<R> &&
           std::ranges::borrowed_range<R> &&
           std::is_same_v<std::ranges::range_value_t<R>, value_type> &&
           !std::is_same_v<std::remove_cvref_t<R>, StringRef> &&
           !std::is_array_v<std::remove_cvref_t<R>>)
  constexpr explicit StringRef(R &&r)
    : base(std::ranges::data(r)), len(std::ranges::size(r)) {}

  template <std::contiguous_iterator I>
  requires(std::is_same_v<std::iter_value_t<I>, value_type>)
  constexpr StringRef(I first, I last)
    : base(std::to_address(first)),
      len(std::ranges::distance(std::move(first), std::move(last))) {}

  constexpr StringRef &operator=(const StringRef &other) noexcept = default;

  constexpr const_iterator begin() const noexcept { return base; }
  constexpr const_iterator cbegin() const noexcept { return base; }

  constexpr const_iterator end() const noexcept { return base + len; }
  constexpr const_iterator cend() const noexcept { return base + len; }

  constexpr const_reverse_iterator rbegin() const noexcept {
    return const_reverse_iterator{base + len};
  }
  constexpr const_reverse_iterator crbegin() const noexcept {
    return const_reverse_iterator{base + len};
  }

  constexpr const_reverse_iterator rend() const noexcept {
    return const_reverse_iterator{base};
  }
  constexpr const_reverse_iterator crend() const noexcept {
    return const_reverse_iterator{base};
  }

  constexpr const_pointer data() const noexcept { return base; }
  constexpr size_type size() const noexcept { return len; }
  [[nodiscard]] constexpr bool empty() const noexcept { return len == 0; }
  constexpr const_reference operator[](size_type pos) const {
    return *(base + pos);
  }

  constexpr operator std::string_view() const noexcept { return {base, len}; }

  static constexpr size_type npos = size_type(-1);

  constexpr StringRef substr(size_type pos = 0, size_type count = npos) const {
    return {base + pos, std::min(count, len - pos)};
  }

private:
  const_pointer base;
  size_type len;
};

inline constexpr bool operator==(const StringRef &lhs,
                                 const StringRef &rhs) noexcept {
  return std::ranges::equal(lhs, rhs);
}

#if !defined(__APPLE__) && !defined(_LIBCPP_VERSION)
inline constexpr std::strong_ordering
operator<=>(const StringRef &lhs, const StringRef &rhs) noexcept {
  return std::lexicographical_compare_three_way(
    std::ranges::begin(lhs), std::ranges::end(lhs), std::ranges::begin(rhs),
    std::ranges::end(rhs));
}
#else  // __APPLE__ || _LIBCPP_VERSION
inline constexpr bool operator<(const StringRef &lhs,
                                const StringRef &rhs) noexcept {
  return std::ranges::lexicographical_compare(lhs, rhs);
}
#endif // __APPLE__ || _LIBCPP_VERSION

inline std::ostream &operator<<(std::ostream &o, const StringRef &s) {
  return o.write(s.data(), s.size());
}

inline std::string &operator+=(std::string &lhs, const StringRef &rhs) {
  lhs.append(rhs.data(), rhs.size());
  return lhs;
}

constexpr StringRef operator""_sr(const char *str, size_t len) noexcept {
  return {str, len};
}

template <typename T, std::size_t N>
[[nodiscard]] std::span<
  const uint8_t, N == std::dynamic_extent ? std::dynamic_extent : N * sizeof(T)>
as_uint8_span(std::span<T, N> s) noexcept {
  return std::span < const uint8_t,
         N == std::dynamic_extent
           ? std::dynamic_extent
           : N * sizeof(T) >
               {reinterpret_cast<const uint8_t *>(s.data()), s.size_bytes()};
}

template <typename T, std::size_t N>
[[nodiscard]] std::span<uint8_t, N == std::dynamic_extent ? std::dynamic_extent
                                                          : N * sizeof(T)>
as_writable_uint8_span(std::span<T, N> s) noexcept {
  return std::span < uint8_t,
         N == std::dynamic_extent
           ? std::dynamic_extent
           : N * sizeof(T) >
               {reinterpret_cast<uint8_t *>(s.data()), s.size_bytes()};
}

template <typename R>
requires(std::ranges::contiguous_range<R> && std::ranges::sized_range<R> &&
         std::ranges::borrowed_range<R> &&
         sizeof(std::ranges::range_value_t<R>) ==
           sizeof(std::string_view::value_type))
[[nodiscard]] std::string_view as_string_view(R &&r) {
  return std::string_view{
    reinterpret_cast<std::string_view::const_pointer>(std::ranges::data(r)),
    std::ranges::size(r)};
}

// Returns StringRef over a given range |r|.
template <typename R>
requires(std::ranges::contiguous_range<R> && std::ranges::sized_range<R> &&
         std::ranges::borrowed_range<R> &&
         sizeof(std::ranges::range_value_t<R>) == sizeof(StringRef::value_type))
[[nodiscard]] StringRef as_string_ref(R &&r) {
  return StringRef{
    reinterpret_cast<StringRef::const_pointer>(std::ranges::data(r)),
    std::ranges::size(r)};
}

// Returns StringRef over a given range [|first|, |last|).
template <std::contiguous_iterator I>
requires(sizeof(std::iter_value_t<I>) == sizeof(StringRef::value_type))
[[nodiscard]] StringRef as_string_ref(I first, I last) {
  return StringRef{
    reinterpret_cast<StringRef::const_pointer>(std::to_address(first)),
    static_cast<size_t>(std::ranges::distance(first, last))};
}

// Returns StringRef over a given range [|first|, |first| + |n|).
template <std::contiguous_iterator I>
requires(sizeof(std::iter_value_t<I>) == sizeof(StringRef::value_type))
[[nodiscard]] StringRef as_string_ref(I first, size_t n) {
  return StringRef{
    reinterpret_cast<StringRef::const_pointer>(std::to_address(first)), n};
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

namespace std {
template <> struct hash<nghttp2::StringRef> {
  std::hash<string_view> hasher;

  std::size_t operator()(const nghttp2::StringRef &s) const noexcept {
    return hasher({s.data(), s.size()});
  }
};
} // namespace std

#endif // TEMPLATE_H
