/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2016 Tatsuhiro Tsujikawa
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
#include "cache_digest.h"

#include <cassert>
#include <array>
#include <limits>

#include <openssl/evp.h>

namespace nghttp2 {

namespace {
int compute_hash_values(std::vector<uint64_t> &hash_values,
                        const std::vector<std::string> &uris, uint32_t nbits) {
  int rv;

  if (nbits > 62) {
    return -1;
  }

  uint64_t mask = (static_cast<uint64_t>(1) << nbits) - 1;

  auto ctx = EVP_MD_CTX_create();

  hash_values.resize(uris.size());

  std::array<uint8_t, 32> md;

  auto p = std::begin(hash_values);
  for (auto &u : uris) {
    rv = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    if (rv != 1) {
      return -1;
    }

    rv = EVP_DigestUpdate(ctx, u.c_str(), u.size());
    if (rv != 1) {
      return -1;
    }

    unsigned int len = md.size();

    rv = EVP_DigestFinal_ex(ctx, md.data(), &len);
    if (rv != 1) {
      return -1;
    }

    assert(len == 32);

    uint64_t v;

    v = (static_cast<uint64_t>(md[24]) << 56) +
        (static_cast<uint64_t>(md[25]) << 48) +
        (static_cast<uint64_t>(md[26]) << 40) +
        (static_cast<uint64_t>(md[27]) << 32) +
        (static_cast<uint64_t>(md[28]) << 24) + (md[29] << 16) + (md[30] << 8) +
        md[31];
    v &= mask;

    *p++ = v;
  }

  EVP_MD_CTX_destroy(ctx);

  return 0;
}
} // namespace

namespace {
std::pair<uint8_t *, size_t> append_uint32(uint8_t *p, size_t b, uint32_t v,
                                           size_t nbits) {
  v &= (1 << nbits) - 1;

  if (8 > b + nbits) {
    *p |= (v << (8 - b - nbits));
    return {p, b + nbits};
  }

  if (8 == b + nbits) {
    *p++ |= v;
    return {p, 0};
  }

  auto h = 8 - b;
  auto left = nbits - h;

  *p++ |= (v >> left);
  b = 0;

  for (; left >= 8; left -= 8) {
    *p++ = (v >> (left - 8)) & 0xff;
  }

  if (left > 0) {
    *p = (v & ((1 << left) - 1)) << (8 - left);
  }

  return {p, left};
}
} // namespace

namespace {
std::pair<uint8_t *, size_t> append_0bit(uint8_t *p, size_t b, size_t nbits) {
  if (8 > b + nbits) {
    return {p, b + nbits};
  }

  if (8 == b + nbits) {
    return {++p, 0};
  }

  nbits -= 8 - b;
  ++p;

  p += nbits / 8;

  return {p, nbits % 8};
}

std::pair<uint8_t *, size_t> append_single_1bit(uint8_t *p, size_t b) {
  if (8 > b + 1) {
    *p |= (1 << (7 - b));
    return {p, b + 1};
  }

  *p++ |= 1;

  return {p, 0};
}
} // namespace

ssize_t cache_digest_encode(uint8_t *data, size_t datalen,
                            const std::vector<std::string> &uris,
                            uint32_t logp) {
  uint32_t n = 1;
  uint32_t logn = 0;

  if (logp > 31) {
    return -1;
  }

  uint32_t p = 1;
  for (uint32_t i = 0; i < logp; ++i, p *= 2)
    ;

  for (; n < uris.size(); n *= 2, ++logn)
    ;

  if (n - uris.size() > uris.size() - n / 2) {
    n /= 2;
    --logn;
  }

  auto maxlen = 2 * n + n * logp;
  if (maxlen > datalen) {
    return -1;
  }

  std::vector<uint64_t> hash_values;

  if (compute_hash_values(hash_values, uris, logn + logp) != 0) {
    return -1;
  }

  std::sort(std::begin(hash_values), std::end(hash_values));

  auto last = data;

  size_t b = 0;

  std::fill_n(data, maxlen, 0);

  std::tie(last, b) = append_uint32(last, b, logn, 5);
  std::tie(last, b) = append_uint32(last, b, logp, 5);

  auto c = std::numeric_limits<uint64_t>::max();

  for (auto v : hash_values) {
    if (v == c) {
      continue;
    }
    auto d = v - c - 1;
    auto q = d / p;
    auto r = d % p;

    std::tie(last, b) = append_0bit(last, b, q);
    std::tie(last, b) = append_single_1bit(last, b);
    std::tie(last, b) = append_uint32(last, b, r, logp);

    c = v;
  }

  if (b != 0) {
    // we already zero-filled.
    ++last;
  }

  return last - data;
}

int cache_digest_hash(uint64_t &key, size_t nbits, const StringRef &s) {
  int rv;
  uint64_t mask = (static_cast<uint64_t>(1) << nbits) - 1;

  std::array<uint8_t, 32> md;

  auto ctx = EVP_MD_CTX_create();

  rv = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
  if (rv != 1) {
    return -1;
  }

  rv = EVP_DigestUpdate(ctx, s.c_str(), s.size());
  if (rv != 1) {
    return -1;
  }

  unsigned int len = md.size();

  rv = EVP_DigestFinal_ex(ctx, md.data(), &len);
  if (rv != 1) {
    return -1;
  }

  assert(len == 32);

  EVP_MD_CTX_destroy(ctx);

  key = (static_cast<uint64_t>(md[24]) << 56) +
        (static_cast<uint64_t>(md[25]) << 48) +
        (static_cast<uint64_t>(md[26]) << 40) +
        (static_cast<uint64_t>(md[27]) << 32) +
        (static_cast<uint64_t>(md[28]) << 24) + (md[29] << 16) + (md[30] << 8) +
        md[31];

  key &= mask;

  return 0;
}

namespace {
std::pair<const uint8_t *, size_t> read_uint32(uint32_t &res, size_t nbits,
                                               const uint8_t *p, size_t b) {
  if (b + nbits < 8) {
    res = (*p >> (8 - b - nbits)) & ((1 << nbits) - 1);
    return {p, b + nbits};
  }

  if (b + nbits == 8) {
    res = *p & ((1 << nbits) - 1);
    return {++p, 0};
  }

  res = *p & ((1 << (8 - b)) - 1);

  ++p;
  nbits -= 8 - b;

  for (; nbits >= 8; nbits -= 8) {
    res <<= 8;
    res += *p++;
  }

  if (nbits) {
    res <<= nbits;
    res += *p >> (8 - nbits);
  }

  return {p, nbits};
}
} // namespace

namespace {
size_t leading_zero(uint8_t c) {
  for (size_t i = 0; i < 8; ++i) {
    if (c & (1 << (7 - i))) {
      return i;
    }
  }

  return 8;
}
} // namespace

namespace {
std::pair<const uint8_t *, size_t>
read_until_1bit(uint32_t &res, const uint8_t *p, size_t b, const uint8_t *end) {
  uint8_t mask = (1 << (8 - b)) - 1;

  if (*p & mask) {
    res = leading_zero(*p & mask) - b;
    b += res + 1;
    if (b == 8) {
      return {++p, 0};
    }
    return {p, b};
  }

  res = 8 - b;

  ++p;

  for (; p != end; ++p, res += 8) {
    if (!*p) {
      continue;
    }

    auto nlz = leading_zero(*p);

    res += nlz;
    b = nlz + 1;

    if (b == 8) {
      return {++p, 0};
    }
    return {p, b};
  }

  return {end, 0};
}
} // namespace

int cache_digest_decode(std::vector<uint64_t> &keys, uint32_t &logn,
                        uint32_t &logp, const uint8_t *data, size_t datalen) {
  auto last = data;
  size_t b = 0;

  auto end = data + datalen;

  if ((end - data) * 8 < 10) {
    return -1;
  }

  keys.resize(0);

  logn = 0;
  logp = 0;

  std::tie(last, b) = read_uint32(logn, 5, last, b);
  std::tie(last, b) = read_uint32(logp, 5, last, b);

  uint32_t n = 1, p = 1;

  for (uint32_t i = 0; i < logn; n *= 2, ++i)
    ;

  for (uint32_t i = 0; i < logp; p *= 2, ++i)
    ;

  uint64_t c = std::numeric_limits<uint64_t>::max();

  for (;;) {
    uint32_t q, r;

    auto may_end = end - last == 1 && b > 0;
    std::tie(last, b) = read_until_1bit(q, last, b, end);

    if (last == end) {
      if (may_end) {
        return 0;
      }

      return -1;
    }

    if ((end - last) * 8 < static_cast<intptr_t>(b + logp)) {
      return -1;
    }

    std::tie(last, b) = read_uint32(r, logp, last, b);

    auto d = static_cast<uint64_t>(q) * p + r;

    c += d + 1;

    keys.push_back(c);

    if (last == end) {
      return 0;
    }
  }
}

} // namespace nghttp2
