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
#include "cache_digest_test.h"

#include <vector>
#include <algorithm>

#include <CUnit/CUnit.h>

#include "cache_digest.h"
#include "template.h"

namespace nghttp2 {

void test_cache_digest_encode_decode(void) {
  int rv;

  auto uris = std::vector<std::string>{"https://nghttp2.org/foo",
                                       "https://nghttp2.org/bar",
                                       "https://nghttp2.org/buzz"};

  auto pbits = 31;
  std::array<uint8_t, 16_k> cdbuf;
  auto cdlen = cache_digest_encode(cdbuf.data(), cdbuf.size(), uris, pbits);

  std::vector<uint64_t> keys;
  uint32_t logn, logp;

  rv = cache_digest_decode(keys, logn, logp, cdbuf.data(), cdlen);

  CU_ASSERT(0 == rv);

  auto query_keys = std::vector<uint64_t>(uris.size());
  for (size_t i = 0; i < uris.size(); ++i) {
    auto &uri = uris[i];

    uint64_t key;

    rv = cache_digest_hash(key, logn + logp, StringRef{uri});

    CU_ASSERT(0 == rv);

    query_keys[i] = key;
  }

  CU_ASSERT(
      std::binary_search(std::begin(keys), std::end(keys), query_keys[0]));
  CU_ASSERT(
      std::binary_search(std::begin(keys), std::end(keys), query_keys[1]));
  CU_ASSERT(
      std::binary_search(std::begin(keys), std::end(keys), query_keys[2]));
}

} // namespace nghttp2
