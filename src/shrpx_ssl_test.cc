/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#include "shrpx_ssl_test.h"

#include <CUnit/CUnit.h>

#include "shrpx_ssl.h"
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

void test_shrpx_ssl_create_lookup_tree(void) {
  auto tree = make_unique<ssl::CertLookupTree>();
  SSL_CTX *ctxs[] = {
      SSL_CTX_new(SSLv23_method()), SSL_CTX_new(SSLv23_method()),
      SSL_CTX_new(SSLv23_method()), SSL_CTX_new(SSLv23_method()),
      SSL_CTX_new(SSLv23_method()), SSL_CTX_new(SSLv23_method()),
      SSL_CTX_new(SSLv23_method()), SSL_CTX_new(SSLv23_method()),
      SSL_CTX_new(SSLv23_method()), SSL_CTX_new(SSLv23_method())};

  constexpr StringRef hostnames[] = {
      StringRef::from_lit("example.com"),
      StringRef::from_lit("www.example.org"),
      StringRef::from_lit("*www.example.org"),
      StringRef::from_lit("x*.host.domain"),
      StringRef::from_lit("*yy.host.domain"),
      StringRef::from_lit("nghttp2.sourceforge.net"),
      StringRef::from_lit("sourceforge.net"),
      StringRef::from_lit("sourceforge.net"), // duplicate
      StringRef::from_lit("*.foo.bar"),       // oo.bar is suffix of *.foo.bar
      StringRef::from_lit("oo.bar")};
  auto num = array_size(ctxs);
  for (size_t i = 0; i < num; ++i) {
    tree->add_cert(ctxs[i], hostnames[i]);
  }

  CU_ASSERT(ctxs[0] == tree->lookup(hostnames[0]));
  CU_ASSERT(ctxs[1] == tree->lookup(hostnames[1]));
  CU_ASSERT(ctxs[2] == tree->lookup(StringRef::from_lit("2www.example.org")));
  CU_ASSERT(nullptr == tree->lookup(StringRef::from_lit("www2.example.org")));
  CU_ASSERT(ctxs[3] == tree->lookup(StringRef::from_lit("x1.host.domain")));
  // Does not match *yy.host.domain, because * must match at least 1
  // character.
  CU_ASSERT(nullptr == tree->lookup(StringRef::from_lit("yy.Host.domain")));
  CU_ASSERT(ctxs[4] == tree->lookup(StringRef::from_lit("zyy.host.domain")));
  CU_ASSERT(nullptr == tree->lookup(StringRef{}));
  CU_ASSERT(ctxs[5] == tree->lookup(hostnames[5]));
  CU_ASSERT(ctxs[6] == tree->lookup(hostnames[6]));
  constexpr char h6[] = "pdylay.sourceforge.net";
  for (int i = 0; i < 7; ++i) {
    CU_ASSERT(0 == tree->lookup(StringRef{h6 + i, str_size(h6) - i}));
  }
  CU_ASSERT(ctxs[8] == tree->lookup(StringRef::from_lit("x.foo.bar")));
  CU_ASSERT(ctxs[9] == tree->lookup(hostnames[9]));

  for (size_t i = 0; i < num; ++i) {
    SSL_CTX_free(ctxs[i]);
  }

  SSL_CTX *ctxs2[] = {
      SSL_CTX_new(SSLv23_method()), SSL_CTX_new(SSLv23_method()),
      SSL_CTX_new(SSLv23_method()), SSL_CTX_new(SSLv23_method())};
  constexpr StringRef names[] = {
      StringRef::from_lit("rab"), StringRef::from_lit("zab"),
      StringRef::from_lit("zzub"), StringRef::from_lit("ab")};
  num = array_size(ctxs2);

  tree = make_unique<ssl::CertLookupTree>();
  for (size_t i = 0; i < num; ++i) {
    tree->add_cert(ctxs2[i], names[i]);
  }
  for (size_t i = 0; i < num; ++i) {
    CU_ASSERT(ctxs2[i] == tree->lookup(names[i]));
  }

  for (size_t i = 0; i < num; ++i) {
    SSL_CTX_free(ctxs2[i]);
  }
}

void test_shrpx_ssl_cert_lookup_tree_add_cert_from_file(void) {
  int rv;
  ssl::CertLookupTree tree;
  auto ssl_ctx = SSL_CTX_new(SSLv23_method());
  const char certfile[] = NGHTTP2_TESTS_DIR "/testdata/cacert.pem";
  rv = ssl::cert_lookup_tree_add_cert_from_file(&tree, ssl_ctx, certfile);
  CU_ASSERT(0 == rv);
  CU_ASSERT(ssl_ctx == tree.lookup(StringRef::from_lit("localhost")));

  SSL_CTX_free(ssl_ctx);
}

template <size_t N, size_t M>
bool tls_hostname_match_wrapper(const char(&pattern)[N],
                                const char(&hostname)[M]) {
  return ssl::tls_hostname_match(StringRef{pattern, N}, StringRef{hostname, M});
}

void test_shrpx_ssl_tls_hostname_match(void) {
  CU_ASSERT(tls_hostname_match_wrapper("example.com", "example.com"));
  CU_ASSERT(tls_hostname_match_wrapper("example.com", "EXAMPLE.com"));

  // check wildcard
  CU_ASSERT(tls_hostname_match_wrapper("*.example.com", "www.example.com"));
  CU_ASSERT(tls_hostname_match_wrapper("*w.example.com", "www.example.com"));
  CU_ASSERT(tls_hostname_match_wrapper("www*.example.com", "www1.example.com"));
  CU_ASSERT(
      tls_hostname_match_wrapper("www*.example.com", "WWW12.EXAMPLE.com"));
  // at least 2 dots are required after '*'
  CU_ASSERT(!tls_hostname_match_wrapper("*.com", "example.com"));
  CU_ASSERT(!tls_hostname_match_wrapper("*", "example.com"));
  // '*' must be in left most label
  CU_ASSERT(
      !tls_hostname_match_wrapper("blog.*.example.com", "blog.my.example.com"));
  // prefix is wrong
  CU_ASSERT(
      !tls_hostname_match_wrapper("client*.example.com", "server.example.com"));
  // '*' must match at least one character
  CU_ASSERT(!tls_hostname_match_wrapper("www*.example.com", "www.example.com"));

  CU_ASSERT(!tls_hostname_match_wrapper("example.com", "nghttp2.org"));
  CU_ASSERT(!tls_hostname_match_wrapper("www.example.com", "example.com"));
  CU_ASSERT(!tls_hostname_match_wrapper("example.com", "www.example.com"));
}

} // namespace shrpx
