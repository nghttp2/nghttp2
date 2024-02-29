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
#include "shrpx_tls_test.h"

#include "munitxx.h"

#include "shrpx_tls.h"
#include "shrpx_log.h"
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace shrpx {

namespace {
const MunitTest tests[]{
    munit_void_test(test_shrpx_tls_create_lookup_tree),
    munit_void_test(test_shrpx_tls_cert_lookup_tree_add_ssl_ctx),
    munit_void_test(test_shrpx_tls_tls_hostname_match),
    munit_void_test(test_shrpx_tls_verify_numeric_hostname),
    munit_void_test(test_shrpx_tls_verify_dns_hostname),
    munit_test_end(),
};
} // namespace

const MunitSuite tls_suite{
    "/tls", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE,
};

void test_shrpx_tls_create_lookup_tree(void) {
  auto tree = std::make_unique<tls::CertLookupTree>();

  constexpr StringRef hostnames[] = {
      StringRef::from_lit("example.com"),             // 0
      StringRef::from_lit("www.example.org"),         // 1
      StringRef::from_lit("*www.example.org"),        // 2
      StringRef::from_lit("xy*.host.domain"),         // 3
      StringRef::from_lit("*yy.host.domain"),         // 4
      StringRef::from_lit("nghttp2.sourceforge.net"), // 5
      StringRef::from_lit("sourceforge.net"),         // 6
      StringRef::from_lit("sourceforge.net"),         // 7, duplicate
      StringRef::from_lit("*.foo.bar"), // 8, oo.bar is suffix of *.foo.bar
      StringRef::from_lit("oo.bar")     // 9
  };
  auto num = array_size(hostnames);

  for (size_t idx = 0; idx < num; ++idx) {
    tree->add_cert(hostnames[idx], idx);
  }

  tree->dump();

  assert_ssize(0, ==, tree->lookup(hostnames[0]));
  assert_ssize(1, ==, tree->lookup(hostnames[1]));
  assert_ssize(2, ==, tree->lookup(StringRef::from_lit("2www.example.org")));
  assert_ssize(-1, ==, tree->lookup(StringRef::from_lit("www2.example.org")));
  assert_ssize(3, ==, tree->lookup(StringRef::from_lit("xy1.host.domain")));
  // Does not match *yy.host.domain, because * must match at least 1
  // character.
  assert_ssize(-1, ==, tree->lookup(StringRef::from_lit("yy.host.domain")));
  assert_ssize(4, ==, tree->lookup(StringRef::from_lit("xyy.host.domain")));
  assert_ssize(-1, ==, tree->lookup(StringRef{}));
  assert_ssize(5, ==, tree->lookup(hostnames[5]));
  assert_ssize(6, ==, tree->lookup(hostnames[6]));
  static constexpr char h6[] = "pdylay.sourceforge.net";
  for (int i = 0; i < 7; ++i) {
    assert_ssize(-1, ==, tree->lookup(StringRef{h6 + i, str_size(h6) - i}));
  }
  assert_ssize(8, ==, tree->lookup(StringRef::from_lit("x.foo.bar")));
  assert_ssize(9, ==, tree->lookup(hostnames[9]));

  constexpr StringRef names[] = {
      StringRef::from_lit("rab"),  // 1
      StringRef::from_lit("zab"),  // 2
      StringRef::from_lit("zzub"), // 3
      StringRef::from_lit("ab")    // 4
  };
  num = array_size(names);

  tree = std::make_unique<tls::CertLookupTree>();
  for (size_t idx = 0; idx < num; ++idx) {
    tree->add_cert(names[idx], idx);
  }
  for (size_t i = 0; i < num; ++i) {
    assert_ssize((ssize_t)i, ==, tree->lookup(names[i]));
  }
}

// We use cfssl to generate key pairs.
//
// CA self-signed key pairs generation:
//
//   $ cfssl genkey -initca ca.nghttp2.org.csr.json |
//     cfssljson -bare ca.nghttp2.org
//
// Create CSR:
//
//   $ cfssl genkey test.nghttp2.org.csr.json | cfssljson -bare test.nghttp2.org
//   $ cfssl genkey test.example.com.csr.json | cfssljson -bare test.example.com
//
// Sign CSR:
//
//   $ cfssl sign -ca ca.nghttp2.org.pem -ca-key ca.nghttp2.org-key.pem
//     -config=ca-config.json -profile=server test.nghttp2.org.csr |
//     cfssljson -bare test.nghttp2.org
//
//   $ cfssl sign -ca ca.nghttp2.org.pem -ca-key ca.nghttp2.org-key.pem
//     -config=ca-config.json -profile=server test.example.com.csr |
//     cfssljson -bare test.example.com
//
void test_shrpx_tls_cert_lookup_tree_add_ssl_ctx(void) {
  int rv;

  static constexpr char nghttp2_certfile[] =
      NGHTTP2_SRC_DIR "/test.nghttp2.org.pem";
  auto nghttp2_ssl_ctx = SSL_CTX_new(TLS_server_method());
  auto nghttp2_ssl_ctx_del = defer(SSL_CTX_free, nghttp2_ssl_ctx);
  auto nghttp2_tls_ctx_data = std::make_unique<tls::TLSContextData>();
  nghttp2_tls_ctx_data->cert_file = nghttp2_certfile;
  SSL_CTX_set_app_data(nghttp2_ssl_ctx, nghttp2_tls_ctx_data.get());
  rv = SSL_CTX_use_certificate_chain_file(nghttp2_ssl_ctx, nghttp2_certfile);

  assert_int(1, ==, rv);

  static constexpr char examples_certfile[] =
      NGHTTP2_SRC_DIR "/test.example.com.pem";
  auto examples_ssl_ctx = SSL_CTX_new(TLS_server_method());
  auto examples_ssl_ctx_del = defer(SSL_CTX_free, examples_ssl_ctx);
  auto examples_tls_ctx_data = std::make_unique<tls::TLSContextData>();
  examples_tls_ctx_data->cert_file = examples_certfile;
  SSL_CTX_set_app_data(examples_ssl_ctx, examples_tls_ctx_data.get());
  rv = SSL_CTX_use_certificate_chain_file(examples_ssl_ctx, examples_certfile);

  assert_int(1, ==, rv);

  tls::CertLookupTree tree;
  std::vector<std::vector<SSL_CTX *>> indexed_ssl_ctx;

  rv = tls::cert_lookup_tree_add_ssl_ctx(&tree, indexed_ssl_ctx,
                                         nghttp2_ssl_ctx);

  assert_int(0, ==, rv);

  rv = tls::cert_lookup_tree_add_ssl_ctx(&tree, indexed_ssl_ctx,
                                         examples_ssl_ctx);

  assert_int(0, ==, rv);

  assert_ssize(-1, ==,
               tree.lookup(StringRef::from_lit("not-used.nghttp2.org")));
  assert_ssize(0, ==, tree.lookup(StringRef::from_lit("test.nghttp2.org")));
  assert_ssize(1, ==, tree.lookup(StringRef::from_lit("w.test.nghttp2.org")));
  assert_ssize(2, ==, tree.lookup(StringRef::from_lit("www.test.nghttp2.org")));
  assert_ssize(3, ==, tree.lookup(StringRef::from_lit("test.example.com")));
}

template <size_t N, size_t M>
bool tls_hostname_match_wrapper(const char (&pattern)[N],
                                const char (&hostname)[M]) {
  return tls::tls_hostname_match(StringRef{pattern, N}, StringRef{hostname, M});
}

void test_shrpx_tls_tls_hostname_match(void) {
  assert_true(tls_hostname_match_wrapper("example.com", "example.com"));
  assert_true(tls_hostname_match_wrapper("example.com", "EXAMPLE.com"));

  // check wildcard
  assert_true(tls_hostname_match_wrapper("*.example.com", "www.example.com"));
  assert_true(tls_hostname_match_wrapper("*w.example.com", "www.example.com"));
  assert_true(
      tls_hostname_match_wrapper("www*.example.com", "www1.example.com"));
  assert_true(
      tls_hostname_match_wrapper("www*.example.com", "WWW12.EXAMPLE.com"));
  // at least 2 dots are required after '*'
  assert_false(tls_hostname_match_wrapper("*.com", "example.com"));
  assert_false(tls_hostname_match_wrapper("*", "example.com"));
  // '*' must be in left most label
  assert_false(
      tls_hostname_match_wrapper("blog.*.example.com", "blog.my.example.com"));
  // prefix is wrong
  assert_false(
      tls_hostname_match_wrapper("client*.example.com", "server.example.com"));
  // '*' must match at least one character
  assert_false(
      tls_hostname_match_wrapper("www*.example.com", "www.example.com"));

  assert_false(tls_hostname_match_wrapper("example.com", "nghttp2.org"));
  assert_false(tls_hostname_match_wrapper("www.example.com", "example.com"));
  assert_false(tls_hostname_match_wrapper("example.com", "www.example.com"));
}

static X509 *load_cert(const char *path) {
  auto f = fopen(path, "r");
  auto cert = PEM_read_X509(f, nullptr, nullptr, nullptr);

  fclose(f);

  return cert;
}

static Address parse_addr(const char *ipaddr) {
  addrinfo hints{};

  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICHOST;
#ifdef AI_NUMERICSERV
  hints.ai_flags |= AI_NUMERICSERV;
#endif

  addrinfo *res = nullptr;

  auto rv = getaddrinfo(ipaddr, "443", &hints, &res);

  assert_int(0, ==, rv);
  assert_not_null(res);

  Address addr;
  addr.len = res->ai_addrlen;
  memcpy(&addr.su, res->ai_addr, res->ai_addrlen);

  freeaddrinfo(res);

  return addr;
}

void test_shrpx_tls_verify_numeric_hostname(void) {
  {
    // Successful IPv4 address match in SAN
    static constexpr char ipaddr[] = "127.0.0.1";
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");
    auto addr = parse_addr(ipaddr);
    auto rv =
        tls::verify_numeric_hostname(cert, StringRef::from_lit(ipaddr), &addr);

    assert_int(0, ==, rv);

    X509_free(cert);
  }

  {
    // Successful IPv6 address match in SAN
    static constexpr char ipaddr[] = "::1";
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");
    auto addr = parse_addr(ipaddr);
    auto rv =
        tls::verify_numeric_hostname(cert, StringRef::from_lit(ipaddr), &addr);

    assert_int(0, ==, rv);

    X509_free(cert);
  }

  {
    // Unsuccessful IPv4 address match in SAN
    static constexpr char ipaddr[] = "192.168.0.127";
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");
    auto addr = parse_addr(ipaddr);
    auto rv =
        tls::verify_numeric_hostname(cert, StringRef::from_lit(ipaddr), &addr);

    assert_int(-1, ==, rv);

    X509_free(cert);
  }

  {
    // CommonName is not used if SAN is available
    static constexpr char ipaddr[] = "192.168.0.1";
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/ipaddr.crt");
    auto addr = parse_addr(ipaddr);
    auto rv =
        tls::verify_numeric_hostname(cert, StringRef::from_lit(ipaddr), &addr);

    assert_int(-1, ==, rv);

    X509_free(cert);
  }

  {
    // Successful IPv4 address match in CommonName
    static constexpr char ipaddr[] = "127.0.0.1";
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/nosan_ip.crt");
    auto addr = parse_addr(ipaddr);
    auto rv =
        tls::verify_numeric_hostname(cert, StringRef::from_lit(ipaddr), &addr);

    assert_int(0, ==, rv);

    X509_free(cert);
  }
}

void test_shrpx_tls_verify_dns_hostname(void) {
  {
    // Successful exact DNS name match in SAN
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");
    auto rv = tls::verify_dns_hostname(
        cert, StringRef::from_lit("nghttp2.example.com"));

    assert_int(0, ==, rv);

    X509_free(cert);
  }

  {
    // Successful wildcard DNS name match in SAN
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");
    auto rv = tls::verify_dns_hostname(
        cert, StringRef::from_lit("www.nghttp2.example.com"));

    assert_int(0, ==, rv);

    X509_free(cert);
  }

  {
    // CommonName is not used if SAN is available.
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");
    auto rv = tls::verify_dns_hostname(cert, StringRef::from_lit("localhost"));

    assert_int(-1, ==, rv);

    X509_free(cert);
  }

  {
    // Successful DNS name match in CommonName
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/nosan.crt");
    auto rv = tls::verify_dns_hostname(cert, StringRef::from_lit("localhost"));

    assert_int(0, ==, rv);

    X509_free(cert);
  }
}

} // namespace shrpx
