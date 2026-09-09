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

#include "shrpx_tls.h"
#include "shrpx_log.h"
#include "util.h"
#include "template.h"
#include "ssl_compat.h"

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
  .prefix = "/tls",
  .tests = tests,
};

void test_shrpx_tls_create_lookup_tree(void) {
  auto tree = std::make_unique<tls::CertLookupTree>();

  static constexpr auto hostnames = std::to_array({
    "example.com"sv,         // 0
    "www.example.org"sv,     // 1
    "*www.example.org"sv,    // 2
    "xy*.host.domain"sv,     // 3
    "*yy.host.domain"sv,     // 4
    "nghttp2.example.net"sv, // 5
    "example.net"sv,         // 6
    "example.net"sv,         // 7, duplicate
    "*.foo.bar"sv,           // 8, oo.bar is suffix of *.foo.bar
    "oo.bar"sv               // 9
  });

  for (auto i = 0UZ; i < hostnames.size(); ++i) {
    assert_ok(tree->add_cert(hostnames[i], i));
  }

  tree->dump();

  assert_ok_eq(0, tree->lookup(hostnames[0]));
  assert_ok_eq(1, tree->lookup(hostnames[1]));
  assert_ok_eq(2, tree->lookup("2www.example.org"sv));
  assert_err(Error::ENTITY_NOT_FOUND, tree->lookup("www2.example.org"sv));
  assert_ok_eq(3, tree->lookup("xy1.host.domain"sv));
  // Does not match *yy.host.domain, because * must match at least 1
  // character.
  assert_err(Error::ENTITY_NOT_FOUND, tree->lookup("yy.host.domain"sv));
  assert_ok_eq(4, tree->lookup("xyy.host.domain"sv));
  assert_err(Error::INVALID_ARGUMENT, tree->lookup(""sv));
  assert_ok_eq(5, tree->lookup(hostnames[5]));
  assert_ok_eq(6, tree->lookup(hostnames[6]));
  static constexpr char h6[] = "pdylay.example.net";
  for (size_t i = 0; i < 7; ++i) {
    assert_err(Error::ENTITY_NOT_FOUND,
               tree->lookup(std::string_view{h6 + i, str_size(h6) - i}));
  }
  assert_ok_eq(8, tree->lookup("x.foo.bar"sv));
  assert_ok_eq(9, tree->lookup(hostnames[9]));

  static constexpr auto names = std::to_array({
    "rab"sv,  // 0
    "zab"sv,  // 1
    "zzub"sv, // 2
    "ab"sv    // 3
  });

  tree = std::make_unique<tls::CertLookupTree>();
  for (auto i = 0UZ; i < names.size(); ++i) {
    assert_ok(tree->add_cert(names[i], i));
  }
  for (auto i = 0UZ; i < names.size(); ++i) {
    assert_ok_eq(i, tree->lookup(names[i]));
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
  auto nghttp2_ssl_ctx_del =
    defer([nghttp2_ssl_ctx] { SSL_CTX_free(nghttp2_ssl_ctx); });
  auto nghttp2_tls_ctx_data = std::make_unique<tls::TLSContextData>();
  SSL_CTX_set_app_data(nghttp2_ssl_ctx, nghttp2_tls_ctx_data.get());
  rv = SSL_CTX_use_certificate_chain_file(nghttp2_ssl_ctx, nghttp2_certfile);

  assert_eq(1, rv);

  static constexpr char examples_certfile[] =
    NGHTTP2_SRC_DIR "/test.example.com.pem";
  auto examples_ssl_ctx = SSL_CTX_new(TLS_server_method());
  auto examples_ssl_ctx_del =
    defer([examples_ssl_ctx] { SSL_CTX_free(examples_ssl_ctx); });
  auto examples_tls_ctx_data = std::make_unique<tls::TLSContextData>();
  SSL_CTX_set_app_data(examples_ssl_ctx, examples_tls_ctx_data.get());
  rv = SSL_CTX_use_certificate_chain_file(examples_ssl_ctx, examples_certfile);

  assert_eq(1, rv);

  tls::CertLookupTree tree;
  std::vector<std::vector<SSL_CTX *>> indexed_ssl_ctx;

  tls::cert_lookup_tree_add_ssl_ctx(&tree, indexed_ssl_ctx, nghttp2_ssl_ctx);
  tls::cert_lookup_tree_add_ssl_ctx(&tree, indexed_ssl_ctx, examples_ssl_ctx);

  assert_err(Error::ENTITY_NOT_FOUND, tree.lookup("not-used.nghttp2.org"sv));
#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
  assert_ok_eq(0, tree.lookup("www.test.nghttp2.org"sv));
  assert_ok_eq(1, tree.lookup("w.test.nghttp2.org"sv));
  assert_ok_eq(2, tree.lookup("test.nghttp2.org"sv));
#else  // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
  assert_ok_eq(0, tree.lookup("test.nghttp2.org"sv));
  assert_ok_eq(1, tree.lookup("w.test.nghttp2.org"sv));
  assert_ok_eq(2, tree.lookup("www.test.nghttp2.org"sv));
#endif // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
  assert_ok_eq(3, tree.lookup("test.example.com"sv));
}

void test_shrpx_tls_tls_hostname_match(void) {
  assert_true(tls::tls_hostname_match("example.com", "example.com"));
  assert_true(tls::tls_hostname_match("example.com", "EXAMPLE.com"));

  // check wildcard
  assert_true(tls::tls_hostname_match("*.example.com", "www.example.com"));
  // wildcard must be the left most label and it must occupy the label
  // entirely.
  assert_false(tls::tls_hostname_match("*w.example.com", "www.example.com"));
  assert_false(tls::tls_hostname_match("www*.example.com", "www1.example.com"));
  assert_false(
    tls::tls_hostname_match("www*.example.com", "WWW12.EXAMPLE.com"));
  assert_false(
    tls::tls_hostname_match("client*.example.com", "server.example.com"));
  // at least 2 dots are required after '*'
  assert_false(tls::tls_hostname_match("*.com", "example.com"));
  assert_false(tls::tls_hostname_match("*", "example.com"));
  // Multiple '*'s disable wildcard match.
  assert_false(tls::tls_hostname_match("*.*.example.com", "www.*.example.com"));
  // '*' must be in left most label
  assert_false(
    tls::tls_hostname_match("blog.*.example.com", "blog.my.example.com"));
  // '*' must match at least one character
  assert_false(tls::tls_hostname_match("*.example.com", ".example.com"));

  assert_false(tls::tls_hostname_match("example.com", "nghttp2.org"));
  assert_false(tls::tls_hostname_match("www.example.com", "example.com"));
  assert_false(tls::tls_hostname_match("example.com", "www.example.com"));
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
#endif // defined(AI_NUMERICSERV)

  addrinfo *res = nullptr;

  auto rv = getaddrinfo(ipaddr, "443", &hints, &res);

  assert_eq(0, rv);
  assert_not_null(res);

  Address addr;
  addr.set(res->ai_addr);

  freeaddrinfo(res);

  return addr;
}

void test_shrpx_tls_verify_numeric_hostname(void) {
  {
    // Successful IPv4 address match in SAN
    static constexpr auto ipaddr = "127.0.0.1"sv;
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");
    auto addr = parse_addr(ipaddr.data());

    assert_ok(tls::verify_numeric_hostname(cert, ipaddr, &addr));

    X509_free(cert);
  }

  {
    // Successful IPv6 address match in SAN
    static constexpr auto ipaddr = "::1"sv;
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");
    auto addr = parse_addr(ipaddr.data());

    assert_ok(tls::verify_numeric_hostname(cert, ipaddr, &addr));

    X509_free(cert);
  }

  {
    // Unsuccessful IPv4 address match in SAN
    static constexpr auto ipaddr = "192.168.0.127"sv;
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");
    auto addr = parse_addr(ipaddr.data());

    assert_err(Error::TLS_VERIFY_PEER,
               tls::verify_numeric_hostname(cert, ipaddr, &addr));

    X509_free(cert);
  }

  {
    // CommonName is not used if SAN is available
    static constexpr auto ipaddr = "192.168.0.1"sv;
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/ipaddr.crt");
    auto addr = parse_addr(ipaddr.data());

    assert_err(Error::TLS_VERIFY_PEER,
               tls::verify_numeric_hostname(cert, ipaddr, &addr));

    X509_free(cert);
  }

  {
    // Successful IPv4 address match in CommonName
    static constexpr auto ipaddr = "127.0.0.1"sv;
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/nosan_ip.crt");
    auto addr = parse_addr(ipaddr.data());

    assert_ok(tls::verify_numeric_hostname(cert, ipaddr, &addr));

    X509_free(cert);
  }
}

void test_shrpx_tls_verify_dns_hostname(void) {
  {
    // Successful exact DNS name match in SAN
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");

    assert_ok(tls::verify_dns_hostname(cert, "nghttp2.example.com"sv));

    X509_free(cert);
  }

  {
    // Successful wildcard DNS name match in SAN
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");

    assert_ok(tls::verify_dns_hostname(cert, "www.nghttp2.example.com"sv));

    X509_free(cert);
  }

  {
    // CommonName is not used if SAN is available.
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/verify_hostname.crt");

    assert_err(Error::TLS_VERIFY_PEER,
               tls::verify_dns_hostname(cert, "localhost"sv));

    X509_free(cert);
  }

  {
    // Successful DNS name match in CommonName
    auto cert = load_cert(NGHTTP2_SRC_DIR "/testdata/nosan.crt");

    assert_ok(tls::verify_dns_hostname(cert, "localhost"sv));

    X509_free(cert);
  }
}

} // namespace shrpx
