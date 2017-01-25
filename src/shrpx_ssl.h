/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
#ifndef SHRPX_SSL_H
#define SHRPX_SSL_H

#include "shrpx.h"

#include <vector>
#include <mutex>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <ev.h>

#ifdef HAVE_NEVERBLEED
#include <neverbleed.h>
#endif // HAVE_NEVERBLEED

#include "network.h"
#include "shrpx_router.h"

namespace shrpx {

class ClientHandler;
class Worker;
class DownstreamConnectionPool;
struct DownstreamAddr;
struct UpstreamAddr;

namespace ssl {

struct TLSSessionCache {
  // ASN1 representation of SSL_SESSION object.  See
  // i2d_SSL_SESSION(3SSL).
  std::vector<uint8_t> session_data;
  // The last time stamp when this cache entry is created or updated.
  ev_tstamp last_updated;
};

// This struct stores the additional information per SSL_CTX.  This is
// attached to SSL_CTX using SSL_CTX_set_app_data().
struct TLSContextData {
  // SCT data formatted so that this can be directly sent as
  // extension_data of signed_certificate_timestamp.
  std::vector<uint8_t> sct_data;
#ifndef HAVE_ATOMIC_STD_SHARED_PTR
  // Protects ocsp_data;
  std::mutex mu;
#endif // !HAVE_ATOMIC_STD_SHARED_PTR
  // OCSP response
  std::shared_ptr<std::vector<uint8_t>> ocsp_data;

  // Path to certificate file
  const char *cert_file;
};

// Create server side SSL_CTX
SSL_CTX *create_ssl_context(const char *private_key_file, const char *cert_file,
                            const std::vector<uint8_t> &sct_data

#ifdef HAVE_NEVERBLEED
                            ,
                            neverbleed_t *nb
#endif // HAVE_NEVERBLEED
                            );

// Create client side SSL_CTX.  This does not configure ALPN settings.
// |next_proto_select_cb| is for NPN.
SSL_CTX *create_ssl_client_context(
#ifdef HAVE_NEVERBLEED
    neverbleed_t *nb,
#endif // HAVE_NEVERBLEED
    const StringRef &cacert, const StringRef &cert_file,
    const StringRef &private_key_file,
    int (*next_proto_select_cb)(SSL *s, unsigned char **out,
                                unsigned char *outlen, const unsigned char *in,
                                unsigned int inlen, void *arg));

ClientHandler *accept_connection(Worker *worker, int fd, sockaddr *addr,
                                 int addrlen, const UpstreamAddr *faddr);

// Check peer's certificate against given |address| and |host|.
int check_cert(SSL *ssl, const Address *addr, const StringRef &host);
// Check peer's certificate against given host name described in
// |addr| and numeric address in |raddr|.  Note that |raddr| might not
// point to &addr->addr.
int check_cert(SSL *ssl, const DownstreamAddr *addr, const Address *raddr);

struct WildcardRevPrefix {
  WildcardRevPrefix(const StringRef &prefix, size_t idx)
      : prefix(std::begin(prefix), std::end(prefix)), idx(idx) {}

  // "Prefix" of wildcard pattern.  It is reversed from original form.
  // For example, if the original wildcard is "test*.nghttp2.org",
  // prefix would be "tset".
  ImmutableString prefix;
  // The index of SSL_CTX.  See ConnectionHandler::get_ssl_ctx().
  size_t idx;
};

struct WildcardPattern {
  // Wildcard host sharing only suffix is probably rare, so we just do
  // linear search.
  std::vector<WildcardRevPrefix> rev_prefix;
};

class CertLookupTree {
public:
  CertLookupTree();

  // Adds hostname pattern |hostname| to the lookup tree, associating
  // value |index|.  When the queried host matches this pattern,
  // |index| is returned.  We support wildcard pattern.  The left most
  // '*' is considered as wildcard character, and it must match at
  // least one character.  If the same pattern has been already added,
  // this function is noop.
  //
  // The caller should lower-case |hostname| since this function does
  // do that, and lookup function performs case-sensitive match.
  //
  // TODO Treat wildcard pattern described as RFC 6125.
  void add_cert(const StringRef &hostname, size_t index);

  // Looks up index using the given |hostname|.  The exact match takes
  // precedence over wildcard match.  For wildcard match, longest
  // match (sum of matched suffix and prefix length in bytes) is
  // preferred, breaking a tie with longer suffix.
  //
  // The caller should lower-case |hostname| since this function
  // performs case-sensitive match.
  ssize_t lookup(const StringRef &hostname);

  // Dumps the contents of this lookup tree to stderr.
  void dump() const;

private:
  // Exact match
  Router router_;
  // Wildcard reversed suffix match.  The returned index is into
  // wildcard_patterns_.
  Router rev_wildcard_router_;
  // Stores wildcard suffix patterns.
  std::vector<WildcardPattern> wildcard_patterns_;
};

// Adds hostnames in |cert| to lookup tree |lt|.  The subjectAltNames
// and commonName are considered as eligible hostname.  If there is at
// least one dNSName in subjectAltNames, commonName is not considered.
// This function returns 0 if it succeeds, or -1.
int cert_lookup_tree_add_cert_from_x509(CertLookupTree *lt, size_t idx,
                                        X509 *cert);

// Returns true if |proto| is included in the
// protocol list |protos|.
bool in_proto_list(const std::vector<StringRef> &protos,
                   const StringRef &proto);

// Returns true if security requirement for HTTP/2 is fulfilled.
bool check_http2_requirement(SSL *ssl);

// Returns SSL/TLS option mask to disable SSL/TLS protocol version not
// included in |tls_proto_list|.  The returned mask can be directly
// passed to SSL_CTX_set_options().
long int create_tls_proto_mask(const std::vector<StringRef> &tls_proto_list);

int set_alpn_prefs(std::vector<unsigned char> &out,
                   const std::vector<StringRef> &protos);

// Setups server side SSL_CTX.  This function inspects get_config()
// and if upstream_no_tls is true, returns nullptr.  Otherwise
// construct default SSL_CTX.  If subcerts are available
// (get_config()->subcerts), caller should provide CertLookupTree
// object as |cert_tree| parameter, otherwise SNI does not work.  All
// the created SSL_CTX is stored into |all_ssl_ctx|.
SSL_CTX *setup_server_ssl_context(std::vector<SSL_CTX *> &all_ssl_ctx,
                                  CertLookupTree *cert_tree
#ifdef HAVE_NEVERBLEED
                                  ,
                                  neverbleed_t *nb
#endif // HAVE_NEVERBLEED
                                  );

// Setups client side SSL_CTX.
SSL_CTX *setup_downstream_client_ssl_context(
#ifdef HAVE_NEVERBLEED
    neverbleed_t *nb
#endif // HAVE_NEVERBLEED
    );

// Sets ALPN settings in |SSL| suitable for HTTP/2 use.
void setup_downstream_http2_alpn(SSL *ssl);
// Sets ALPN settings in |SSL| suitable for HTTP/1.1 use.
void setup_downstream_http1_alpn(SSL *ssl);

// Creates CertLookupTree.  If frontend is configured not to use TLS,
// this function returns nullptr.
std::unique_ptr<CertLookupTree> create_cert_lookup_tree();

SSL *create_ssl(SSL_CTX *ssl_ctx);

// Returns true if SSL/TLS is enabled on upstream
bool upstream_tls_enabled();

// Performs TLS hostname match.  |pattern| can contain wildcard
// character '*', which matches prefix of target hostname.  There are
// several restrictions to make wildcard work.  The matching algorithm
// is based on RFC 6125.
bool tls_hostname_match(const StringRef &pattern, const StringRef &hostname);

// Caches |session| which is associated to remote address |addr|.
// |session| is serialized into ASN1 representation, and stored.  |t|
// is used as a time stamp.  Depending on the existing cache's time
// stamp, |session| might not be cached.
void try_cache_tls_session(TLSSessionCache &cache, const Address &addr,
                           SSL_SESSION *session, ev_tstamp t);

// Returns cached session associated |addr|.  If no cache entry is
// found associated to |addr|, nullptr will be returned.
SSL_SESSION *reuse_tls_session(const TLSSessionCache &addr);

// Loads certificate form file |filename|.  The caller should delete
// the returned object using X509_free().
X509 *load_certificate(const char *filename);

} // namespace ssl

} // namespace shrpx

#endif // SHRPX_SSL_H
