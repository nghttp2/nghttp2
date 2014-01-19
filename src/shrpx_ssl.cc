/*
 * nghttp2 - HTTP/2.0 C Library
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
#include "shrpx_ssl.h"

#include <sys/socket.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include <vector>
#include <string>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <nghttp2/nghttp2.h>

#include "shrpx_log.h"
#include "shrpx_client_handler.h"
#include "shrpx_config.h"
#include "shrpx_accesslog.h"
#include "util.h"

using namespace nghttp2;

namespace shrpx {

namespace ssl {

namespace {
std::pair<unsigned char*, size_t> next_proto;
unsigned char proto_list[256];
} // namespace

namespace {
int next_proto_cb(SSL *s, const unsigned char **data, unsigned int *len,
                  void *arg)
{
  auto next_proto = static_cast<std::pair<unsigned char*, size_t>*>(arg);
  *data = next_proto->first;
  *len = next_proto->second;
  return SSL_TLSEXT_ERR_OK;
}
} // namespace

namespace {
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
  if(!preverify_ok) {
    int err = X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    LOG(ERROR) << "client certificate verify error:num=" << err << ":"
               << X509_verify_cert_error_string(err)
               << ":depth=" << depth;
  }
  return preverify_ok;
}
} // namespace

namespace {
size_t set_npn_prefs(unsigned char *out, char **protos, size_t len)
{
  unsigned char *ptr = out;
  size_t listlen = 0;
  for(size_t i = 0; i < len; ++i) {
    size_t plen = strlen(protos[i]);
    *ptr = plen;
    memcpy(ptr+1, protos[i], *ptr);
    ptr += *ptr+1;
    listlen += 1 + plen;
  }
  return listlen;
}
} // namespace

namespace {
int ssl_pem_passwd_cb(char *buf, int size, int rwflag, void *user_data)
{
  auto config = static_cast<Config*>(user_data);
  int len = (int)strlen(config->private_key_passwd);
  if (size < len + 1) {
    LOG(ERROR) << "ssl_pem_passwd_cb: buf is too small " << size;
    return 0;
  }
  // Copy string including last '\0'.
  memcpy(buf, config->private_key_passwd, len+1);
  return len;
}
} // namespace

namespace {
int servername_callback(SSL *ssl, int *al, void *arg)
{
  if(get_config()->cert_tree) {
    const char *hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if(hostname) {
      auto ssl_ctx = cert_lookup_tree_lookup(get_config()->cert_tree,
                                             hostname, strlen(hostname));
      if(ssl_ctx) {
        SSL_set_SSL_CTX(ssl, ssl_ctx);
      }
    }
  }
  return SSL_TLSEXT_ERR_NOACK;
}
} // namespace

namespace {
void info_callback(const SSL *ssl, int where, int ret)
{
  // To mitigate possible DOS attack using lots of renegotiations, we
  // disable renegotiation. Since OpenSSL does not provide an easy way
  // to disable it, we check that renegotiation is started in this
  // callback.
  if(where & SSL_CB_HANDSHAKE_START) {
    auto handler = static_cast<ClientHandler*>(SSL_get_app_data(ssl));
    if(handler && handler->get_tls_handshake()) {
      handler->set_tls_renegotiation(true);
      if(LOG_ENABLED(INFO)) {
        CLOG(INFO, handler) << "TLS renegotiation started";
      }
    }
  }
}
} // namespace

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
namespace {
int alpn_select_proto_cb(SSL* ssl,
                         const unsigned char **out,
                         unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
  if(nghttp2_select_next_protocol
     (const_cast<unsigned char**>(out), outlen, in, inlen) == -1) {
    return SSL_TLSEXT_ERR_NOACK;
  }
  return SSL_TLSEXT_ERR_OK;
}
} // namespace
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

namespace {
const char *names[] = { "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3" };
const size_t namelen = sizeof(names)/sizeof(names[0]);
const long int masks[] = { SSL_OP_NO_TLSv1_2, SSL_OP_NO_TLSv1_1,
                           SSL_OP_NO_TLSv1, SSL_OP_NO_SSLv3 };
long int create_tls_proto_mask(char **tls_proto_list, size_t len)
{
  long int res = 0;
  for(size_t i = 0; i < namelen; ++i) {
    size_t j;
    for(j = 0; j < len; ++j) {
      if(strcasecmp(names[i], tls_proto_list[j]) == 0) {
        break;
      }
    }
    if(j == len) {
      res |= masks[i];
    }
  }
  return res;
}
} // namespace

SSL_CTX* create_ssl_context(const char *private_key_file,
                            const char *cert_file)
{
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(SSLv23_server_method());
  if(!ssl_ctx) {
    LOG(FATAL) << ERR_error_string(ERR_get_error(), nullptr);
    DIE();
  }

  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION |
                      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                      SSL_OP_SINGLE_ECDH_USE | SSL_OP_SINGLE_DH_USE |
                      SSL_OP_NO_TICKET |
                      create_tls_proto_mask(get_config()->tls_proto_list,
                                            get_config()->tls_proto_list_len));

  const unsigned char sid_ctx[] = "shrpx";
  SSL_CTX_set_session_id_context(ssl_ctx, sid_ctx, sizeof(sid_ctx)-1);
  SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);

  const char *ciphers;
  if(get_config()->ciphers) {
    ciphers = get_config()->ciphers;
    // If ciphers are given, honor its order unconditionally
    SSL_CTX_set_options(ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
  } else {
    ciphers = "HIGH:!aNULL:!eNULL";
    if(get_config()->honor_cipher_order) {
      SSL_CTX_set_options(ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }
  }
  if(SSL_CTX_set_cipher_list(ssl_ctx, ciphers) == 0) {
    LOG(FATAL) << "SSL_CTX_set_cipher_list " << ciphers << " failed: "
               << ERR_error_string(ERR_get_error(), nullptr);
    DIE();
  }

#ifndef OPENSSL_NO_EC

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
#else // OPENSSL_VERSION_NUBMER < 0x10002000L
  // Use P-256, which is sufficiently secure at the time of this
  // writing.
  auto ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if(ecdh == nullptr) {
    LOG(FATAL) << "EC_KEY_new_by_curv_name failed: "
               << ERR_error_string(ERR_get_error(), nullptr);
    DIE();
  }
  SSL_CTX_set_tmp_ecdh(ssl_ctx, ecdh);
  EC_KEY_free(ecdh);
#endif // OPENSSL_VERSION_NUBMER < 0x10002000L

#endif /* OPENSSL_NO_EC */

  if(get_config()->dh_param_file) {
    // Read DH parameters from file
    auto bio = BIO_new_file(get_config()->dh_param_file, "r");
    if(bio == nullptr) {
      LOG(FATAL) << "BIO_new_file() failed: "
                 << ERR_error_string(ERR_get_error(), nullptr);
      DIE();
    }
    auto dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);
    if(dh == nullptr) {
      LOG(FATAL) << "PEM_read_bio_DHparams() failed: "
                 << ERR_error_string(ERR_get_error(), nullptr);
      DIE();
    }
    SSL_CTX_set_tmp_dh(ssl_ctx, dh);
    DH_free(dh);
    BIO_free(bio);
  }

  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  if (get_config()->private_key_passwd) {
    SSL_CTX_set_default_passwd_cb(ssl_ctx, ssl_pem_passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, (void *)get_config());
  }
  if(SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file,
                                 SSL_FILETYPE_PEM) != 1) {
    LOG(FATAL) << "SSL_CTX_use_PrivateKey_file failed: "
               << ERR_error_string(ERR_get_error(), nullptr);
    DIE();
  }
  if(SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
    LOG(FATAL) << "SSL_CTX_use_certificate_file failed: "
               << ERR_error_string(ERR_get_error(), nullptr);
    DIE();
  }
  if(SSL_CTX_check_private_key(ssl_ctx) != 1) {
    LOG(FATAL) << "SSL_CTX_check_private_key failed: "
               << ERR_error_string(ERR_get_error(), nullptr);
    DIE();
  }
  if(get_config()->verify_client) {
    if(get_config()->verify_client_cacert) {
      if(SSL_CTX_load_verify_locations(ssl_ctx,
                                       get_config()->verify_client_cacert,
                                       nullptr) != 1) {
        LOG(FATAL) << "Could not load trusted ca certificates from "
                   << get_config()->verify_client_cacert << ": "
                   << ERR_error_string(ERR_get_error(), nullptr);
        DIE();
      }
      // It is heard that SSL_CTX_load_verify_locations() may leave
      // error even though it returns success. See
      // http://forum.nginx.org/read.php?29,242540
      ERR_clear_error();
      auto list = SSL_load_client_CA_file(get_config()->verify_client_cacert);
      if(!list) {
        LOG(FATAL) << "Could not load ca certificates from "
                   << get_config()->verify_client_cacert << ": "
                   << ERR_error_string(ERR_get_error(), nullptr);
        DIE();
      }
      SSL_CTX_set_client_CA_list(ssl_ctx, list);
    }
    SSL_CTX_set_verify(ssl_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE |
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_callback);
  }
  SSL_CTX_set_tlsext_servername_callback(ssl_ctx, servername_callback);
  SSL_CTX_set_info_callback(ssl_ctx, info_callback);

  // NPN advertisement
  auto proto_list_len = set_npn_prefs(proto_list, get_config()->npn_list,
                                      get_config()->npn_list_len);
  next_proto.first = proto_list;
  next_proto.second = proto_list_len;
  SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, &next_proto);
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  // ALPN selection callback
  SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_proto_cb, nullptr);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L
  return ssl_ctx;
}

namespace {
int select_next_proto_cb(SSL* ssl,
                         unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
  if(nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    *out = (unsigned char*)NGHTTP2_PROTO_VERSION_ID;
    *outlen = NGHTTP2_PROTO_VERSION_ID_LEN;
  }
  return SSL_TLSEXT_ERR_OK;
}
} // namespace

SSL_CTX* create_ssl_client_context()
{
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if(!ssl_ctx) {
    LOG(FATAL) << ERR_error_string(ERR_get_error(), nullptr);
    DIE();
  }
  SSL_CTX_set_options(ssl_ctx,
                      SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION |
                      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
                      create_tls_proto_mask(get_config()->tls_proto_list,
                                            get_config()->tls_proto_list_len));

  const char *ciphers;
  if(get_config()->ciphers) {
    ciphers = get_config()->ciphers;
  } else {
    ciphers = "HIGH:!aNULL:!eNULL";
  }
  if(SSL_CTX_set_cipher_list(ssl_ctx, ciphers) == 0) {
    LOG(FATAL) << "SSL_CTX_set_cipher_list " << ciphers << " failed: "
               << ERR_error_string(ERR_get_error(), nullptr);
    DIE();
  }

  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);

  if(SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
    LOG(WARNING) << "Could not load system trusted ca certificates: "
                 << ERR_error_string(ERR_get_error(), nullptr);
  }

  if(get_config()->cacert) {
    if(SSL_CTX_load_verify_locations(ssl_ctx, get_config()->cacert, nullptr)
       != 1) {
      LOG(FATAL) << "Could not load trusted ca certificates from "
                 << get_config()->cacert << ": "
                 << ERR_error_string(ERR_get_error(), nullptr);
      DIE();
    }
  }

  if(get_config()->client_private_key_file) {
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx,
                                   get_config()->client_private_key_file,
                                   SSL_FILETYPE_PEM) != 1) {
      LOG(FATAL) << "Could not load client private key from "
                 << get_config()->client_private_key_file << ": "
                 << ERR_error_string(ERR_get_error(), nullptr);
      DIE();
    }
  }
  if(get_config()->client_cert_file) {
    if(SSL_CTX_use_certificate_chain_file(ssl_ctx,
                                          get_config()->client_cert_file)
       != 1) {
      LOG(FATAL) << "Could not load client certificate from "
                 << get_config()->client_cert_file << ": "
                 << ERR_error_string(ERR_get_error(), nullptr);
      DIE();
    }
  }
  // NPN selection callback
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, nullptr);

#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  // ALPN advertisement
  auto proto_list_len = set_npn_prefs(proto_list, get_config()->npn_list,
                                      get_config()->npn_list_len);
  next_proto.first = proto_list;
  next_proto.second = proto_list_len;
  SSL_CTX_set_alpn_protos(ssl_ctx, proto_list, proto_list[0] + 1);
#endif // OPENSSL_VERSION_NUMBER >= 0x10002000L

  return ssl_ctx;
}

ClientHandler* accept_connection(event_base *evbase, SSL_CTX *ssl_ctx,
                                 evutil_socket_t fd,
                                 sockaddr *addr, int addrlen)
{
  char host[NI_MAXHOST];
  int rv;
  rv = getnameinfo(addr, addrlen, host, sizeof(host), nullptr, 0,
                   NI_NUMERICHOST);
  if(rv == 0) {
    if(get_config()->accesslog) {
      upstream_connect(host);
    }

    int val = 1;
    rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                    reinterpret_cast<char *>(&val), sizeof(val));
    if(rv == -1) {
      LOG(WARNING) << "Setting option TCP_NODELAY failed: errno="
                   << errno;
    }
    SSL *ssl = nullptr;
    bufferevent *bev;
    if(ssl_ctx) {
      ssl = SSL_new(ssl_ctx);
      if(!ssl) {
        LOG(ERROR) << "SSL_new() failed: "
                   << ERR_error_string(ERR_get_error(), nullptr);
        return nullptr;
      }
      SSL_set_fd(ssl, fd);
      // To detect TLS renegotiation and deal with it, we have to use
      // filter-based OpenSSL bufferevent and set evbuffer callback by
      // our own.
      auto underlying_bev = bufferevent_socket_new(evbase, fd, 0);
      bev = bufferevent_openssl_filter_new(evbase, underlying_bev, ssl,
                                           BUFFEREVENT_SSL_ACCEPTING,
                                           BEV_OPT_DEFER_CALLBACKS);
    } else {
      bev = bufferevent_socket_new(evbase, fd, BEV_OPT_DEFER_CALLBACKS);
    }
    if(!bev) {
      LOG(ERROR) << "bufferevent_socket_new() failed";
      if(ssl) {
        SSL_free(ssl);
      }
      return nullptr;
    }
    return new ClientHandler(bev, fd, ssl, host);
  } else {
    LOG(ERROR) << "getnameinfo() failed: " << gai_strerror(rv);
    return nullptr;
  }
}

bool numeric_host(const char *hostname)
{
  struct addrinfo hints;
  struct addrinfo* res;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICHOST;
  if(getaddrinfo(hostname, nullptr, &hints, &res)) {
    return false;
  }
  freeaddrinfo(res);
  return true;
}

namespace {
bool tls_hostname_match(const char *pattern, const char *hostname)
{
  const char *ptWildcard = strchr(pattern, '*');
  if(ptWildcard == nullptr) {
    return util::strieq(pattern, hostname);
  }
  const char *ptLeftLabelEnd = strchr(pattern, '.');
  bool wildcardEnabled = true;
  // Do case-insensitive match. At least 2 dots are required to enable
  // wildcard match. Also wildcard must be in the left-most label.
  // Don't attempt to match a presented identifier where the wildcard
  // character is embedded within an A-label.
  if(ptLeftLabelEnd == 0 || strchr(ptLeftLabelEnd+1, '.') == 0 ||
     ptLeftLabelEnd < ptWildcard || util::istartsWith(pattern, "xn--")) {
    wildcardEnabled = false;
  }
  if(!wildcardEnabled) {
    return util::strieq(pattern, hostname);
  }
  const char *hnLeftLabelEnd = strchr(hostname, '.');
  if(hnLeftLabelEnd == 0 || !util::strieq(ptLeftLabelEnd, hnLeftLabelEnd)) {
    return false;
  }
  // Perform wildcard match. Here '*' must match at least one
  // character.
  if(hnLeftLabelEnd - hostname < ptLeftLabelEnd - pattern) {
    return false;
  }
  return util::istartsWith(hostname, hnLeftLabelEnd, pattern, ptWildcard) &&
    util::iendsWith(hostname, hnLeftLabelEnd, ptWildcard+1, ptLeftLabelEnd);
}
} // namespace

namespace {
int verify_hostname(const char *hostname,
                    const sockaddr_union *su,
                    size_t salen,
                    const std::vector<std::string>& dns_names,
                    const std::vector<std::string>& ip_addrs,
                    const std::string& common_name)
{
  if(numeric_host(hostname)) {
    if(ip_addrs.empty()) {
      return util::strieq(common_name.c_str(), hostname) ? 0 : -1;
    }
    const void *saddr;
    switch(su->storage.ss_family) {
    case AF_INET:
      saddr = &su->in.sin_addr;
      break;
    case AF_INET6:
      saddr = &su->in6.sin6_addr;
      break;
    default:
      return -1;
    }
    for(size_t i = 0; i < ip_addrs.size(); ++i) {
      if(salen == ip_addrs[i].size() &&
         memcmp(saddr, ip_addrs[i].c_str(), salen) == 0) {
        return 0;
      }
    }
  } else {
    if(dns_names.empty()) {
      return tls_hostname_match(common_name.c_str(), hostname) ? 0 : -1;
    }
    for(size_t i = 0; i < dns_names.size(); ++i) {
      if(tls_hostname_match(dns_names[i].c_str(), hostname)) {
        return 0;
      }
    }
  }
  return -1;
}
} // namespace

void get_altnames(X509 *cert,
                  std::vector<std::string>& dns_names,
                  std::vector<std::string>& ip_addrs,
                  std::string& common_name)
{
  GENERAL_NAMES *altnames =
    static_cast<GENERAL_NAMES*>
    (X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
  if(altnames) {
    util::auto_delete<GENERAL_NAMES*> altnames_deleter(altnames,
                                                       GENERAL_NAMES_free);
    size_t n = sk_GENERAL_NAME_num(altnames);
    for(size_t i = 0; i < n; ++i) {
      const GENERAL_NAME *altname = sk_GENERAL_NAME_value(altnames, i);
      if(altname->type == GEN_DNS) {
        const char *name;
        name = reinterpret_cast<char*>(ASN1_STRING_data(altname->d.ia5));
        if(!name) {
          continue;
        }
        size_t len = ASN1_STRING_length(altname->d.ia5);
        if(std::find(name, name+len, '\0') != name+len) {
          // Embedded NULL is not permitted.
          continue;
        }
        dns_names.push_back(std::string(name, len));
      } else if(altname->type == GEN_IPADD) {
        const unsigned char *ip_addr = altname->d.iPAddress->data;
        if(!ip_addr) {
          continue;
        }
        size_t len = altname->d.iPAddress->length;
        ip_addrs.push_back(std::string(reinterpret_cast<const char*>(ip_addr),
                                      len));
      }
    }
  }
  X509_NAME *subjectname = X509_get_subject_name(cert);
  if(!subjectname) {
    LOG(WARNING) << "Could not get X509 name object from the certificate.";
    return;
  }
  int lastpos = -1;
  while(1) {
    lastpos = X509_NAME_get_index_by_NID(subjectname, NID_commonName,
                                         lastpos);
    if(lastpos == -1) {
      break;
    }
    X509_NAME_ENTRY *entry = X509_NAME_get_entry(subjectname, lastpos);
    unsigned char *out;
    int outlen = ASN1_STRING_to_UTF8(&out, X509_NAME_ENTRY_get_data(entry));
    if(outlen < 0) {
      continue;
    }
    if(std::find(out, out+outlen, '\0') != out+outlen) {
      // Embedded NULL is not permitted.
      continue;
    }
    common_name.assign(&out[0], &out[outlen]);
    OPENSSL_free(out);
    break;
  }
}

int check_cert(SSL *ssl)
{
  auto cert = SSL_get_peer_certificate(ssl);
  if(!cert) {
    LOG(ERROR) << "No certificate found";
    return -1;
  }
  util::auto_delete<X509*> cert_deleter(cert, X509_free);
  long verify_res = SSL_get_verify_result(ssl);
  if(verify_res != X509_V_OK) {
    LOG(ERROR) << "Certificate verification failed: "
               << X509_verify_cert_error_string(verify_res);
    return -1;
  }
  std::string common_name;
  std::vector<std::string> dns_names;
  std::vector<std::string> ip_addrs;
  get_altnames(cert, dns_names, ip_addrs, common_name);
  if(verify_hostname(get_config()->downstream_host,
                     &get_config()->downstream_addr,
                     get_config()->downstream_addrlen,
                     dns_names, ip_addrs, common_name) != 0) {
    LOG(ERROR) << "Certificate verification failed: hostname does not match";
    return -1;
  }
  return 0;
}

namespace {
std::unique_ptr<pthread_mutex_t[]> ssl_locks;
} // namespace

namespace {
void ssl_locking_cb(int mode, int type, const char *file, int line)
{
  if(mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(ssl_locks[type]));
  } else {
    pthread_mutex_unlock(&(ssl_locks[type]));
  }
}
} // namespace

void setup_ssl_lock()
{
  ssl_locks = util::make_unique<pthread_mutex_t[]>(CRYPTO_num_locks());
  for(int i = 0; i < CRYPTO_num_locks(); ++i) {
    // Always returns 0
    pthread_mutex_init(&(ssl_locks[i]), 0);
  }
  //CRYPTO_set_id_callback(ssl_thread_id); OpenSSL manual says that if
  // threadid_func is not specified using
  // CRYPTO_THREADID_set_callback(), then default implementation is
  // used. We use this default one.
  CRYPTO_set_locking_callback(ssl_locking_cb);
}

void teardown_ssl_lock()
{
  for(int i = 0; i < CRYPTO_num_locks(); ++i) {
    pthread_mutex_destroy(&(ssl_locks[i]));
  }
  ssl_locks.reset();
}

CertLookupTree* cert_lookup_tree_new()
{
  auto tree = new CertLookupTree();
  auto root = new CertNode();
  root->ssl_ctx = 0;
  root->str = 0;
  root->first = root->last = 0;
  tree->root = root;
  return tree;
}

namespace {
void cert_node_del(CertNode *node)
{
  for(auto& a : node->next) {
    cert_node_del(a);
  }
  delete node;
}
} // namespace

void cert_lookup_tree_del(CertLookupTree *lt)
{
  cert_node_del(lt->root);
  for(auto& s : lt->hosts) {
    delete [] s;
  }
  delete lt;
}

namespace {
// The |offset| is the index in the hostname we are examining.  We are
// going to scan from |offset| in backwards.
void cert_lookup_tree_add_cert(CertLookupTree *lt, CertNode *node,
                               SSL_CTX *ssl_ctx,
                               char *hostname, size_t len, int offset)
{
  int i, next_len = node->next.size();
  char c = hostname[offset];
  CertNode *cn = nullptr;
  for(i = 0; i < next_len; ++i) {
    cn = node->next[i];
    if(cn->str[cn->first] == c) {
      break;
    }
  }
  if(i == next_len) {
    if(c == '*') {
      // We assume hostname as wildcard hostname when first '*' is
      // encountered. Note that as per RFC 6125 (6.4.3), there are
      // some restrictions for wildcard hostname. We just ignore
      // these rules here but do the proper check when we do the
      // match.
      node->wildcard_certs.push_back(std::make_pair(hostname, ssl_ctx));
    } else {
      int j;
      auto new_node = new CertNode();
      new_node->str = hostname;
      new_node->first = offset;
      // If wildcard is found, set the region before it because we
      // don't include it in [first, last).
      for(j = offset; j >= 0 && hostname[j] != '*'; --j);
      new_node->last = j;
      if(j == -1) {
        new_node->ssl_ctx = ssl_ctx;
      } else {
        new_node->ssl_ctx = nullptr;
        new_node->wildcard_certs.push_back(std::make_pair(hostname, ssl_ctx));
      }
      node->next.push_back(new_node);
    }
  } else {
    int j;
    for(i = cn->first, j = offset; i > cn->last && j >= 0 &&
          cn->str[i] == hostname[j]; --i, --j);
    if(i == cn->last) {
      if(j == -1) {
        if(cn->ssl_ctx) {
          // same hostname, we don't overwrite exiting ssl_ctx
        } else {
          cn->ssl_ctx = ssl_ctx;
        }
      } else {
        // The existing hostname is a suffix of this hostname.
        // Continue matching at potion j.
        cert_lookup_tree_add_cert(lt, cn, ssl_ctx, hostname, len, j);
      }
    } else {
      auto new_node = new CertNode();
      new_node->ssl_ctx = cn->ssl_ctx;
      new_node->str = cn->str;
      new_node->first = i;
      new_node->last = cn->last;
      new_node->wildcard_certs.swap(cn->wildcard_certs);
      new_node->next.swap(cn->next);

      cn->next.push_back(new_node);

      cn->last = i;
      if(j == -1) {
        // This hostname is a suffix of the existing hostname.
        cn->ssl_ctx = ssl_ctx;
      } else {
        // This hostname and existing one share suffix.
        cn->ssl_ctx = nullptr;
        cert_lookup_tree_add_cert(lt, cn, ssl_ctx, hostname, len, j);
      }
    }
  }
}
} // namespace

void cert_lookup_tree_add_cert(CertLookupTree *lt, SSL_CTX *ssl_ctx,
                               const char *hostname, size_t len)
{
  if(len == 0) {
    return;
  }
  // Copy hostname including terminal NULL
  char *host_copy = new char[len + 1];
  for(size_t i = 0; i < len; ++i) {
    host_copy[i] = util::lowcase(hostname[i]);
  }
  host_copy[len] = '\0';
  lt->hosts.push_back(host_copy);
  cert_lookup_tree_add_cert(lt, lt->root, ssl_ctx, host_copy, len, len-1);
}

namespace {
SSL_CTX* cert_lookup_tree_lookup(CertLookupTree *lt, CertNode *node,
                                 const char *hostname, size_t len, int offset)
{
  int i, j;
  for(i = node->first, j = offset; i > node->last && j >= 0 &&
        node->str[i] == util::lowcase(hostname[j]); --i, --j);
  if(i != node->last) {
    return nullptr;
  }
  if(j == -1) {
    if(node->ssl_ctx) {
      // exact match
      return node->ssl_ctx;
    } else {
      // Do not perform wildcard-match because '*' must match at least
      // one character.
      return nullptr;
    }
  }
  for(auto& wildcert : node->wildcard_certs) {
    if(tls_hostname_match(wildcert.first, hostname)) {
      return wildcert.second;
    }
  }
  char c = util::lowcase(hostname[j]);
  for(auto& next_node : node->next) {
    if(next_node->str[next_node->first] == c) {
      return cert_lookup_tree_lookup(lt, next_node, hostname, len, j);
    }
  }
  return nullptr;
}
} // namespace

SSL_CTX* cert_lookup_tree_lookup(CertLookupTree *lt,
                                 const char *hostname, size_t len)
{
  return cert_lookup_tree_lookup(lt, lt->root, hostname, len, len-1);
}


int cert_lookup_tree_add_cert_from_file(CertLookupTree *lt, SSL_CTX *ssl_ctx,
                                        const char *certfile)
{
  auto bio = BIO_new(BIO_s_file());
  if(!bio) {
    LOG(ERROR) << "BIO_new failed";
    return -1;
  }
  util::auto_delete<BIO*> bio_deleter(bio, BIO_vfree);
  if(!BIO_read_filename(bio, certfile)) {
    LOG(ERROR) << "Could not read certificate file '" << certfile << "'";
    return -1;
  }
  auto cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  if(!cert) {
    LOG(ERROR) << "Could not read X509 structure from file '"
               << certfile << "'";
    return -1;
  }
  util::auto_delete<X509*> cert_deleter(cert, X509_free);
  std::string common_name;
  std::vector<std::string> dns_names;
  std::vector<std::string> ip_addrs;
  get_altnames(cert, dns_names, ip_addrs, common_name);
  for(auto& dns_name : dns_names) {
    cert_lookup_tree_add_cert(lt, ssl_ctx, dns_name.c_str(), dns_name.size());
  }
  cert_lookup_tree_add_cert(lt, ssl_ctx, common_name.c_str(),
                            common_name.size());
  return 0;
}

bool in_proto_list(char **protos, size_t len,
                   const unsigned char *proto, size_t protolen)
{
  for(size_t i = 0; i < len; ++i) {
    if(strlen(protos[i]) == protolen &&
       memcmp(protos[i], proto, protolen) == 0) {
      return true;
    }
  }
  return false;
}

} // namespace ssl

} // namespace shrpx
