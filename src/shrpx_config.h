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
#ifndef SHRPX_CONFIG_H
#define SHRPX_CONFIG_H

#include "shrpx.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>

#include <event.h>
#include <openssl/ssl.h>

namespace shrpx {

namespace ssl {

struct CertLookupTree;

} // namespace ssl

extern const char SHRPX_OPT_PRIVATE_KEY_FILE[];
extern const char SHRPX_OPT_PRIVATE_KEY_PASSWD_FILE[];
extern const char SHRPX_OPT_CERTIFICATE_FILE[];
extern const char SHRPX_OPT_DH_PARAM_FILE[];
extern const char SHRPX_OPT_SUBCERT[];
extern const char SHRPX_OPT_BACKEND[];
extern const char SHRPX_OPT_FRONTEND[];
extern const char SHRPX_OPT_WORKERS[];
extern const char SHRPX_OPT_HTTP2_MAX_CONCURRENT_STREAMS[];
extern const char SHRPX_OPT_LOG_LEVEL[];
extern const char SHRPX_OPT_DAEMON[];
extern const char SHRPX_OPT_HTTP2_PROXY[];
extern const char SHRPX_OPT_HTTP2_BRIDGE[];
extern const char SHRPX_OPT_CLIENT_PROXY[];
extern const char SHRPX_OPT_ADD_X_FORWARDED_FOR[];
extern const char SHRPX_OPT_NO_VIA[];
extern const char SHRPX_OPT_FRONTEND_HTTP2_READ_TIMEOUT[];
extern const char SHRPX_OPT_FRONTEND_READ_TIMEOUT[];
extern const char SHRPX_OPT_FRONTEND_WRITE_TIMEOUT[];
extern const char SHRPX_OPT_BACKEND_READ_TIMEOUT[];
extern const char SHRPX_OPT_BACKEND_WRITE_TIMEOUT[];
extern const char SHRPX_OPT_ACCESSLOG[];
extern const char SHRPX_OPT_BACKEND_KEEP_ALIVE_TIMEOUT[];
extern const char SHRPX_OPT_FRONTEND_HTTP2_WINDOW_BITS[];
extern const char SHRPX_OPT_BACKEND_HTTP2_WINDOW_BITS[];
extern const char SHRPX_OPT_FRONTEND_NO_TLS[];
extern const char SHRPX_OPT_BACKEND_NO_TLS[];
extern const char SHRPX_OPT_PID_FILE[];
extern const char SHRPX_OPT_USER[];
extern const char SHRPX_OPT_SYSLOG[];
extern const char SHRPX_OPT_SYSLOG_FACILITY[];
extern const char SHRPX_OPT_BACKLOG[];
extern const char SHRPX_OPT_CIPHERS[];
extern const char SHRPX_OPT_HONOR_CIPHER_ORDER[];
extern const char SHRPX_OPT_CLIENT[];
extern const char SHRPX_OPT_INSECURE[];
extern const char SHRPX_OPT_CACERT[];
extern const char SHRPX_OPT_BACKEND_IPV4[];
extern const char SHRPX_OPT_BACKEND_IPV6[];
extern const char SHRPX_OPT_BACKEND_HTTP_PROXY_URI[];
extern const char SHRPX_OPT_BACKEND_TLS_SNI_FIELD[];
extern const char SHRPX_OPT_READ_RATE[];
extern const char SHRPX_OPT_READ_BURST[];
extern const char SHRPX_OPT_WRITE_RATE[];
extern const char SHRPX_OPT_WRITE_BURST[];
extern const char SHRPX_OPT_NPN_LIST[];
extern const char SHRPX_OPT_VERIFY_CLIENT[];
extern const char SHRPX_OPT_VERIFY_CLIENT_CACERT[];
extern const char SHRPX_OPT_CLIENT_PRIVATE_KEY_FILE[];
extern const char SHRPX_OPT_CLIENT_CERT_FILE[];

union sockaddr_union {
  sockaddr sa;
  sockaddr_storage storage;
  sockaddr_in6 in6;
  sockaddr_in in;
};

enum shrpx_proto {
  PROTO_SPDY,
  PROTO_HTTP
};

struct Config {
  bool verbose;
  bool daemon;
  char *host;
  uint16_t port;
  char *private_key_file;
  char *private_key_passwd;
  char *cert_file;
  char *dh_param_file;
  SSL_CTX *default_ssl_ctx;
  ssl::CertLookupTree *cert_tree;
  bool verify_client;
  const char *server_name;
  char *downstream_host;
  uint16_t downstream_port;
  char *downstream_hostport;
  sockaddr_union downstream_addr;
  size_t downstream_addrlen;
  timeval http2_upstream_read_timeout;
  timeval upstream_read_timeout;
  timeval upstream_write_timeout;
  timeval downstream_read_timeout;
  timeval downstream_write_timeout;
  timeval downstream_idle_read_timeout;
  size_t num_worker;
  size_t http2_max_concurrent_streams;
  bool http2_proxy;
  bool http2_bridge;
  bool client_proxy;
  bool add_x_forwarded_for;
  bool no_via;
  bool accesslog;
  size_t http2_upstream_window_bits;
  size_t http2_downstream_window_bits;
  bool upstream_no_tls;
  bool downstream_no_tls;
  char *backend_tls_sni_name;
  char *pid_file;
  uid_t uid;
  gid_t gid;
  char *conf_path;
  bool syslog;
  int syslog_facility;
  // This member finally decides syslog is used or not
  bool use_syslog;
  int backlog;
  char *ciphers;
  bool honor_cipher_order;
  bool client;
  // true if --client or --client-proxy are enabled.
  bool client_mode;
  // downstream protocol; this will be determined by given options.
  shrpx_proto downstream_proto;
  bool insecure;
  char *cacert;
  bool backend_ipv4;
  bool backend_ipv6;
  // true if stderr refers to a terminal.
  bool tty;
  // userinfo in http proxy URI, not percent-encoded form
  char *downstream_http_proxy_userinfo;
  // host in http proxy URI
  char *downstream_http_proxy_host;
  // port in http proxy URI
  uint16_t downstream_http_proxy_port;
  // binary form of http proxy host and port
  sockaddr_union downstream_http_proxy_addr;
  // actual size of downstream_http_proxy_addr
  size_t downstream_http_proxy_addrlen;
  // Rate limit configuration
  ev_token_bucket_cfg *rate_limit_cfg;
  size_t read_rate;
  size_t read_burst;
  size_t write_rate;
  size_t write_burst;
  // Comma delimited list of NPN protocol strings in the order of
  // preference.
  char **npn_list;
  // The number of elements in npn_list
  size_t npn_list_len;
  // The list of (private key file, certificate file) pair
  std::vector<std::pair<std::string, std::string>> subcerts;
  // Path to file containing CA certificate solely used for client
  // certificate validation
  char *verify_client_cacert;
  char *client_private_key_file;
  char *client_cert_file;
};

const Config* get_config();
Config* mod_config();
void create_config();

// Parses option name |opt| and value |optarg|.  The results are
// stored into statically allocated Config object. This function
// returns 0 if it succeeds, or -1.
int parse_config(const char *opt, const char *optarg);

// Loads configurations from |filename| and stores them in statically
// allocated Config object. This function returns 0 if it succeeds, or
// -1.
int load_config(const char *filename);

// Read passwd from |filename|
std::string read_passwd_from_file(const char *filename);

// Parses NPN protocol strings in |s| and stores the protocols list in
// mod_config()->npn_list and assigns the number of elements in
// mod_config()->npn_list_len. The |s| must be comma delimited list of
// protocol strings. The strings must be delimited by a single command
// and any white spaces around it are treated as a part of protocol
// strings.  This function always succeeds and returns 0.
int parse_config_npn_list(const char *s);

// Copies NULL-terminated string |val| to |*destp|. If |*destp| is not
// NULL, it is freed before copying.
void set_config_str(char **destp, const char *val);

// Returns string for syslog |facility|.
const char* str_syslog_facility(int facility);

// Returns integer value of syslog |facility| string.
int int_syslog_facility(const char *strfacility);

} // namespace shrpx

#endif // SHRPX_CONFIG_H
