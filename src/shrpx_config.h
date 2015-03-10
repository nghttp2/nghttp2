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
#ifndef SHRPX_CONFIG_H
#define SHRPX_CONFIG_H

#include "shrpx.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdio>
#include <vector>
#include <memory>

#include <openssl/ssl.h>

#include <ev.h>

#include <nghttp2/nghttp2.h>

namespace shrpx {

struct LogFragment;

namespace ssl {

class CertLookupTree;

} // namespace ssl

#define SHRPX_UNIX_PATH_PREFIX "unix:"

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
extern const char SHRPX_OPT_STRIP_INCOMING_X_FORWARDED_FOR[];
extern const char SHRPX_OPT_NO_VIA[];
extern const char SHRPX_OPT_FRONTEND_HTTP2_READ_TIMEOUT[];
extern const char SHRPX_OPT_FRONTEND_READ_TIMEOUT[];
extern const char SHRPX_OPT_FRONTEND_WRITE_TIMEOUT[];
extern const char SHRPX_OPT_BACKEND_READ_TIMEOUT[];
extern const char SHRPX_OPT_BACKEND_WRITE_TIMEOUT[];
extern const char SHRPX_OPT_STREAM_READ_TIMEOUT[];
extern const char SHRPX_OPT_STREAM_WRITE_TIMEOUT[];
extern const char SHRPX_OPT_ACCESSLOG_FILE[];
extern const char SHRPX_OPT_ACCESSLOG_SYSLOG[];
extern const char SHRPX_OPT_ACCESSLOG_FORMAT[];
extern const char SHRPX_OPT_ERRORLOG_FILE[];
extern const char SHRPX_OPT_ERRORLOG_SYSLOG[];
extern const char SHRPX_OPT_BACKEND_KEEP_ALIVE_TIMEOUT[];
extern const char SHRPX_OPT_FRONTEND_HTTP2_WINDOW_BITS[];
extern const char SHRPX_OPT_BACKEND_HTTP2_WINDOW_BITS[];
extern const char SHRPX_OPT_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS[];
extern const char SHRPX_OPT_BACKEND_HTTP2_CONNECTION_WINDOW_BITS[];
extern const char SHRPX_OPT_FRONTEND_NO_TLS[];
extern const char SHRPX_OPT_BACKEND_NO_TLS[];
extern const char SHRPX_OPT_PID_FILE[];
extern const char SHRPX_OPT_USER[];
extern const char SHRPX_OPT_SYSLOG_FACILITY[];
extern const char SHRPX_OPT_BACKLOG[];
extern const char SHRPX_OPT_CIPHERS[];
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
extern const char SHRPX_OPT_WORKER_READ_RATE[];
extern const char SHRPX_OPT_WORKER_READ_BURST[];
extern const char SHRPX_OPT_WORKER_WRITE_RATE[];
extern const char SHRPX_OPT_WORKER_WRITE_BURST[];
extern const char SHRPX_OPT_NPN_LIST[];
extern const char SHRPX_OPT_TLS_PROTO_LIST[];
extern const char SHRPX_OPT_VERIFY_CLIENT[];
extern const char SHRPX_OPT_VERIFY_CLIENT_CACERT[];
extern const char SHRPX_OPT_CLIENT_PRIVATE_KEY_FILE[];
extern const char SHRPX_OPT_CLIENT_CERT_FILE[];
extern const char SHRPX_OPT_FRONTEND_HTTP2_DUMP_REQUEST_HEADER[];
extern const char SHRPX_OPT_FRONTEND_HTTP2_DUMP_RESPONSE_HEADER[];
extern const char SHRPX_OPT_HTTP2_NO_COOKIE_CRUMBLING[];
extern const char SHRPX_OPT_FRONTEND_FRAME_DEBUG[];
extern const char SHRPX_OPT_PADDING[];
extern const char SHRPX_OPT_ALTSVC[];
extern const char SHRPX_OPT_ADD_RESPONSE_HEADER[];
extern const char SHRPX_OPT_WORKER_FRONTEND_CONNECTIONS[];
extern const char SHRPX_OPT_NO_LOCATION_REWRITE[];
extern const char SHRPX_OPT_NO_HOST_REWRITE[];
extern const char SHRPX_OPT_BACKEND_HTTP1_CONNECTIONS_PER_HOST[];
extern const char SHRPX_OPT_BACKEND_HTTP1_CONNECTIONS_PER_FRONTEND[];
extern const char SHRPX_OPT_LISTENER_DISABLE_TIMEOUT[];
extern const char SHRPX_OPT_TLS_TICKET_KEY_FILE[];
extern const char SHRPX_OPT_RLIMIT_NOFILE[];
extern const char SHRPX_OPT_TLS_CTX_PER_WORKER[];
extern const char SHRPX_OPT_BACKEND_REQUEST_BUFFER[];
extern const char SHRPX_OPT_BACKEND_RESPONSE_BUFFER[];
extern const char SHRPX_OPT_NO_SERVER_PUSH[];
extern const char SHRPX_OPT_BACKEND_HTTP2_CONNECTION_CHECK[];

union sockaddr_union {
  sockaddr_storage storage;
  sockaddr sa;
  sockaddr_in6 in6;
  sockaddr_in in;
  sockaddr_un un;
};

enum shrpx_proto { PROTO_HTTP2, PROTO_HTTP };

struct AltSvc {
  AltSvc()
      : protocol_id(nullptr), host(nullptr), origin(nullptr),
        protocol_id_len(0), host_len(0), origin_len(0), port(0) {}

  char *protocol_id;
  char *host;
  char *origin;

  size_t protocol_id_len;
  size_t host_len;
  size_t origin_len;

  uint16_t port;
};

struct DownstreamAddr {
  DownstreamAddr() : addr{{0}}, addrlen(0), port(0), host_unix(false) {}
  sockaddr_union addr;
  // backend address.  If |host_unix| is true, this is UNIX domain
  // socket path.
  std::unique_ptr<char[]> host;
  std::unique_ptr<char[]> hostport;
  size_t addrlen;
  // backend port.  0 if |host_unix| is true.
  uint16_t port;
  // true if |host| contains UNIX domain socket path.
  bool host_unix;
};

struct TicketKey {
  uint8_t name[16];
  uint8_t aes_key[16];
  uint8_t hmac_key[16];
};

struct TicketKeys {
  ~TicketKeys();
  std::vector<TicketKey> keys;
};

struct Config {
  // The list of (private key file, certificate file) pair
  std::vector<std::pair<std::string, std::string>> subcerts;
  std::vector<AltSvc> altsvcs;
  std::vector<std::pair<std::string, std::string>> add_response_headers;
  std::vector<unsigned char> alpn_prefs;
  std::vector<LogFragment> accesslog_format;
  std::vector<DownstreamAddr> downstream_addrs;
  std::vector<std::string> tls_ticket_key_files;
  // binary form of http proxy host and port
  sockaddr_union downstream_http_proxy_addr;
  ev_tstamp http2_upstream_read_timeout;
  ev_tstamp upstream_read_timeout;
  ev_tstamp upstream_write_timeout;
  ev_tstamp downstream_read_timeout;
  ev_tstamp downstream_write_timeout;
  ev_tstamp stream_read_timeout;
  ev_tstamp stream_write_timeout;
  ev_tstamp downstream_idle_read_timeout;
  ev_tstamp listener_disable_timeout;
  // address of frontend connection.  This could be a path to UNIX
  // domain socket.  In this case, |host_unix| must be true.
  std::unique_ptr<char[]> host;
  std::unique_ptr<char[]> private_key_file;
  std::unique_ptr<char[]> private_key_passwd;
  std::unique_ptr<char[]> cert_file;
  std::unique_ptr<char[]> dh_param_file;
  const char *server_name;
  std::unique_ptr<char[]> backend_tls_sni_name;
  std::unique_ptr<char[]> pid_file;
  std::unique_ptr<char[]> conf_path;
  std::unique_ptr<char[]> ciphers;
  std::unique_ptr<char[]> cacert;
  // userinfo in http proxy URI, not percent-encoded form
  std::unique_ptr<char[]> downstream_http_proxy_userinfo;
  // host in http proxy URI
  std::unique_ptr<char[]> downstream_http_proxy_host;
  std::unique_ptr<char[]> http2_upstream_dump_request_header_file;
  std::unique_ptr<char[]> http2_upstream_dump_response_header_file;
  // // Rate limit configuration per connection
  // ev_token_bucket_cfg *rate_limit_cfg;
  // // Rate limit configuration per worker (thread)
  // ev_token_bucket_cfg *worker_rate_limit_cfg;
  // list of supported NPN/ALPN protocol strings in the order of
  // preference. The each element of this list is a NULL-terminated
  // string.
  std::vector<char *> npn_list;
  // list of supported SSL/TLS protocol strings. The each element of
  // this list is a NULL-terminated string.
  std::vector<char *> tls_proto_list;
  // Path to file containing CA certificate solely used for client
  // certificate validation
  std::unique_ptr<char[]> verify_client_cacert;
  std::unique_ptr<char[]> client_private_key_file;
  std::unique_ptr<char[]> client_cert_file;
  std::unique_ptr<char[]> accesslog_file;
  std::unique_ptr<char[]> errorlog_file;
  FILE *http2_upstream_dump_request_header;
  FILE *http2_upstream_dump_response_header;
  nghttp2_session_callbacks *http2_upstream_callbacks;
  nghttp2_session_callbacks *http2_downstream_callbacks;
  nghttp2_option *http2_option;
  nghttp2_option *http2_client_option;
  char **argv;
  char *cwd;
  size_t num_worker;
  size_t http2_max_concurrent_streams;
  size_t http2_upstream_window_bits;
  size_t http2_downstream_window_bits;
  size_t http2_upstream_connection_window_bits;
  size_t http2_downstream_connection_window_bits;
  size_t http2_downstream_connections_per_worker;
  size_t downstream_connections_per_host;
  size_t downstream_connections_per_frontend;
  // actual size of downstream_http_proxy_addr
  size_t downstream_http_proxy_addrlen;
  size_t read_rate;
  size_t read_burst;
  size_t write_rate;
  size_t write_burst;
  size_t worker_read_rate;
  size_t worker_read_burst;
  size_t worker_write_rate;
  size_t worker_write_burst;
  size_t padding;
  size_t worker_frontend_connections;
  size_t rlimit_nofile;
  size_t downstream_request_buffer_size;
  size_t downstream_response_buffer_size;
  // Bit mask to disable SSL/TLS protocol versions.  This will be
  // passed to SSL_CTX_set_options().
  long int tls_proto_mask;
  // downstream protocol; this will be determined by given options.
  shrpx_proto downstream_proto;
  int syslog_facility;
  int backlog;
  int argc;
  std::unique_ptr<char[]> user;
  uid_t uid;
  gid_t gid;
  pid_t pid;
  // frontend listening port.  0 if frontend listens on UNIX domain
  // socket, in this case |host_unix| must be true.
  uint16_t port;
  // port in http proxy URI
  uint16_t downstream_http_proxy_port;
  bool verbose;
  bool daemon;
  bool verify_client;
  bool http2_proxy;
  bool http2_bridge;
  bool client_proxy;
  bool add_x_forwarded_for;
  bool strip_incoming_x_forwarded_for;
  bool no_via;
  bool upstream_no_tls;
  bool downstream_no_tls;
  // Send accesslog to syslog, ignoring accesslog_file.
  bool accesslog_syslog;
  // Send errorlog to syslog, ignoring errorlog_file.
  bool errorlog_syslog;
  bool client;
  // true if --client or --client-proxy are enabled.
  bool client_mode;
  bool insecure;
  bool backend_ipv4;
  bool backend_ipv6;
  bool http2_no_cookie_crumbling;
  bool upstream_frame_debug;
  bool no_location_rewrite;
  bool no_host_rewrite;
  bool tls_ctx_per_worker;
  bool no_server_push;
  // true if host contains UNIX domain socket path
  bool host_unix;
  bool http2_downstream_connchk;
};

const Config *get_config();
Config *mod_config();
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

// Parses comma delimited strings in |s| and returns the array of
// pointers, each element points to the each substring in |s|.  The
// |s| must be comma delimited list of strings.  The strings must be
// delimited by a single comma and any white spaces around it are
// treated as a part of protocol strings.  This function may modify
// |s| and the caller must leave it as is after this call.  This
// function copies |s| and first element in the return value points to
// it.  It is caller's responsibility to deallocate its memory.
std::vector<char *> parse_config_str_list(const char *s);

// Clears all elements of |list|, which is returned by
// parse_config_str_list().  If list is not empty, list[0] is freed by
// free(2).  After this call, list.empty() must be true.
void clear_config_str_list(std::vector<char *> &list);

// Parses header field in |optarg|.  We expect header field is formed
// like "NAME: VALUE".  We require that NAME is non empty string.  ":"
// is allowed at the start of the NAME, but NAME == ":" is not
// allowed.  This function returns pair of NAME and VALUE.
std::pair<std::string, std::string> parse_header(const char *optarg);

std::vector<LogFragment> parse_log_format(const char *optarg);

// Returns a copy of NULL-terminated string |val|.
std::unique_ptr<char[]> strcopy(const char *val);

// Returns a copy of string |val| of length |n|.  The returned string
// will be NULL-terminated.
std::unique_ptr<char[]> strcopy(const char *val, size_t n);

// Returns a copy of val.c_str().
std::unique_ptr<char[]> strcopy(const std::string &val);

// Returns string for syslog |facility|.
const char *str_syslog_facility(int facility);

// Returns integer value of syslog |facility| string.
int int_syslog_facility(const char *strfacility);

FILE *open_file_for_write(const char *filename);

// Reads TLS ticket key file in |files| and returns TicketKey which
// stores read key data.  This function returns TicketKey if it
// succeeds, or nullptr.
std::unique_ptr<TicketKeys>
read_tls_ticket_key_file(const std::vector<std::string> &files);

} // namespace shrpx

#endif // SHRPX_CONFIG_H
