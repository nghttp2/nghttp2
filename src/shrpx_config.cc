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
#include "shrpx_config.h"

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif // HAVE_PWD_H
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif // HAVE_NETDB_H
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif // HAVE_SYSLOG_H
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif // HAVE_FCNTL_H
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif // HAVE_UNISTD_H

#include <cstring>
#include <cerrno>
#include <limits>
#include <fstream>

#include <nghttp2/nghttp2.h>

#include "http-parser/http_parser.h"

#include "shrpx_log.h"
#include "shrpx_ssl.h"
#include "shrpx_http.h"
#include "http2.h"
#include "util.h"
#include "template.h"
#include "base64.h"

namespace shrpx {

namespace {
Config *config = nullptr;
} // namespace

const Config *get_config() { return config; }

Config *mod_config() { return config; }

void create_config() { config = new Config(); }

TicketKeys::~TicketKeys() {
  /* Erase keys from memory */
  for (auto &key : keys) {
    memset(&key, 0, sizeof(key));
  }
}

DownstreamAddr::DownstreamAddr(const DownstreamAddr &other)
    : addr(other.addr), host(other.host ? strcopy(other.host.get()) : nullptr),
      hostport(other.hostport ? strcopy(other.hostport.get()) : nullptr),
      port(other.port), host_unix(other.host_unix) {}

DownstreamAddr &DownstreamAddr::operator=(const DownstreamAddr &other) {
  if (this == &other) {
    return *this;
  }

  addr = other.addr;
  host = (other.host ? strcopy(other.host.get()) : nullptr);
  hostport = (other.hostport ? strcopy(other.hostport.get()) : nullptr);
  port = other.port;
  host_unix = other.host_unix;

  return *this;
}

namespace {
int split_host_port(char *host, size_t hostlen, uint16_t *port_ptr,
                    const char *hostport, size_t hostportlen) {
  // host and port in |hostport| is separated by single ','.
  const char *p = strchr(hostport, ',');
  if (!p) {
    LOG(ERROR) << "Invalid host, port: " << hostport;
    return -1;
  }
  size_t len = p - hostport;
  if (hostlen < len + 1) {
    LOG(ERROR) << "Hostname too long: " << hostport;
    return -1;
  }
  memcpy(host, hostport, len);
  host[len] = '\0';

  errno = 0;
  auto portlen = hostportlen - len - 1;
  auto d = util::parse_uint(reinterpret_cast<const uint8_t *>(p + 1), portlen);
  if (1 <= d && d <= std::numeric_limits<uint16_t>::max()) {
    *port_ptr = d;
    return 0;
  } else {
    LOG(ERROR) << "Port is invalid: " << std::string(p + 1, portlen);
    return -1;
  }
}
} // namespace

namespace {
bool is_secure(const char *filename) {
  struct stat buf;
  int rv = stat(filename, &buf);
  if (rv == 0) {
    if ((buf.st_mode & S_IRWXU) && !(buf.st_mode & S_IRWXG) &&
        !(buf.st_mode & S_IRWXO)) {
      return true;
    }
  }

  return false;
}
} // namespace

std::unique_ptr<TicketKeys>
read_tls_ticket_key_file(const std::vector<std::string> &files,
                         const EVP_CIPHER *cipher, const EVP_MD *hmac) {
  auto ticket_keys = make_unique<TicketKeys>();
  auto &keys = ticket_keys->keys;
  keys.resize(files.size());
  auto enc_keylen = EVP_CIPHER_key_length(cipher);
  auto hmac_keylen = EVP_MD_size(hmac);
  if (cipher == EVP_aes_128_cbc()) {
    // backward compatibility, as a legacy of using same file format
    // with nginx and apache.
    hmac_keylen = 16;
  }
  auto expectedlen = keys[0].data.name.size() + enc_keylen + hmac_keylen;
  char buf[256];
  assert(sizeof(buf) >= expectedlen);

  size_t i = 0;
  for (auto &file : files) {
    struct stat fst {};

    if (stat(file.c_str(), &fst) == -1) {
      auto error = errno;
      LOG(ERROR) << "tls-ticket-key-file: could not stat file " << file
                 << ", errno=" << error;
      return nullptr;
    }

    if (static_cast<size_t>(fst.st_size) != expectedlen) {
      LOG(ERROR) << "tls-ticket-key-file: the expected file size is "
                 << expectedlen << ", the actual file size is " << fst.st_size;
      return nullptr;
    }

    std::ifstream f(file.c_str());
    if (!f) {
      LOG(ERROR) << "tls-ticket-key-file: could not open file " << file;
      return nullptr;
    }

    f.read(buf, expectedlen);
    if (static_cast<size_t>(f.gcount()) != expectedlen) {
      LOG(ERROR) << "tls-ticket-key-file: want to read " << expectedlen
                 << " bytes but only read " << f.gcount() << " bytes from "
                 << file;
      return nullptr;
    }

    auto &key = keys[i++];
    key.cipher = cipher;
    key.hmac = hmac;
    key.hmac_keylen = hmac_keylen;

    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "enc_keylen=" << enc_keylen
                << ", hmac_keylen=" << key.hmac_keylen;
    }

    auto p = buf;
    std::copy_n(p, key.data.name.size(), std::begin(key.data.name));
    p += key.data.name.size();
    std::copy_n(p, enc_keylen, std::begin(key.data.enc_key));
    p += enc_keylen;
    std::copy_n(p, hmac_keylen, std::begin(key.data.hmac_key));

    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "session ticket key: " << util::format_hex(key.data.name);
    }
  }
  return ticket_keys;
}

FILE *open_file_for_write(const char *filename) {
#if defined O_CLOEXEC
  auto fd = open(filename, O_WRONLY | O_CLOEXEC | O_CREAT | O_TRUNC,
                 S_IRUSR | S_IWUSR);
#else
  auto fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

  // We get race condition if execve is called at the same time.
  if (fd != -1) {
    util::make_socket_closeonexec(fd);
  }
#endif
  if (fd == -1) {
    LOG(ERROR) << "Failed to open " << filename
               << " for writing. Cause: " << strerror(errno);
    return nullptr;
  }
  auto f = fdopen(fd, "wb");
  if (f == nullptr) {
    LOG(ERROR) << "Failed to open " << filename
               << " for writing. Cause: " << strerror(errno);
    return nullptr;
  }

  return f;
}

std::string read_passwd_from_file(const char *filename) {
  std::string line;

  if (!is_secure(filename)) {
    LOG(ERROR) << "Private key passwd file " << filename
               << " has insecure mode.";
    return line;
  }

  std::ifstream in(filename, std::ios::binary);
  if (!in) {
    LOG(ERROR) << "Could not open key passwd file " << filename;
    return line;
  }

  std::getline(in, line);
  return line;
}

std::vector<Range<const char *>> split_config_str_list(const char *s,
                                                       char delim) {
  size_t len = 1;
  auto last = s + strlen(s);
  for (const char *first = s, *d = nullptr;
       (d = std::find(first, last, delim)) != last; ++len, first = d + 1)
    ;

  auto list = std::vector<Range<const char *>>(len);

  len = 0;
  for (auto first = s;; ++len) {
    auto stop = std::find(first, last, delim);
    list[len] = {first, stop};
    if (stop == last) {
      break;
    }
    first = stop + 1;
  }
  return list;
}

std::vector<std::string> parse_config_str_list(const char *s, char delim) {
  auto ranges = split_config_str_list(s, delim);
  auto res = std::vector<std::string>();
  res.reserve(ranges.size());
  for (const auto &range : ranges) {
    res.emplace_back(range.first, range.second);
  }
  return res;
}

std::pair<std::string, std::string> parse_header(const char *optarg) {
  // We skip possible ":" at the start of optarg.
  const auto *colon = strchr(optarg + 1, ':');

  // name = ":" is not allowed
  if (colon == nullptr || (optarg[0] == ':' && colon == optarg + 1)) {
    return {"", ""};
  }

  auto value = colon + 1;
  for (; *value == '\t' || *value == ' '; ++value)
    ;

  return {std::string(optarg, colon), std::string(value, strlen(value))};
}

template <typename T>
int parse_uint(T *dest, const char *opt, const char *optarg) {
  char *end = nullptr;

  errno = 0;

  auto val = strtol(optarg, &end, 10);

  if (!optarg[0] || errno != 0 || *end || val < 0) {
    LOG(ERROR) << opt << ": bad value.  Specify an integer >= 0.";
    return -1;
  }

  *dest = val;

  return 0;
}

namespace {
template <typename T>
int parse_uint_with_unit(T *dest, const char *opt, const char *optarg) {
  auto n = util::parse_uint_with_unit(optarg);
  if (n == -1) {
    LOG(ERROR) << opt << ": bad value: '" << optarg << "'";
    return -1;
  }

  *dest = n;

  return 0;
}
} // namespace

template <typename T>
int parse_int(T *dest, const char *opt, const char *optarg) {
  char *end = nullptr;

  errno = 0;

  auto val = strtol(optarg, &end, 10);

  if (!optarg[0] || errno != 0 || *end) {
    LOG(ERROR) << opt << ": bad value.  Specify an integer.";
    return -1;
  }

  *dest = val;

  return 0;
}

namespace {
// generated by gennghttpxfun.py
LogFragmentType log_var_lookup_token(const char *name, size_t namelen) {
  switch (namelen) {
  case 3:
    switch (name[2]) {
    case 'd':
      if (util::strieq_l("pi", name, 2)) {
        return SHRPX_LOGF_PID;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'n':
      if (util::strieq_l("alp", name, 3)) {
        return SHRPX_LOGF_ALPN;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 's':
      if (util::strieq_l("statu", name, 5)) {
        return SHRPX_LOGF_STATUS;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 't':
      if (util::strieq_l("reques", name, 6)) {
        return SHRPX_LOGF_REQUEST;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'l':
      if (util::strieq_l("time_loca", name, 9)) {
        return SHRPX_LOGF_TIME_LOCAL;
      }
      break;
    case 'r':
      if (util::strieq_l("ssl_ciphe", name, 9)) {
        return SHRPX_LOGF_SSL_CIPHER;
      }
      break;
    }
    break;
  case 11:
    switch (name[10]) {
    case 'r':
      if (util::strieq_l("remote_add", name, 10)) {
        return SHRPX_LOGF_REMOTE_ADDR;
      }
      break;
    case 't':
      if (util::strieq_l("remote_por", name, 10)) {
        return SHRPX_LOGF_REMOTE_PORT;
      }
      if (util::strieq_l("server_por", name, 10)) {
        return SHRPX_LOGF_SERVER_PORT;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case '1':
      if (util::strieq_l("time_iso860", name, 11)) {
        return SHRPX_LOGF_TIME_ISO8601;
      }
      break;
    case 'e':
      if (util::strieq_l("request_tim", name, 11)) {
        return SHRPX_LOGF_REQUEST_TIME;
      }
      break;
    case 'l':
      if (util::strieq_l("ssl_protoco", name, 11)) {
        return SHRPX_LOGF_SSL_PROTOCOL;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'd':
      if (util::strieq_l("ssl_session_i", name, 13)) {
        return SHRPX_LOGF_SSL_SESSION_ID;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 't':
      if (util::strieq_l("body_bytes_sen", name, 14)) {
        return SHRPX_LOGF_BODY_BYTES_SENT;
      }
      break;
    }
    break;
  case 18:
    switch (name[17]) {
    case 'd':
      if (util::strieq_l("ssl_session_reuse", name, 17)) {
        return SHRPX_LOGF_SSL_SESSION_REUSED;
      }
      break;
    }
    break;
  }
  return SHRPX_LOGF_NONE;
}
} // namespace

namespace {
bool var_token(char c) {
  return util::isAlpha(c) || util::isDigit(c) || c == '_';
}
} // namespace

std::vector<LogFragment> parse_log_format(const char *optarg) {
  auto literal_start = optarg;
  auto p = optarg;
  auto eop = p + strlen(optarg);

  auto res = std::vector<LogFragment>();

  for (; p != eop;) {
    if (*p != '$') {
      ++p;
      continue;
    }

    auto var_start = p;

    ++p;

    const char *var_name;
    size_t var_namelen;
    if (p != eop && *p == '{') {
      var_name = ++p;
      for (; p != eop && var_token(*p); ++p)
        ;

      if (p == eop || *p != '}') {
        LOG(WARN) << "Missing '}' after " << std::string(var_start, p);
        continue;
      }

      var_namelen = p - var_name;
      ++p;
    } else {
      var_name = p;
      for (; p != eop && var_token(*p); ++p)
        ;

      var_namelen = p - var_name;
    }

    const char *value = nullptr;

    auto type = log_var_lookup_token(var_name, var_namelen);

    if (type == SHRPX_LOGF_NONE) {
      if (util::istartsWith(var_name, var_namelen, "http_")) {
        type = SHRPX_LOGF_HTTP;
        value = var_name + str_size("http_");
      } else {
        LOG(WARN) << "Unrecognized log format variable: "
                  << std::string(var_name, var_namelen);
        continue;
      }
    }

    if (literal_start < var_start) {
      res.emplace_back(SHRPX_LOGF_LITERAL, strcopy(literal_start, var_start));
    }

    literal_start = p;

    if (value == nullptr) {
      res.emplace_back(type);
      continue;
    }

    res.emplace_back(type, strcopy(value, var_name + var_namelen));
    auto &v = res.back().value;
    for (size_t i = 0; v[i]; ++i) {
      if (v[i] == '_') {
        v[i] = '-';
      }
    }
  }

  if (literal_start != eop) {
    res.emplace_back(SHRPX_LOGF_LITERAL, strcopy(literal_start, eop));
  }

  return res;
}

namespace {
int parse_duration(ev_tstamp *dest, const char *opt, const char *optarg) {
  auto t = util::parse_duration_with_unit(optarg);
  if (t == std::numeric_limits<double>::infinity()) {
    LOG(ERROR) << opt << ": bad value: '" << optarg << "'";
    return -1;
  }

  *dest = t;

  return 0;
}
} // namespace

namespace {
// Parses host-path mapping patterns in |src|, and stores mappings in
// config.  We will store each host-path pattern found in |src| with
// |addr|.  |addr| will be copied accordingly.  Also we make a group
// based on the pattern.  The "/" pattern is considered as catch-all.
void parse_mapping(const DownstreamAddr &addr, const char *src) {
  // This returns at least 1 element (it could be empty string).  We
  // will append '/' to all patterns, so it becomes catch-all pattern.
  auto mapping = split_config_str_list(src, ':');
  assert(!mapping.empty());
  for (const auto &raw_pattern : mapping) {
    auto done = false;
    std::string pattern;
    auto slash = std::find(raw_pattern.first, raw_pattern.second, '/');
    if (slash == raw_pattern.second) {
      // This effectively makes empty pattern to "/".
      pattern.assign(raw_pattern.first, raw_pattern.second);
      util::inp_strlower(pattern);
      pattern += "/";
    } else {
      pattern.assign(raw_pattern.first, slash);
      util::inp_strlower(pattern);
      pattern += http2::normalize_path(slash, raw_pattern.second);
    }
    for (auto &g : mod_config()->downstream_addr_groups) {
      if (g.pattern == pattern) {
        g.addrs.push_back(addr);
        done = true;
        break;
      }
    }
    if (done) {
      continue;
    }
    DownstreamAddrGroup g(pattern);
    g.addrs.push_back(addr);
    mod_config()->downstream_addr_groups.push_back(std::move(g));
  }
}
} // namespace

// generated by gennghttpxfun.py
enum {
  SHRPX_OPTID_ACCESSLOG_FILE,
  SHRPX_OPTID_ACCESSLOG_FORMAT,
  SHRPX_OPTID_ACCESSLOG_SYSLOG,
  SHRPX_OPTID_ADD_REQUEST_HEADER,
  SHRPX_OPTID_ADD_RESPONSE_HEADER,
  SHRPX_OPTID_ADD_X_FORWARDED_FOR,
  SHRPX_OPTID_ALTSVC,
  SHRPX_OPTID_BACKEND,
  SHRPX_OPTID_BACKEND_HTTP_PROXY_URI,
  SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_FRONTEND,
  SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_HOST,
  SHRPX_OPTID_BACKEND_HTTP2_CONNECTION_WINDOW_BITS,
  SHRPX_OPTID_BACKEND_HTTP2_CONNECTIONS_PER_WORKER,
  SHRPX_OPTID_BACKEND_HTTP2_WINDOW_BITS,
  SHRPX_OPTID_BACKEND_IPV4,
  SHRPX_OPTID_BACKEND_IPV6,
  SHRPX_OPTID_BACKEND_KEEP_ALIVE_TIMEOUT,
  SHRPX_OPTID_BACKEND_NO_TLS,
  SHRPX_OPTID_BACKEND_READ_TIMEOUT,
  SHRPX_OPTID_BACKEND_REQUEST_BUFFER,
  SHRPX_OPTID_BACKEND_RESPONSE_BUFFER,
  SHRPX_OPTID_BACKEND_TLS_SNI_FIELD,
  SHRPX_OPTID_BACKEND_WRITE_TIMEOUT,
  SHRPX_OPTID_BACKLOG,
  SHRPX_OPTID_CACERT,
  SHRPX_OPTID_CERTIFICATE_FILE,
  SHRPX_OPTID_CIPHERS,
  SHRPX_OPTID_CLIENT,
  SHRPX_OPTID_CLIENT_CERT_FILE,
  SHRPX_OPTID_CLIENT_PRIVATE_KEY_FILE,
  SHRPX_OPTID_CLIENT_PROXY,
  SHRPX_OPTID_CONF,
  SHRPX_OPTID_DAEMON,
  SHRPX_OPTID_DH_PARAM_FILE,
  SHRPX_OPTID_ERRORLOG_FILE,
  SHRPX_OPTID_ERRORLOG_SYSLOG,
  SHRPX_OPTID_FETCH_OCSP_RESPONSE_FILE,
  SHRPX_OPTID_FRONTEND,
  SHRPX_OPTID_FRONTEND_FRAME_DEBUG,
  SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS,
  SHRPX_OPTID_FRONTEND_HTTP2_DUMP_REQUEST_HEADER,
  SHRPX_OPTID_FRONTEND_HTTP2_DUMP_RESPONSE_HEADER,
  SHRPX_OPTID_FRONTEND_HTTP2_READ_TIMEOUT,
  SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_BITS,
  SHRPX_OPTID_FRONTEND_NO_TLS,
  SHRPX_OPTID_FRONTEND_READ_TIMEOUT,
  SHRPX_OPTID_FRONTEND_WRITE_TIMEOUT,
  SHRPX_OPTID_HEADER_FIELD_BUFFER,
  SHRPX_OPTID_HOST_REWRITE,
  SHRPX_OPTID_HTTP2_BRIDGE,
  SHRPX_OPTID_HTTP2_MAX_CONCURRENT_STREAMS,
  SHRPX_OPTID_HTTP2_NO_COOKIE_CRUMBLING,
  SHRPX_OPTID_HTTP2_PROXY,
  SHRPX_OPTID_INCLUDE,
  SHRPX_OPTID_INSECURE,
  SHRPX_OPTID_LISTENER_DISABLE_TIMEOUT,
  SHRPX_OPTID_LOG_LEVEL,
  SHRPX_OPTID_MAX_HEADER_FIELDS,
  SHRPX_OPTID_NO_HOST_REWRITE,
  SHRPX_OPTID_NO_LOCATION_REWRITE,
  SHRPX_OPTID_NO_OCSP,
  SHRPX_OPTID_NO_SERVER_PUSH,
  SHRPX_OPTID_NO_VIA,
  SHRPX_OPTID_NPN_LIST,
  SHRPX_OPTID_OCSP_UPDATE_INTERVAL,
  SHRPX_OPTID_PADDING,
  SHRPX_OPTID_PID_FILE,
  SHRPX_OPTID_PRIVATE_KEY_FILE,
  SHRPX_OPTID_PRIVATE_KEY_PASSWD_FILE,
  SHRPX_OPTID_READ_BURST,
  SHRPX_OPTID_READ_RATE,
  SHRPX_OPTID_RLIMIT_NOFILE,
  SHRPX_OPTID_STREAM_READ_TIMEOUT,
  SHRPX_OPTID_STREAM_WRITE_TIMEOUT,
  SHRPX_OPTID_STRIP_INCOMING_X_FORWARDED_FOR,
  SHRPX_OPTID_SUBCERT,
  SHRPX_OPTID_SYSLOG_FACILITY,
  SHRPX_OPTID_TLS_PROTO_LIST,
  SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED,
  SHRPX_OPTID_TLS_TICKET_KEY_CIPHER,
  SHRPX_OPTID_TLS_TICKET_KEY_FILE,
  SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED,
  SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_INTERVAL,
  SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_FAIL,
  SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_RETRY,
  SHRPX_OPTID_USER,
  SHRPX_OPTID_VERIFY_CLIENT,
  SHRPX_OPTID_VERIFY_CLIENT_CACERT,
  SHRPX_OPTID_WORKER_FRONTEND_CONNECTIONS,
  SHRPX_OPTID_WORKER_READ_BURST,
  SHRPX_OPTID_WORKER_READ_RATE,
  SHRPX_OPTID_WORKER_WRITE_BURST,
  SHRPX_OPTID_WORKER_WRITE_RATE,
  SHRPX_OPTID_WORKERS,
  SHRPX_OPTID_WRITE_BURST,
  SHRPX_OPTID_WRITE_RATE,
  SHRPX_OPTID_MAXIDX,
};

namespace {
// generated by gennghttpxfun.py
int option_lookup_token(const char *name, size_t namelen) {
  switch (namelen) {
  case 4:
    switch (name[3]) {
    case 'f':
      if (util::strieq_l("con", name, 3)) {
        return SHRPX_OPTID_CONF;
      }
      break;
    case 'r':
      if (util::strieq_l("use", name, 3)) {
        return SHRPX_OPTID_USER;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'a':
      if (util::strieq_l("no-vi", name, 5)) {
        return SHRPX_OPTID_NO_VIA;
      }
      break;
    case 'c':
      if (util::strieq_l("altsv", name, 5)) {
        return SHRPX_OPTID_ALTSVC;
      }
      break;
    case 'n':
      if (util::strieq_l("daemo", name, 5)) {
        return SHRPX_OPTID_DAEMON;
      }
      break;
    case 't':
      if (util::strieq_l("cacer", name, 5)) {
        return SHRPX_OPTID_CACERT;
      }
      if (util::strieq_l("clien", name, 5)) {
        return SHRPX_OPTID_CLIENT;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'd':
      if (util::strieq_l("backen", name, 6)) {
        return SHRPX_OPTID_BACKEND;
      }
      break;
    case 'e':
      if (util::strieq_l("includ", name, 6)) {
        return SHRPX_OPTID_INCLUDE;
      }
      break;
    case 'g':
      if (util::strieq_l("backlo", name, 6)) {
        return SHRPX_OPTID_BACKLOG;
      }
      if (util::strieq_l("paddin", name, 6)) {
        return SHRPX_OPTID_PADDING;
      }
      break;
    case 'p':
      if (util::strieq_l("no-ocs", name, 6)) {
        return SHRPX_OPTID_NO_OCSP;
      }
      break;
    case 's':
      if (util::strieq_l("cipher", name, 6)) {
        return SHRPX_OPTID_CIPHERS;
      }
      if (util::strieq_l("worker", name, 6)) {
        return SHRPX_OPTID_WORKERS;
      }
      break;
    case 't':
      if (util::strieq_l("subcer", name, 6)) {
        return SHRPX_OPTID_SUBCERT;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'd':
      if (util::strieq_l("fronten", name, 7)) {
        return SHRPX_OPTID_FRONTEND;
      }
      break;
    case 'e':
      if (util::strieq_l("insecur", name, 7)) {
        return SHRPX_OPTID_INSECURE;
      }
      if (util::strieq_l("pid-fil", name, 7)) {
        return SHRPX_OPTID_PID_FILE;
      }
      break;
    case 't':
      if (util::strieq_l("npn-lis", name, 7)) {
        return SHRPX_OPTID_NPN_LIST;
      }
      break;
    }
    break;
  case 9:
    switch (name[8]) {
    case 'e':
      if (util::strieq_l("read-rat", name, 8)) {
        return SHRPX_OPTID_READ_RATE;
      }
      break;
    case 'l':
      if (util::strieq_l("log-leve", name, 8)) {
        return SHRPX_OPTID_LOG_LEVEL;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'e':
      if (util::strieq_l("write-rat", name, 9)) {
        return SHRPX_OPTID_WRITE_RATE;
      }
      break;
    case 't':
      if (util::strieq_l("read-burs", name, 9)) {
        return SHRPX_OPTID_READ_BURST;
      }
      break;
    }
    break;
  case 11:
    switch (name[10]) {
    case 't':
      if (util::strieq_l("write-burs", name, 10)) {
        return SHRPX_OPTID_WRITE_BURST;
      }
      break;
    case 'y':
      if (util::strieq_l("http2-prox", name, 10)) {
        return SHRPX_OPTID_HTTP2_PROXY;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case '4':
      if (util::strieq_l("backend-ipv", name, 11)) {
        return SHRPX_OPTID_BACKEND_IPV4;
      }
      break;
    case '6':
      if (util::strieq_l("backend-ipv", name, 11)) {
        return SHRPX_OPTID_BACKEND_IPV6;
      }
      break;
    case 'e':
      if (util::strieq_l("host-rewrit", name, 11)) {
        return SHRPX_OPTID_HOST_REWRITE;
      }
      if (util::strieq_l("http2-bridg", name, 11)) {
        return SHRPX_OPTID_HTTP2_BRIDGE;
      }
      break;
    case 'y':
      if (util::strieq_l("client-prox", name, 11)) {
        return SHRPX_OPTID_CLIENT_PROXY;
      }
      break;
    }
    break;
  case 13:
    switch (name[12]) {
    case 'e':
      if (util::strieq_l("dh-param-fil", name, 12)) {
        return SHRPX_OPTID_DH_PARAM_FILE;
      }
      if (util::strieq_l("errorlog-fil", name, 12)) {
        return SHRPX_OPTID_ERRORLOG_FILE;
      }
      if (util::strieq_l("rlimit-nofil", name, 12)) {
        return SHRPX_OPTID_RLIMIT_NOFILE;
      }
      break;
    case 't':
      if (util::strieq_l("verify-clien", name, 12)) {
        return SHRPX_OPTID_VERIFY_CLIENT;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'e':
      if (util::strieq_l("accesslog-fil", name, 13)) {
        return SHRPX_OPTID_ACCESSLOG_FILE;
      }
      break;
    case 'h':
      if (util::strieq_l("no-server-pus", name, 13)) {
        return SHRPX_OPTID_NO_SERVER_PUSH;
      }
      break;
    case 's':
      if (util::strieq_l("backend-no-tl", name, 13)) {
        return SHRPX_OPTID_BACKEND_NO_TLS;
      }
      break;
    case 't':
      if (util::strieq_l("tls-proto-lis", name, 13)) {
        return SHRPX_OPTID_TLS_PROTO_LIST;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 'e':
      if (util::strieq_l("no-host-rewrit", name, 14)) {
        return SHRPX_OPTID_NO_HOST_REWRITE;
      }
      break;
    case 'g':
      if (util::strieq_l("errorlog-syslo", name, 14)) {
        return SHRPX_OPTID_ERRORLOG_SYSLOG;
      }
      break;
    case 's':
      if (util::strieq_l("frontend-no-tl", name, 14)) {
        return SHRPX_OPTID_FRONTEND_NO_TLS;
      }
      break;
    case 'y':
      if (util::strieq_l("syslog-facilit", name, 14)) {
        return SHRPX_OPTID_SYSLOG_FACILITY;
      }
      break;
    }
    break;
  case 16:
    switch (name[15]) {
    case 'e':
      if (util::strieq_l("certificate-fil", name, 15)) {
        return SHRPX_OPTID_CERTIFICATE_FILE;
      }
      if (util::strieq_l("client-cert-fil", name, 15)) {
        return SHRPX_OPTID_CLIENT_CERT_FILE;
      }
      if (util::strieq_l("private-key-fil", name, 15)) {
        return SHRPX_OPTID_PRIVATE_KEY_FILE;
      }
      if (util::strieq_l("worker-read-rat", name, 15)) {
        return SHRPX_OPTID_WORKER_READ_RATE;
      }
      break;
    case 'g':
      if (util::strieq_l("accesslog-syslo", name, 15)) {
        return SHRPX_OPTID_ACCESSLOG_SYSLOG;
      }
      break;
    case 't':
      if (util::strieq_l("accesslog-forma", name, 15)) {
        return SHRPX_OPTID_ACCESSLOG_FORMAT;
      }
      break;
    }
    break;
  case 17:
    switch (name[16]) {
    case 'e':
      if (util::strieq_l("worker-write-rat", name, 16)) {
        return SHRPX_OPTID_WORKER_WRITE_RATE;
      }
      break;
    case 's':
      if (util::strieq_l("max-header-field", name, 16)) {
        return SHRPX_OPTID_MAX_HEADER_FIELDS;
      }
      break;
    case 't':
      if (util::strieq_l("worker-read-burs", name, 16)) {
        return SHRPX_OPTID_WORKER_READ_BURST;
      }
      break;
    }
    break;
  case 18:
    switch (name[17]) {
    case 'r':
      if (util::strieq_l("add-request-heade", name, 17)) {
        return SHRPX_OPTID_ADD_REQUEST_HEADER;
      }
      break;
    case 't':
      if (util::strieq_l("worker-write-burs", name, 17)) {
        return SHRPX_OPTID_WORKER_WRITE_BURST;
      }
      break;
    }
    break;
  case 19:
    switch (name[18]) {
    case 'e':
      if (util::strieq_l("no-location-rewrit", name, 18)) {
        return SHRPX_OPTID_NO_LOCATION_REWRITE;
      }
      if (util::strieq_l("tls-ticket-key-fil", name, 18)) {
        return SHRPX_OPTID_TLS_TICKET_KEY_FILE;
      }
      break;
    case 'r':
      if (util::strieq_l("add-response-heade", name, 18)) {
        return SHRPX_OPTID_ADD_RESPONSE_HEADER;
      }
      if (util::strieq_l("add-x-forwarded-fo", name, 18)) {
        return SHRPX_OPTID_ADD_X_FORWARDED_FOR;
      }
      if (util::strieq_l("header-field-buffe", name, 18)) {
        return SHRPX_OPTID_HEADER_FIELD_BUFFER;
      }
      break;
    case 't':
      if (util::strieq_l("stream-read-timeou", name, 18)) {
        return SHRPX_OPTID_STREAM_READ_TIMEOUT;
      }
      break;
    }
    break;
  case 20:
    switch (name[19]) {
    case 'g':
      if (util::strieq_l("frontend-frame-debu", name, 19)) {
        return SHRPX_OPTID_FRONTEND_FRAME_DEBUG;
      }
      break;
    case 'l':
      if (util::strieq_l("ocsp-update-interva", name, 19)) {
        return SHRPX_OPTID_OCSP_UPDATE_INTERVAL;
      }
      break;
    case 't':
      if (util::strieq_l("backend-read-timeou", name, 19)) {
        return SHRPX_OPTID_BACKEND_READ_TIMEOUT;
      }
      if (util::strieq_l("stream-write-timeou", name, 19)) {
        return SHRPX_OPTID_STREAM_WRITE_TIMEOUT;
      }
      if (util::strieq_l("verify-client-cacer", name, 19)) {
        return SHRPX_OPTID_VERIFY_CLIENT_CACERT;
      }
      break;
    }
    break;
  case 21:
    switch (name[20]) {
    case 'd':
      if (util::strieq_l("backend-tls-sni-fiel", name, 20)) {
        return SHRPX_OPTID_BACKEND_TLS_SNI_FIELD;
      }
      break;
    case 'r':
      if (util::strieq_l("tls-ticket-key-ciphe", name, 20)) {
        return SHRPX_OPTID_TLS_TICKET_KEY_CIPHER;
      }
      break;
    case 't':
      if (util::strieq_l("backend-write-timeou", name, 20)) {
        return SHRPX_OPTID_BACKEND_WRITE_TIMEOUT;
      }
      if (util::strieq_l("frontend-read-timeou", name, 20)) {
        return SHRPX_OPTID_FRONTEND_READ_TIMEOUT;
      }
      break;
    }
    break;
  case 22:
    switch (name[21]) {
    case 'i':
      if (util::strieq_l("backend-http-proxy-ur", name, 21)) {
        return SHRPX_OPTID_BACKEND_HTTP_PROXY_URI;
      }
      break;
    case 'r':
      if (util::strieq_l("backend-request-buffe", name, 21)) {
        return SHRPX_OPTID_BACKEND_REQUEST_BUFFER;
      }
      break;
    case 't':
      if (util::strieq_l("frontend-write-timeou", name, 21)) {
        return SHRPX_OPTID_FRONTEND_WRITE_TIMEOUT;
      }
      break;
    }
    break;
  case 23:
    switch (name[22]) {
    case 'e':
      if (util::strieq_l("client-private-key-fil", name, 22)) {
        return SHRPX_OPTID_CLIENT_PRIVATE_KEY_FILE;
      }
      if (util::strieq_l("private-key-passwd-fil", name, 22)) {
        return SHRPX_OPTID_PRIVATE_KEY_PASSWD_FILE;
      }
      break;
    case 'r':
      if (util::strieq_l("backend-response-buffe", name, 22)) {
        return SHRPX_OPTID_BACKEND_RESPONSE_BUFFER;
      }
      break;
    }
    break;
  case 24:
    switch (name[23]) {
    case 'd':
      if (util::strieq_l("tls-ticket-key-memcache", name, 23)) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED;
      }
      break;
    case 'e':
      if (util::strieq_l("fetch-ocsp-response-fil", name, 23)) {
        return SHRPX_OPTID_FETCH_OCSP_RESPONSE_FILE;
      }
      break;
    case 't':
      if (util::strieq_l("listener-disable-timeou", name, 23)) {
        return SHRPX_OPTID_LISTENER_DISABLE_TIMEOUT;
      }
      break;
    }
    break;
  case 25:
    switch (name[24]) {
    case 'g':
      if (util::strieq_l("http2-no-cookie-crumblin", name, 24)) {
        return SHRPX_OPTID_HTTP2_NO_COOKIE_CRUMBLING;
      }
      break;
    case 's':
      if (util::strieq_l("backend-http2-window-bit", name, 24)) {
        return SHRPX_OPTID_BACKEND_HTTP2_WINDOW_BITS;
      }
      break;
    }
    break;
  case 26:
    switch (name[25]) {
    case 's':
      if (util::strieq_l("frontend-http2-window-bit", name, 25)) {
        return SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_BITS;
      }
      break;
    case 't':
      if (util::strieq_l("backend-keep-alive-timeou", name, 25)) {
        return SHRPX_OPTID_BACKEND_KEEP_ALIVE_TIMEOUT;
      }
      break;
    }
    break;
  case 27:
    switch (name[26]) {
    case 'd':
      if (util::strieq_l("tls-session-cache-memcache", name, 26)) {
        return SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED;
      }
      break;
    case 's':
      if (util::strieq_l("worker-frontend-connection", name, 26)) {
        return SHRPX_OPTID_WORKER_FRONTEND_CONNECTIONS;
      }
      break;
    case 't':
      if (util::strieq_l("frontend-http2-read-timeou", name, 26)) {
        return SHRPX_OPTID_FRONTEND_HTTP2_READ_TIMEOUT;
      }
      break;
    }
    break;
  case 28:
    switch (name[27]) {
    case 's':
      if (util::strieq_l("http2-max-concurrent-stream", name, 27)) {
        return SHRPX_OPTID_HTTP2_MAX_CONCURRENT_STREAMS;
      }
      break;
    }
    break;
  case 30:
    switch (name[29]) {
    case 'r':
      if (util::strieq_l("strip-incoming-x-forwarded-fo", name, 29)) {
        return SHRPX_OPTID_STRIP_INCOMING_X_FORWARDED_FOR;
      }
      break;
    }
    break;
  case 33:
    switch (name[32]) {
    case 'l':
      if (util::strieq_l("tls-ticket-key-memcached-interva", name, 32)) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_INTERVAL;
      }
      if (util::strieq_l("tls-ticket-key-memcached-max-fai", name, 32)) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_FAIL;
      }
      break;
    }
    break;
  case 34:
    switch (name[33]) {
    case 'r':
      if (util::strieq_l("frontend-http2-dump-request-heade", name, 33)) {
        return SHRPX_OPTID_FRONTEND_HTTP2_DUMP_REQUEST_HEADER;
      }
      break;
    case 't':
      if (util::strieq_l("backend-http1-connections-per-hos", name, 33)) {
        return SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_HOST;
      }
      break;
    case 'y':
      if (util::strieq_l("tls-ticket-key-memcached-max-retr", name, 33)) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_RETRY;
      }
      break;
    }
    break;
  case 35:
    switch (name[34]) {
    case 'r':
      if (util::strieq_l("frontend-http2-dump-response-heade", name, 34)) {
        return SHRPX_OPTID_FRONTEND_HTTP2_DUMP_RESPONSE_HEADER;
      }
      break;
    }
    break;
  case 36:
    switch (name[35]) {
    case 'r':
      if (util::strieq_l("backend-http2-connections-per-worke", name, 35)) {
        return SHRPX_OPTID_BACKEND_HTTP2_CONNECTIONS_PER_WORKER;
      }
      break;
    case 's':
      if (util::strieq_l("backend-http2-connection-window-bit", name, 35)) {
        return SHRPX_OPTID_BACKEND_HTTP2_CONNECTION_WINDOW_BITS;
      }
      break;
    }
    break;
  case 37:
    switch (name[36]) {
    case 's':
      if (util::strieq_l("frontend-http2-connection-window-bit", name, 36)) {
        return SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS;
      }
      break;
    }
    break;
  case 38:
    switch (name[37]) {
    case 'd':
      if (util::strieq_l("backend-http1-connections-per-fronten", name, 37)) {
        return SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_FRONTEND;
      }
      break;
    }
    break;
  }
  return -1;
}
} // namespace

int parse_config(const char *opt, const char *optarg,
                 std::set<std::string> &included_set) {
  char host[NI_MAXHOST];
  uint16_t port;

  auto optid = option_lookup_token(opt, strlen(opt));

  switch (optid) {
  case SHRPX_OPTID_BACKEND: {
    auto optarglen = strlen(optarg);
    const char *pat_delim = strchr(optarg, ';');
    if (!pat_delim) {
      pat_delim = optarg + optarglen;
    }
    DownstreamAddr addr;
    if (util::istartsWith(optarg, SHRPX_UNIX_PATH_PREFIX)) {
      auto path = optarg + str_size(SHRPX_UNIX_PATH_PREFIX);
      addr.host = strcopy(path, pat_delim);
      addr.host_unix = true;
    } else {
      if (split_host_port(host, sizeof(host), &port, optarg,
                          pat_delim - optarg) == -1) {
        return -1;
      }

      addr.host = strcopy(host);
      addr.port = port;
    }

    auto mapping = pat_delim < optarg + optarglen ? pat_delim + 1 : pat_delim;
    // We may introduce new parameter after additional ';', so don't
    // allow extra ';' in pattern for now.
    if (strchr(mapping, ';') != nullptr) {
      LOG(ERROR) << opt << ": ';' must not be used in pattern";
      return -1;
    }
    parse_mapping(addr, mapping);

    return 0;
  }
  case SHRPX_OPTID_FRONTEND: {
    if (util::istartsWith(optarg, SHRPX_UNIX_PATH_PREFIX)) {
      auto path = optarg + str_size(SHRPX_UNIX_PATH_PREFIX);
      mod_config()->host = strcopy(path);
      mod_config()->port = 0;
      mod_config()->host_unix = true;

      return 0;
    }

    if (split_host_port(host, sizeof(host), &port, optarg, strlen(optarg)) ==
        -1) {
      return -1;
    }

    mod_config()->host = strcopy(host);
    mod_config()->port = port;
    mod_config()->host_unix = false;

    return 0;
  }
  case SHRPX_OPTID_WORKERS:
    return parse_uint(&mod_config()->num_worker, opt, optarg);
  case SHRPX_OPTID_HTTP2_MAX_CONCURRENT_STREAMS:
    return parse_uint(&mod_config()->http2_max_concurrent_streams, opt, optarg);
  case SHRPX_OPTID_LOG_LEVEL:
    if (Log::set_severity_level_by_name(optarg) == -1) {
      LOG(ERROR) << opt << ": Invalid severity level: " << optarg;
      return -1;
    }

    return 0;
  case SHRPX_OPTID_DAEMON:
    mod_config()->daemon = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_HTTP2_PROXY:
    mod_config()->http2_proxy = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_HTTP2_BRIDGE:
    mod_config()->http2_bridge = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_CLIENT_PROXY:
    mod_config()->client_proxy = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_ADD_X_FORWARDED_FOR:
    mod_config()->add_x_forwarded_for = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_STRIP_INCOMING_X_FORWARDED_FOR:
    mod_config()->strip_incoming_x_forwarded_for = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_NO_VIA:
    mod_config()->no_via = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_FRONTEND_HTTP2_READ_TIMEOUT:
    return parse_duration(&mod_config()->http2_upstream_read_timeout, opt,
                          optarg);
  case SHRPX_OPTID_FRONTEND_READ_TIMEOUT:
    return parse_duration(&mod_config()->upstream_read_timeout, opt, optarg);
  case SHRPX_OPTID_FRONTEND_WRITE_TIMEOUT:
    return parse_duration(&mod_config()->upstream_write_timeout, opt, optarg);
  case SHRPX_OPTID_BACKEND_READ_TIMEOUT:
    return parse_duration(&mod_config()->downstream_read_timeout, opt, optarg);
  case SHRPX_OPTID_BACKEND_WRITE_TIMEOUT:
    return parse_duration(&mod_config()->downstream_write_timeout, opt, optarg);
  case SHRPX_OPTID_STREAM_READ_TIMEOUT:
    return parse_duration(&mod_config()->stream_read_timeout, opt, optarg);
  case SHRPX_OPTID_STREAM_WRITE_TIMEOUT:
    return parse_duration(&mod_config()->stream_write_timeout, opt, optarg);
  case SHRPX_OPTID_ACCESSLOG_FILE:
    mod_config()->accesslog_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_ACCESSLOG_SYSLOG:
    mod_config()->accesslog_syslog = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_ACCESSLOG_FORMAT:
    mod_config()->accesslog_format = parse_log_format(optarg);

    return 0;
  case SHRPX_OPTID_ERRORLOG_FILE:
    mod_config()->errorlog_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_ERRORLOG_SYSLOG:
    mod_config()->errorlog_syslog = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_BACKEND_KEEP_ALIVE_TIMEOUT:
    return parse_duration(&mod_config()->downstream_idle_read_timeout, opt,
                          optarg);
  case SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_BITS:
  case SHRPX_OPTID_BACKEND_HTTP2_WINDOW_BITS: {
    size_t *resp;

    if (optid == SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_BITS) {
      resp = &mod_config()->http2_upstream_window_bits;
    } else {
      resp = &mod_config()->http2_downstream_window_bits;
    }

    errno = 0;

    int n;

    if (parse_uint(&n, opt, optarg) != 0) {
      return -1;
    }

    if (n >= 31) {
      LOG(ERROR) << opt
                 << ": specify the integer in the range [0, 30], inclusive";
      return -1;
    }

    *resp = n;

    return 0;
  }
  case SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS:
  case SHRPX_OPTID_BACKEND_HTTP2_CONNECTION_WINDOW_BITS: {
    size_t *resp;

    if (optid == SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS) {
      resp = &mod_config()->http2_upstream_connection_window_bits;
    } else {
      resp = &mod_config()->http2_downstream_connection_window_bits;
    }

    errno = 0;

    int n;

    if (parse_uint(&n, opt, optarg) != 0) {
      return -1;
    }

    if (n < 16 || n >= 31) {
      LOG(ERROR) << opt
                 << ": specify the integer in the range [16, 30], inclusive";
      return -1;
    }

    *resp = n;

    return 0;
  }
  case SHRPX_OPTID_FRONTEND_NO_TLS:
    mod_config()->upstream_no_tls = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_BACKEND_NO_TLS:
    mod_config()->downstream_no_tls = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_BACKEND_TLS_SNI_FIELD:
    mod_config()->backend_tls_sni_name = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_PID_FILE:
    mod_config()->pid_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_USER: {
    auto pwd = getpwnam(optarg);
    if (!pwd) {
      LOG(ERROR) << opt << ": failed to get uid from " << optarg << ": "
                 << strerror(errno);
      return -1;
    }
    mod_config()->user = strcopy(pwd->pw_name);
    mod_config()->uid = pwd->pw_uid;
    mod_config()->gid = pwd->pw_gid;

    return 0;
  }
  case SHRPX_OPTID_PRIVATE_KEY_FILE:
    mod_config()->private_key_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_PRIVATE_KEY_PASSWD_FILE: {
    auto passwd = read_passwd_from_file(optarg);
    if (passwd.empty()) {
      LOG(ERROR) << opt << ": Couldn't read key file's passwd from " << optarg;
      return -1;
    }
    mod_config()->private_key_passwd = strcopy(passwd);

    return 0;
  }
  case SHRPX_OPTID_CERTIFICATE_FILE:
    mod_config()->cert_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_DH_PARAM_FILE:
    mod_config()->dh_param_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_SUBCERT: {
    // Private Key file and certificate file separated by ':'.
    const char *sp = strchr(optarg, ':');
    if (sp) {
      std::string keyfile(optarg, sp);
      // TODO Do we need private key for subcert?
      mod_config()->subcerts.emplace_back(keyfile, sp + 1);
    }

    return 0;
  }
  case SHRPX_OPTID_SYSLOG_FACILITY: {
    int facility = int_syslog_facility(optarg);
    if (facility == -1) {
      LOG(ERROR) << opt << ": Unknown syslog facility: " << optarg;
      return -1;
    }
    mod_config()->syslog_facility = facility;

    return 0;
  }
  case SHRPX_OPTID_BACKLOG: {
    int n;
    if (parse_int(&n, opt, optarg) != 0) {
      return -1;
    }

    if (n < -1) {
      LOG(ERROR) << opt << ": " << optarg << " is not allowed";

      return -1;
    }

    mod_config()->backlog = n;

    return 0;
  }
  case SHRPX_OPTID_CIPHERS:
    mod_config()->ciphers = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_CLIENT:
    mod_config()->client = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_INSECURE:
    mod_config()->insecure = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_CACERT:
    mod_config()->cacert = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_BACKEND_IPV4:
    mod_config()->backend_ipv4 = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_BACKEND_IPV6:
    mod_config()->backend_ipv6 = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_BACKEND_HTTP_PROXY_URI: {
    // parse URI and get hostname, port and optionally userinfo.
    http_parser_url u{};
    int rv = http_parser_parse_url(optarg, strlen(optarg), 0, &u);
    if (rv == 0) {
      std::string val;
      if (u.field_set & UF_USERINFO) {
        http2::copy_url_component(val, &u, UF_USERINFO, optarg);
        // Surprisingly, u.field_set & UF_USERINFO is nonzero even if
        // userinfo component is empty string.
        if (!val.empty()) {
          val = util::percentDecode(val.begin(), val.end());
          mod_config()->downstream_http_proxy_userinfo = strcopy(val);
        }
      }
      if (u.field_set & UF_HOST) {
        http2::copy_url_component(val, &u, UF_HOST, optarg);
        mod_config()->downstream_http_proxy_host = strcopy(val);
      } else {
        LOG(ERROR) << opt << ": no hostname specified";
        return -1;
      }
      if (u.field_set & UF_PORT) {
        mod_config()->downstream_http_proxy_port = u.port;
      } else {
        LOG(ERROR) << opt << ": no port specified";
        return -1;
      }
    } else {
      LOG(ERROR) << opt << ": parse error";
      return -1;
    }

    return 0;
  }
  case SHRPX_OPTID_READ_RATE:
    return parse_uint_with_unit(&mod_config()->read_rate, opt, optarg);
  case SHRPX_OPTID_READ_BURST:
    return parse_uint_with_unit(&mod_config()->read_burst, opt, optarg);
  case SHRPX_OPTID_WRITE_RATE:
    return parse_uint_with_unit(&mod_config()->write_rate, opt, optarg);
  case SHRPX_OPTID_WRITE_BURST:
    return parse_uint_with_unit(&mod_config()->write_burst, opt, optarg);
  case SHRPX_OPTID_WORKER_READ_RATE:
    LOG(WARN) << opt << ": not implemented yet";
    return parse_uint_with_unit(&mod_config()->worker_read_rate, opt, optarg);
  case SHRPX_OPTID_WORKER_READ_BURST:
    LOG(WARN) << opt << ": not implemented yet";
    return parse_uint_with_unit(&mod_config()->worker_read_burst, opt, optarg);
  case SHRPX_OPTID_WORKER_WRITE_RATE:
    LOG(WARN) << opt << ": not implemented yet";
    return parse_uint_with_unit(&mod_config()->worker_write_rate, opt, optarg);
  case SHRPX_OPTID_WORKER_WRITE_BURST:
    LOG(WARN) << opt << ": not implemented yet";
    return parse_uint_with_unit(&mod_config()->worker_write_burst, opt, optarg);
  case SHRPX_OPTID_NPN_LIST:
    mod_config()->npn_list = parse_config_str_list(optarg);

    return 0;
  case SHRPX_OPTID_TLS_PROTO_LIST:
    mod_config()->tls_proto_list = parse_config_str_list(optarg);

    return 0;
  case SHRPX_OPTID_VERIFY_CLIENT:
    mod_config()->verify_client = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_VERIFY_CLIENT_CACERT:
    mod_config()->verify_client_cacert = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_CLIENT_PRIVATE_KEY_FILE:
    mod_config()->client_private_key_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_CLIENT_CERT_FILE:
    mod_config()->client_cert_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_FRONTEND_HTTP2_DUMP_REQUEST_HEADER:
    mod_config()->http2_upstream_dump_request_header_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_FRONTEND_HTTP2_DUMP_RESPONSE_HEADER:
    mod_config()->http2_upstream_dump_response_header_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_HTTP2_NO_COOKIE_CRUMBLING:
    mod_config()->http2_no_cookie_crumbling = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_FRONTEND_FRAME_DEBUG:
    mod_config()->upstream_frame_debug = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_PADDING:
    return parse_uint(&mod_config()->padding, opt, optarg);
  case SHRPX_OPTID_ALTSVC: {
    auto tokens = parse_config_str_list(optarg);

    if (tokens.size() < 2) {
      // Requires at least protocol_id and port
      LOG(ERROR) << opt << ": too few parameters: " << optarg;
      return -1;
    }

    if (tokens.size() > 4) {
      // We only need protocol_id, port, host and origin
      LOG(ERROR) << opt << ": too many parameters: " << optarg;
      return -1;
    }

    int port;

    if (parse_uint(&port, opt, tokens[1].c_str()) != 0) {
      return -1;
    }

    if (port < 1 ||
        port > static_cast<int>(std::numeric_limits<uint16_t>::max())) {
      LOG(ERROR) << opt << ": port is invalid: " << tokens[1];
      return -1;
    }

    AltSvc altsvc;

    altsvc.protocol_id = std::move(tokens[0]);

    altsvc.port = port;
    altsvc.service = std::move(tokens[1]);

    if (tokens.size() > 2) {
      altsvc.host = std::move(tokens[2]);

      if (tokens.size() > 3) {
        altsvc.origin = std::move(tokens[3]);
      }
    }

    mod_config()->altsvcs.push_back(std::move(altsvc));

    return 0;
  }
  case SHRPX_OPTID_ADD_REQUEST_HEADER:
  case SHRPX_OPTID_ADD_RESPONSE_HEADER: {
    auto p = parse_header(optarg);
    if (p.first.empty()) {
      LOG(ERROR) << opt << ": header field name is empty: " << optarg;
      return -1;
    }
    if (optid == SHRPX_OPTID_ADD_REQUEST_HEADER) {
      mod_config()->add_request_headers.push_back(std::move(p));
    } else {
      mod_config()->add_response_headers.push_back(std::move(p));
    }
    return 0;
  }
  case SHRPX_OPTID_WORKER_FRONTEND_CONNECTIONS:
    return parse_uint(&mod_config()->worker_frontend_connections, opt, optarg);
  case SHRPX_OPTID_NO_LOCATION_REWRITE:
    mod_config()->no_location_rewrite = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_NO_HOST_REWRITE:
    LOG(WARN) << SHRPX_OPT_NO_HOST_REWRITE
              << ": deprecated.  :authority and host header fields are NOT "
                 "altered by default.  To rewrite these headers, use "
                 "--host-rewrite option.";

    return 0;
  case SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_HOST: {
    int n;

    if (parse_uint(&n, opt, optarg) != 0) {
      return -1;
    }

    if (n == 0) {
      LOG(ERROR) << opt << ": specify an integer strictly more than 0";

      return -1;
    }

    mod_config()->downstream_connections_per_host = n;

    return 0;
  }
  case SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_FRONTEND:
    return parse_uint(&mod_config()->downstream_connections_per_frontend, opt,
                      optarg);
  case SHRPX_OPTID_LISTENER_DISABLE_TIMEOUT:
    return parse_duration(&mod_config()->listener_disable_timeout, opt, optarg);
  case SHRPX_OPTID_TLS_TICKET_KEY_FILE:
    mod_config()->tls_ticket_key_files.push_back(optarg);
    return 0;
  case SHRPX_OPTID_RLIMIT_NOFILE: {
    int n;

    if (parse_uint(&n, opt, optarg) != 0) {
      return -1;
    }

    if (n < 0) {
      LOG(ERROR) << opt << ": specify the integer more than or equal to 0";

      return -1;
    }

    mod_config()->rlimit_nofile = n;

    return 0;
  }
  case SHRPX_OPTID_BACKEND_REQUEST_BUFFER:
  case SHRPX_OPTID_BACKEND_RESPONSE_BUFFER: {
    size_t n;
    if (parse_uint_with_unit(&n, opt, optarg) != 0) {
      return -1;
    }

    if (n == 0) {
      LOG(ERROR) << opt << ": specify an integer strictly more than 0";

      return -1;
    }

    if (optid == SHRPX_OPTID_BACKEND_REQUEST_BUFFER) {
      mod_config()->downstream_request_buffer_size = n;
    } else {
      mod_config()->downstream_response_buffer_size = n;
    }

    return 0;
  }

  case SHRPX_OPTID_NO_SERVER_PUSH:
    mod_config()->no_server_push = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_BACKEND_HTTP2_CONNECTIONS_PER_WORKER:
    return parse_uint(&mod_config()->http2_downstream_connections_per_worker,
                      opt, optarg);
  case SHRPX_OPTID_FETCH_OCSP_RESPONSE_FILE:
    mod_config()->fetch_ocsp_response_file = strcopy(optarg);

    return 0;
  case SHRPX_OPTID_OCSP_UPDATE_INTERVAL:
    return parse_duration(&mod_config()->ocsp_update_interval, opt, optarg);
  case SHRPX_OPTID_NO_OCSP:
    mod_config()->no_ocsp = util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_HEADER_FIELD_BUFFER:
    return parse_uint_with_unit(&mod_config()->header_field_buffer, opt,
                                optarg);
  case SHRPX_OPTID_MAX_HEADER_FIELDS:
    return parse_uint(&mod_config()->max_header_fields, opt, optarg);
  case SHRPX_OPTID_INCLUDE: {
    if (included_set.count(optarg)) {
      LOG(ERROR) << opt << ": " << optarg << " has already been included";
      return -1;
    }

    included_set.insert(optarg);
    auto rv = load_config(optarg, included_set);
    included_set.erase(optarg);

    if (rv != 0) {
      return -1;
    }

    return 0;
  }
  case SHRPX_OPTID_TLS_TICKET_KEY_CIPHER:
    if (util::strieq(optarg, "aes-128-cbc")) {
      mod_config()->tls_ticket_key_cipher = EVP_aes_128_cbc();
    } else if (util::strieq(optarg, "aes-256-cbc")) {
      mod_config()->tls_ticket_key_cipher = EVP_aes_256_cbc();
    } else {
      LOG(ERROR) << opt
                 << ": unsupported cipher for ticket encryption: " << optarg;
      return -1;
    }
    mod_config()->tls_ticket_key_cipher_given = true;

    return 0;
  case SHRPX_OPTID_HOST_REWRITE:
    mod_config()->no_host_rewrite = !util::strieq(optarg, "yes");

    return 0;
  case SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED: {
    if (split_host_port(host, sizeof(host), &port, optarg, strlen(optarg)) ==
        -1) {
      return -1;
    }

    mod_config()->session_cache_memcached_host = strcopy(host);
    mod_config()->session_cache_memcached_port = port;

    return 0;
  }
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED: {
    if (split_host_port(host, sizeof(host), &port, optarg, strlen(optarg)) ==
        -1) {
      return -1;
    }

    mod_config()->tls_ticket_key_memcached_host = strcopy(host);
    mod_config()->tls_ticket_key_memcached_port = port;

    return 0;
  }
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_INTERVAL:
    return parse_duration(&mod_config()->tls_ticket_key_memcached_interval, opt,
                          optarg);
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_RETRY: {
    int n;
    if (parse_uint(&n, opt, optarg) != 0) {
      return -1;
    }

    if (n > 30) {
      LOG(ERROR) << opt << ": must be smaller than or equal to 30";
      return -1;
    }

    mod_config()->tls_ticket_key_memcached_max_retry = n;
    return 0;
  }
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_FAIL:
    return parse_uint(&mod_config()->tls_ticket_key_memcached_max_fail, opt,
                      optarg);
  case SHRPX_OPTID_CONF:
    LOG(WARN) << "conf: ignored";

    return 0;
  }

  LOG(ERROR) << "Unknown option: " << opt;

  return -1;
}

int load_config(const char *filename, std::set<std::string> &include_set) {
  std::ifstream in(filename, std::ios::binary);
  if (!in) {
    LOG(ERROR) << "Could not open config file " << filename;
    return -1;
  }
  std::string line;
  int linenum = 0;
  while (std::getline(in, line)) {
    ++linenum;
    if (line.empty() || line[0] == '#') {
      continue;
    }
    size_t i;
    size_t size = line.size();
    for (i = 0; i < size && line[i] != '='; ++i)
      ;
    if (i == size) {
      LOG(ERROR) << "Bad configuration format in " << filename << " at line "
                 << linenum;
      return -1;
    }
    line[i] = '\0';
    auto s = line.c_str();
    if (parse_config(s, s + i + 1, include_set) == -1) {
      return -1;
    }
  }
  return 0;
}

const char *str_syslog_facility(int facility) {
  switch (facility) {
  case (LOG_AUTH):
    return "auth";
#ifdef LOG_AUTHPRIV
  case (LOG_AUTHPRIV):
    return "authpriv";
#endif // LOG_AUTHPRIV
  case (LOG_CRON):
    return "cron";
  case (LOG_DAEMON):
    return "daemon";
#ifdef LOG_FTP
  case (LOG_FTP):
    return "ftp";
#endif // LOG_FTP
  case (LOG_KERN):
    return "kern";
  case (LOG_LOCAL0):
    return "local0";
  case (LOG_LOCAL1):
    return "local1";
  case (LOG_LOCAL2):
    return "local2";
  case (LOG_LOCAL3):
    return "local3";
  case (LOG_LOCAL4):
    return "local4";
  case (LOG_LOCAL5):
    return "local5";
  case (LOG_LOCAL6):
    return "local6";
  case (LOG_LOCAL7):
    return "local7";
  case (LOG_LPR):
    return "lpr";
  case (LOG_MAIL):
    return "mail";
  case (LOG_SYSLOG):
    return "syslog";
  case (LOG_USER):
    return "user";
  case (LOG_UUCP):
    return "uucp";
  default:
    return "(unknown)";
  }
}

int int_syslog_facility(const char *strfacility) {
  if (util::strieq(strfacility, "auth")) {
    return LOG_AUTH;
  }

#ifdef LOG_AUTHPRIV
  if (util::strieq(strfacility, "authpriv")) {
    return LOG_AUTHPRIV;
  }
#endif // LOG_AUTHPRIV

  if (util::strieq(strfacility, "cron")) {
    return LOG_CRON;
  }

  if (util::strieq(strfacility, "daemon")) {
    return LOG_DAEMON;
  }

#ifdef LOG_FTP
  if (util::strieq(strfacility, "ftp")) {
    return LOG_FTP;
  }
#endif // LOG_FTP

  if (util::strieq(strfacility, "kern")) {
    return LOG_KERN;
  }

  if (util::strieq(strfacility, "local0")) {
    return LOG_LOCAL0;
  }

  if (util::strieq(strfacility, "local1")) {
    return LOG_LOCAL1;
  }

  if (util::strieq(strfacility, "local2")) {
    return LOG_LOCAL2;
  }

  if (util::strieq(strfacility, "local3")) {
    return LOG_LOCAL3;
  }

  if (util::strieq(strfacility, "local4")) {
    return LOG_LOCAL4;
  }

  if (util::strieq(strfacility, "local5")) {
    return LOG_LOCAL5;
  }

  if (util::strieq(strfacility, "local6")) {
    return LOG_LOCAL6;
  }

  if (util::strieq(strfacility, "local7")) {
    return LOG_LOCAL7;
  }

  if (util::strieq(strfacility, "lpr")) {
    return LOG_LPR;
  }

  if (util::strieq(strfacility, "mail")) {
    return LOG_MAIL;
  }

  if (util::strieq(strfacility, "news")) {
    return LOG_NEWS;
  }

  if (util::strieq(strfacility, "syslog")) {
    return LOG_SYSLOG;
  }

  if (util::strieq(strfacility, "user")) {
    return LOG_USER;
  }

  if (util::strieq(strfacility, "uucp")) {
    return LOG_UUCP;
  }

  return -1;
}

namespace {
template <typename InputIt>
bool path_match(const std::string &pattern, const std::string &host,
                InputIt path_first, InputIt path_last) {
  if (pattern.back() != '/') {
    return pattern.size() == host.size() + (path_last - path_first) &&
           std::equal(std::begin(host), std::end(host), std::begin(pattern)) &&
           std::equal(path_first, path_last, std::begin(pattern) + host.size());
  }

  if (pattern.size() >= host.size() &&
      std::equal(std::begin(host), std::end(host), std::begin(pattern)) &&
      util::startsWith(path_first, path_last, std::begin(pattern) + host.size(),
                       std::end(pattern))) {
    return true;
  }

  // If pattern ends with '/', and pattern and path matches without
  // that slash, we consider they match to deal with request to the
  // directory without trailing slash.  That is if pattern is "/foo/"
  // and path is "/foo", we consider they match.

  assert(!pattern.empty());
  return pattern.size() - 1 == host.size() + (path_last - path_first) &&
         std::equal(std::begin(host), std::end(host), std::begin(pattern)) &&
         std::equal(path_first, path_last, std::begin(pattern) + host.size());
}
} // namespace

namespace {
template <typename InputIt>
ssize_t match(const std::string &host, InputIt path_first, InputIt path_last,
              const std::vector<DownstreamAddrGroup> &groups) {
  ssize_t res = -1;
  size_t best = 0;
  for (size_t i = 0; i < groups.size(); ++i) {
    auto &g = groups[i];
    auto &pattern = g.pattern;
    if (!path_match(pattern, host, path_first, path_last)) {
      continue;
    }
    if (res == -1 || best < pattern.size()) {
      best = pattern.size();
      res = i;
    }
  }
  return res;
}
} // namespace

namespace {
template <typename InputIt>
size_t match_downstream_addr_group_host(
    const std::string &host, InputIt path_first, InputIt path_last,
    const std::vector<DownstreamAddrGroup> &groups, size_t catch_all) {
  if (path_first == path_last || *path_first != '/') {
    constexpr const char P[] = "/";
    auto group = match(host, P, P + 1, groups);
    if (group != -1) {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Found pattern with query " << host
                  << ", matched pattern=" << groups[group].pattern;
      }
      return group;
    }
    return catch_all;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Perform mapping selection, using host=" << host
              << ", path=" << std::string(path_first, path_last);
  }

  auto group = match(host, path_first, path_last, groups);
  if (group != -1) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Found pattern with query " << host
                << std::string(path_first, path_last)
                << ", matched pattern=" << groups[group].pattern;
    }
    return group;
  }

  group = match("", path_first, path_last, groups);
  if (group != -1) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Found pattern with query "
                << std::string(path_first, path_last)
                << ", matched pattern=" << groups[group].pattern;
    }
    return group;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "None match.  Use catch-all pattern";
  }
  return catch_all;
}
} // namespace

size_t match_downstream_addr_group(
    const std::string &hostport, const std::string &raw_path,
    const std::vector<DownstreamAddrGroup> &groups, size_t catch_all) {
  if (std::find(std::begin(hostport), std::end(hostport), '/') !=
      std::end(hostport)) {
    // We use '/' specially, and if '/' is included in host, it breaks
    // our code.  Select catch-all case.
    return catch_all;
  }

  auto fragment = std::find(std::begin(raw_path), std::end(raw_path), '#');
  auto query = std::find(std::begin(raw_path), fragment, '?');
  auto path_first = std::begin(raw_path);
  auto path_last = query;

  if (hostport.empty()) {
    return match_downstream_addr_group_host(hostport, path_first, path_last,
                                            groups, catch_all);
  }

  std::string host;
  if (hostport[0] == '[') {
    // assume this is IPv6 numeric address
    auto p = std::find(std::begin(hostport), std::end(hostport), ']');
    if (p == std::end(hostport)) {
      return catch_all;
    }
    if (p + 1 < std::end(hostport) && *(p + 1) != ':') {
      return catch_all;
    }
    host.assign(std::begin(hostport), p + 1);
  } else {
    auto p = std::find(std::begin(hostport), std::end(hostport), ':');
    if (p == std::begin(hostport)) {
      return catch_all;
    }
    host.assign(std::begin(hostport), p);
  }

  util::inp_strlower(host);
  return match_downstream_addr_group_host(host, path_first, path_last, groups,
                                          catch_all);
}

} // namespace shrpx
