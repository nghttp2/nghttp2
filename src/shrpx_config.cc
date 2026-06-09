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
#  include <pwd.h>
#endif // defined(HAVE_PWD_H)
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif // defined(HAVE_NETDB_H)
#ifdef HAVE_SYSLOG_H
#  include <syslog.h>
#endif // defined(HAVE_SYSLOG_H)
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif // defined(HAVE_FCNTL_H)
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif // defined(HAVE_UNISTD_H)
#include <dirent.h>

#include <cstring>
#include <cerrno>
#include <limits>
#include <fstream>
#include <unordered_map>

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/openssl/evp.h>
#else // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
#  include <openssl/evp.h>
#endif // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

#include <nghttp2/nghttp2.h>

#include "urlparse.h"

#include "shrpx_log.h"
#include "shrpx_tls.h"
#include "shrpx_http.h"
#ifdef HAVE_MRUBY
#  include "shrpx_mruby.h"
#endif // defined(HAVE_MRUBY)
#include "util.h"
#include "base64.h"
#include "ssl_compat.h"
#include "xsi_strerror.h"

#ifndef AI_NUMERICSERV
#  define AI_NUMERICSERV 0
#endif // !defined(AI_NUMERICSERV)

namespace shrpx {

namespace {
Config *config;
} // namespace

constexpr auto SHRPX_UNIX_PATH_PREFIX = "unix:"sv;

const Config *get_config() { return config; }

Config *mod_config() { return config; }

std::unique_ptr<Config> replace_config(std::unique_ptr<Config> another) {
  auto p = config;
  config = another.release();
  return std::unique_ptr<Config>(p);
}

void create_config() { config = new Config(); }

Config::~Config() {
  auto &upstreamconf = http2.upstream;

  nghttp2_option_del(upstreamconf.option);
  nghttp2_option_del(upstreamconf.alt_mode_option);
  nghttp2_session_callbacks_del(upstreamconf.callbacks);

  auto &downstreamconf = http2.downstream;

  nghttp2_option_del(downstreamconf.option);
  nghttp2_session_callbacks_del(downstreamconf.callbacks);

  auto &dumpconf = http2.upstream.debug.dump;

  if (dumpconf.request_header) {
    fclose(dumpconf.request_header);
  }

  if (dumpconf.response_header) {
    fclose(dumpconf.response_header);
  }

#if OPENSSL_4_0_0_API
  auto &tlsconf = tls;
  if (tlsconf.ech_store) {
    OSSL_ECHSTORE_free(tlsconf.ech_store);
  }
#endif // OPENSSL_4_0_0_API
}

TicketKeys::~TicketKeys() {
  /* Erase keys from memory */
  for (auto &key : keys) {
    memset(&key, 0, sizeof(key));
  }
}

struct HostPort {
  std::string_view host;
  uint16_t port;
};

namespace {
std::expected<HostPort, Error> split_host_port(BlockAllocator &balloc,
                                               std::string_view hostport,
                                               std::string_view opt) {
  // host and port in |hostport| is separated by single ','.
  auto sep = std::ranges::find(hostport, ',');
  if (sep == std::ranges::end(hostport)) {
    Log{ERROR} << opt << ": Invalid host, port: " << hostport;
    return std::unexpected{Error::INVALID_ARGUMENT};
  }
  auto len = as_unsigned(sep - std::ranges::begin(hostport));
  if (NI_MAXHOST < len + 1) {
    Log{ERROR} << opt << ": Hostname too long: " << hostport;
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  auto portstr = std::string_view{sep + 1, std::ranges::end(hostport)};
  auto d = util::parse_uint(portstr);
  if (!d || 1 > *d || *d > std::numeric_limits<uint16_t>::max()) {
    Log{ERROR} << opt << ": Port is invalid: " << portstr;
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  return HostPort{
    .host = make_string_ref(balloc, std::ranges::begin(hostport), sep),
    .port = static_cast<uint16_t>(*d),
  };
}
} // namespace

namespace {
bool is_secure(std::string_view filename) {
  struct stat buf;
  int rv = stat(filename.data(), &buf);
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
read_tls_ticket_key_file(const std::vector<std::string_view> &files,
                         const EVP_CIPHER *cipher, const EVP_MD *hmac) {
  auto ticket_keys = std::make_unique<TicketKeys>();
  auto &keys = ticket_keys->keys;
  keys.resize(files.size());
  auto enc_keylen = static_cast<size_t>(EVP_CIPHER_key_length(cipher));
  auto hmac_keylen = static_cast<size_t>(EVP_MD_size(hmac));
  if (cipher == nghttp2::tls::aes_128_cbc()) {
    // backward compatibility, as a legacy of using same file format
    // with nginx and apache.
    hmac_keylen = 16;
  }
  auto expectedlen = keys[0].data.name.size() + enc_keylen + hmac_keylen;
  std::array<char, 256> buf;
  assert(buf.size() >= expectedlen);

  size_t i = 0;
  for (auto &file : files) {
    struct stat fst{};

    if (stat(file.data(), &fst) == -1) {
      auto error = errno;
      Log{ERROR} << "tls-ticket-key-file: could not stat file " << file
                 << ", errno=" << error;
      return nullptr;
    }

    if (static_cast<size_t>(fst.st_size) != expectedlen) {
      Log{ERROR} << "tls-ticket-key-file: the expected file size is "
                 << expectedlen << ", the actual file size is " << fst.st_size;
      return nullptr;
    }

    std::ifstream f(file.data());
    if (!f) {
      Log{ERROR} << "tls-ticket-key-file: could not open file " << file;
      return nullptr;
    }

    f.read(buf.data(), static_cast<std::streamsize>(expectedlen));
    if (static_cast<size_t>(f.gcount()) != expectedlen) {
      Log{ERROR} << "tls-ticket-key-file: want to read " << expectedlen
                 << " bytes but only read " << f.gcount() << " bytes from "
                 << file;
      return nullptr;
    }

    auto &key = keys[i++];
    key.cipher = cipher;
    key.hmac = hmac;
    key.hmac_keylen = hmac_keylen;

    if (log_enabled(INFO)) {
      Log{INFO} << "enc_keylen=" << enc_keylen
                << ", hmac_keylen=" << key.hmac_keylen;
    }

    auto p = std::ranges::begin(buf);
    p = std::ranges::copy_n(p, as_signed(key.data.name.size()),
                            std::ranges::begin(key.data.name))
          .in;
    p = std::ranges::copy_n(p, as_signed(enc_keylen),
                            std::ranges::begin(key.data.enc_key))
          .in;
    std::ranges::copy_n(p, as_signed(hmac_keylen),
                        std::ranges::begin(key.data.hmac_key));

    if (log_enabled(INFO)) {
      Log{INFO} << "session ticket key: " << util::format_hex(key.data.name);
    }
  }
  return ticket_keys;
}

#ifdef ENABLE_HTTP3
std::expected<std::unique_ptr<QUICKeyingMaterials>, Error>
read_quic_secret_file(std::string_view path) {
  constexpr size_t expectedlen =
    SHRPX_QUIC_SECRET_RESERVEDLEN + SHRPX_QUIC_SECRETLEN + SHRPX_QUIC_SALTLEN;

  std::ifstream f(path.data());
  if (!f) {
    Log{ERROR} << "frontend-quic-secret-file: could not open file " << path;
    return std::unexpected{Error::IO};
  }

  auto qkms = std::make_unique<QUICKeyingMaterials>();
  auto &kms = qkms->keying_materials;

  std::string line;

  while (std::getline(f, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }

    auto s = std::string_view{line};

    if (s.size() != expectedlen * 2 || !util::is_hex_string(s)) {
      Log{ERROR} << "frontend-quic-secret-file: each line must be a "
                 << expectedlen * 2 << " bytes hex encoded string";
      return std::unexpected{Error::INVALID_CONFIG};
    }

    kms.emplace_back();
    auto &qkm = kms.back();

    auto p = std::ranges::begin(s);

    util::decode_hex(p, p + qkm.reserved.size(),
                     std::ranges::begin(qkm.reserved));
    p += qkm.reserved.size() * 2;
    util::decode_hex(p, p + qkm.secret.size(), std::ranges::begin(qkm.secret));
    p += qkm.secret.size() * 2;
    util::decode_hex(p, p + qkm.salt.size(), std::ranges::begin(qkm.salt));
    p += qkm.salt.size() * 2;

    assert(static_cast<size_t>(p - std::ranges::begin(s)) == expectedlen * 2);

    qkm.id = qkm.reserved[0] & SHRPX_QUIC_DCID_KM_ID_MASK;

    if (kms.size() == 8) {
      break;
    }
  }

  if (util::stream_error(f)) {
    Log{ERROR}
      << "frontend-quic-secret-file: error occurred while reading file "
      << path;
    return std::unexpected{Error::IO};
  }

  if (kms.empty()) {
    Log{WARN}
      << "frontend-quic-secret-file: no keying materials are present in file "
      << path;
    return std::unexpected{Error::INVALID_CONFIG};
  }

  return qkms;
}
#endif // defined(ENABLE_HTTP3)

std::expected<FILE *, Error> open_file_for_write(const char *filename) {
  std::array<char, STRERROR_BUFSIZE> errbuf;

#ifdef O_CLOEXEC
  auto fd =
    open(filename, O_WRONLY | O_CLOEXEC | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
#else  // !defined(O_CLOEXEC)
  auto fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

  // We get race condition if execve is called at the same time.
  if (fd != -1) {
    util::make_socket_closeonexec(fd);
  }
#endif // !defined(O_CLOEXEC)
  if (fd == -1) {
    auto error = errno;
    Log{ERROR} << "Failed to open " << filename << " for writing. Cause: "
               << xsi_strerror(error, errbuf.data(), errbuf.size());
    return std::unexpected{Error::SYSCALL};
  }
  auto f = fdopen(fd, "wb");
  if (f == nullptr) {
    auto error = errno;
    Log{ERROR} << "Failed to open " << filename << " for writing. Cause: "
               << xsi_strerror(error, errbuf.data(), errbuf.size());
    return std::unexpected{Error::LIBC};
  }

  return f;
}

namespace {
// Read passwd from |filename|
std::expected<std::string, Error>
read_passwd_from_file(std::string_view opt, std::string_view filename) {
  if (!is_secure(filename)) {
    Log{ERROR} << opt << ": Private key passwd file " << filename
               << " has insecure mode.";
    return std::unexpected{Error::IO};
  }

  std::ifstream in(filename.data(), std::ios::binary);
  if (!in) {
    Log{ERROR} << opt << ": Could not open key passwd file " << filename;
    return std::unexpected{Error::IO};
  }

  std::string line;

  std::getline(in, line);
  return line;
}
} // namespace

std::expected<HeaderRef, Error> parse_header(BlockAllocator &balloc,
                                             std::string_view optarg) {
  auto colon = std::ranges::find(optarg, ':');

  if (colon == std::ranges::end(optarg) ||
      colon == std::ranges::begin(optarg)) {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  auto value = colon + 1;
  for (; *value == '\t' || *value == ' '; ++value)
    ;

  auto name_iov = make_byte_ref(
    balloc,
    as_unsigned(std::ranges::distance(std::ranges::begin(optarg), colon) + 1));
  auto p = util::tolower(std::ranges::begin(optarg), colon,
                         std::ranges::begin(name_iov));
  *p = '\0';

  auto nv = HeaderRef(
    as_string_view(std::ranges::begin(name_iov), p),
    make_string_ref(balloc, std::string_view{value, std::ranges::end(optarg)}));

  if (!nghttp2_check_header_name(
        reinterpret_cast<const uint8_t *>(nv.name.data()), nv.name.size()) ||
      !nghttp2_check_header_value_rfc9113(
        reinterpret_cast<const uint8_t *>(nv.value.data()), nv.value.size())) {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  return nv;
}

template <typename T>
std::expected<T, Error> parse_uint(std::string_view opt,
                                   std::string_view optarg) {
  auto maybe_n = util::parse_uint(optarg);
  if (!maybe_n) {
    Log{ERROR} << opt << ": bad value.  Specify an integer >= 0.";
    return std::unexpected{maybe_n.error()};
  }

  auto n = *maybe_n;

  if constexpr (!std::is_same_v<T, uint64_t>) {
    if (static_cast<uint64_t>(std::numeric_limits<T>::max()) < n) {
      Log{ERROR} << opt
                 << ": too large.  The value should be less than or equal to "
                 << std::numeric_limits<T>::max();
      return std::unexpected{Error::INVALID_ARGUMENT};
    }
  }

  return static_cast<T>(n);
}

namespace {
template <typename T>
std::expected<T, Error> parse_uint_with_unit(std::string_view opt,
                                             std::string_view optarg) {
  auto maybe_n = util::parse_uint_with_unit(optarg);
  if (!maybe_n) {
    Log{ERROR} << opt << ": bad value: '" << optarg << "'";
    return std::unexpected{maybe_n.error()};
  }

  auto n = *maybe_n;

  if constexpr (!std::is_same_v<T, uint64_t>) {
    if (static_cast<uint64_t>(std::numeric_limits<T>::max()) < n) {
      Log{ERROR} << opt
                 << ": too large.  The value should be less than or equal to "
                 << std::numeric_limits<T>::max();
      return std::unexpected{Error::INVALID_ARGUMENT};
    }
  }

  return static_cast<T>(n);
}
} // namespace

namespace {
std::expected<AltSvc, Error> parse_altsvc(std::string_view opt,
                                          std::string_view optarg) {
  // PROTOID, PORT, HOST, ORIGIN, PARAMS.
  auto tokens = util::split_str(optarg, ',', 5);

  if (tokens.size() < 2) {
    // Requires at least protocol_id and port
    Log{ERROR} << opt << ": too few parameters: " << optarg;
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  auto maybe_port = parse_uint<uint16_t>(opt, tokens[1]);
  if (!maybe_port) {
    return std::unexpected{maybe_port.error()};
  }

  auto port = *maybe_port;
  if (port == 0) {
    Log{ERROR} << opt << ": port is invalid: " << tokens[1];
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  AltSvc altsvc{
    .protocol_id = make_string_ref(config->balloc, tokens[0]),
    .service = make_string_ref(config->balloc, tokens[1]),
    .port = port,
  };

  if (tokens.size() > 2) {
    if (!tokens[2].empty()) {
      altsvc.host = make_string_ref(config->balloc, tokens[2]);
    }

    if (tokens.size() > 3) {
      if (!tokens[3].empty()) {
        altsvc.origin = make_string_ref(config->balloc, tokens[3]);
      }

      if (tokens.size() > 4) {
        if (!tokens[4].empty()) {
          altsvc.params = make_string_ref(config->balloc, tokens[4]);
        }
      }
    }
  }

  return altsvc;
}
} // namespace

namespace {
// generated by gennghttpxfun.py
LogFragmentType log_var_lookup_token(std::string_view name) {
  switch (name.size()) {
  case 3:
    switch (name[2]) {
    case 'd':
      if (util::strieq("pi"sv, name.substr(0, 2))) {
        return LogFragmentType::PID;
      }
      break;
    }
    break;
  case 4:
    switch (name[3]) {
    case 'h':
      if (util::strieq("pat"sv, name.substr(0, 3))) {
        return LogFragmentType::PATH;
      }
      break;
    case 'n':
      if (util::strieq("alp"sv, name.substr(0, 3))) {
        return LogFragmentType::ALPN;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'd':
      if (util::strieq("metho"sv, name.substr(0, 5))) {
        return LogFragmentType::METHOD;
      }
      break;
    case 's':
      if (util::strieq("statu"sv, name.substr(0, 5))) {
        return LogFragmentType::STATUS;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'i':
      if (util::strieq("tls_sn"sv, name.substr(0, 6))) {
        return LogFragmentType::TLS_SNI;
      }
      break;
    case 't':
      if (util::strieq("reques"sv, name.substr(0, 6))) {
        return LogFragmentType::REQUEST;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'l':
      if (util::strieq("time_loca"sv, name.substr(0, 9))) {
        return LogFragmentType::TIME_LOCAL;
      }
      break;
    case 'r':
      if (util::strieq("ssl_ciphe"sv, name.substr(0, 9))) {
        return LogFragmentType::SSL_CIPHER;
      }
      if (util::strieq("tls_ciphe"sv, name.substr(0, 9))) {
        return LogFragmentType::TLS_CIPHER;
      }
      break;
    }
    break;
  case 11:
    switch (name[10]) {
    case 'r':
      if (util::strieq("remote_add"sv, name.substr(0, 10))) {
        return LogFragmentType::REMOTE_ADDR;
      }
      break;
    case 't':
      if (util::strieq("remote_por"sv, name.substr(0, 10))) {
        return LogFragmentType::REMOTE_PORT;
      }
      if (util::strieq("server_por"sv, name.substr(0, 10))) {
        return LogFragmentType::SERVER_PORT;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case '1':
      if (util::strieq("time_iso860"sv, name.substr(0, 11))) {
        return LogFragmentType::TIME_ISO8601;
      }
      break;
    case 'e':
      if (util::strieq("request_tim"sv, name.substr(0, 11))) {
        return LogFragmentType::REQUEST_TIME;
      }
      break;
    case 'l':
      if (util::strieq("ssl_protoco"sv, name.substr(0, 11))) {
        return LogFragmentType::SSL_PROTOCOL;
      }
      if (util::strieq("tls_protoco"sv, name.substr(0, 11))) {
        return LogFragmentType::TLS_PROTOCOL;
      }
      break;
    case 't':
      if (util::strieq("backend_hos"sv, name.substr(0, 11))) {
        return LogFragmentType::BACKEND_HOST;
      }
      if (util::strieq("backend_por"sv, name.substr(0, 11))) {
        return LogFragmentType::BACKEND_PORT;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'd':
      if (util::strieq("ssl_session_i"sv, name.substr(0, 13))) {
        return LogFragmentType::SSL_SESSION_ID;
      }
      if (util::strieq("tls_session_i"sv, name.substr(0, 13))) {
        return LogFragmentType::TLS_SESSION_ID;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 't':
      if (util::strieq("body_bytes_sen"sv, name.substr(0, 14))) {
        return LogFragmentType::BODY_BYTES_SENT;
      }
      break;
    }
    break;
  case 16:
    switch (name[15]) {
    case 'd':
      if (util::strieq("tls_ech_accepte"sv, name.substr(0, 15))) {
        return LogFragmentType::TLS_ECH_ACCEPTED;
      }
      break;
    case 'n':
      if (util::strieq("protocol_versio"sv, name.substr(0, 15))) {
        return LogFragmentType::PROTOCOL_VERSION;
      }
      break;
    }
    break;
  case 17:
    switch (name[16]) {
    case 'l':
      if (util::strieq("tls_client_seria"sv, name.substr(0, 16))) {
        return LogFragmentType::TLS_CLIENT_SERIAL;
      }
      break;
    }
    break;
  case 18:
    switch (name[17]) {
    case 'd':
      if (util::strieq("ssl_session_reuse"sv, name.substr(0, 17))) {
        return LogFragmentType::SSL_SESSION_REUSED;
      }
      if (util::strieq("tls_session_reuse"sv, name.substr(0, 17))) {
        return LogFragmentType::TLS_SESSION_REUSED;
      }
      break;
    case 'y':
      if (util::strieq("path_without_quer"sv, name.substr(0, 17))) {
        return LogFragmentType::PATH_WITHOUT_QUERY;
      }
      break;
    }
    break;
  case 22:
    switch (name[21]) {
    case 'e':
      if (util::strieq("tls_client_issuer_nam"sv, name.substr(0, 21))) {
        return LogFragmentType::TLS_CLIENT_ISSUER_NAME;
      }
      break;
    }
    break;
  case 23:
    switch (name[22]) {
    case 'e':
      if (util::strieq("tls_client_subject_nam"sv, name.substr(0, 22))) {
        return LogFragmentType::TLS_CLIENT_SUBJECT_NAME;
      }
      break;
    }
    break;
  case 27:
    switch (name[26]) {
    case '1':
      if (util::strieq("tls_client_fingerprint_sha"sv, name.substr(0, 26))) {
        return LogFragmentType::TLS_CLIENT_FINGERPRINT_SHA1;
      }
      break;
    }
    break;
  case 29:
    switch (name[28]) {
    case '6':
      if (util::strieq("tls_client_fingerprint_sha25"sv, name.substr(0, 28))) {
        return LogFragmentType::TLS_CLIENT_FINGERPRINT_SHA256;
      }
      break;
    }
    break;
  }
  return LogFragmentType::NONE;
}
} // namespace

namespace {
bool var_token(char c) {
  return util::is_alpha(c) || util::is_digit(c) || c == '_';
}
} // namespace

std::vector<LogFragment> parse_log_format(BlockAllocator &balloc,
                                          std::string_view optarg) {
  auto literal_start = std::ranges::begin(optarg);
  auto p = literal_start;
  auto eop = std::ranges::end(optarg);

  auto res = std::vector<LogFragment>();

  for (; p != eop;) {
    if (*p != '$') {
      ++p;
      continue;
    }

    auto var_start = p;

    ++p;

    std::string_view var_name;
    if (p != eop && *p == '{') {
      auto var_name_start = ++p;
      for (; p != eop && var_token(*p); ++p)
        ;

      if (p == eop || *p != '}') {
        Log{WARN} << "Missing '}' after " << std::string_view{var_start, p};
        continue;
      }

      var_name = std::string_view{var_name_start, p};
      ++p;
    } else {
      auto var_name_start = p;
      for (; p != eop && var_token(*p); ++p)
        ;

      var_name = std::string_view{var_name_start, p};
    }

    auto value = std::ranges::begin(var_name);

    auto type = log_var_lookup_token(var_name);

    if (type == LogFragmentType::NONE) {
      if (util::istarts_with(var_name, "http_"sv)) {
        if ("host"sv == var_name.substr(str_size("http_"))) {
          // Special handling of host header field.  We will use
          // :authority header field if host header is missing.  This
          // is a typical case in HTTP/2.
          type = LogFragmentType::AUTHORITY;
        } else {
          type = LogFragmentType::HTTP;
          value += str_size("http_");
        }
      } else {
        Log{WARN} << "Unrecognized log format variable: " << var_name;
        continue;
      }
    }

    if (literal_start < var_start) {
      res.emplace_back(
        LogFragmentType::LITERAL,
        make_string_ref(balloc, std::string_view{literal_start, var_start}));
    }

    literal_start = p;

    if (value == std::ranges::begin(var_name)) {
      res.emplace_back(type);
      continue;
    }

    {
      auto iov = make_byte_ref(
        balloc,
        as_unsigned(std::ranges::distance(value, std::ranges::end(var_name)) +
                    1));
      auto p = std::ranges::transform(value, std::ranges::end(var_name),
                                      std::ranges::begin(iov),
                                      [](auto c) { return c == '_' ? '-' : c; })
                 .out;
      *p = '\0';
      res.emplace_back(type, as_string_view(std::ranges::begin(iov), p));
    }
  }

  if (literal_start != eop) {
    res.emplace_back(
      LogFragmentType::LITERAL,
      make_string_ref(balloc, std::string_view{literal_start, eop}));
  }

  return res;
}

namespace {
std::expected<int, Error> parse_address_family(std::string_view opt,
                                               std::string_view optarg) {
  if (util::strieq("auto"sv, optarg)) {
    return AF_UNSPEC;
  }
  if (util::strieq("IPv4"sv, optarg)) {
    return AF_INET;
  }
  if (util::strieq("IPv6"sv, optarg)) {
    return AF_INET6;
  }

  Log{ERROR} << opt << ": bad value: '" << optarg << "'";
  return std::unexpected{Error::INVALID_ARGUMENT};
}
} // namespace

namespace {
std::expected<ev_tstamp, Error> parse_duration(std::string_view opt,
                                               std::string_view optarg) {
  return util::parse_duration_with_unit(optarg).transform_error(
    [opt, optarg](auto &&err) {
      Log{ERROR} << opt << ": bad value: '" << optarg << "'";

      return err;
    });
}
} // namespace

namespace {
std::expected<int, Error> parse_tls_proto_version(std::string_view opt,
                                                  std::string_view optarg) {
  return tls::proto_version_from_string(optarg).transform_error(
    [opt, optarg](auto &&err) {
      Log{ERROR} << opt << ": invalid TLS protocol version: " << optarg;

      return err;
    });
}
} // namespace

struct MemcachedConnectionParams {
  bool tls{};
};

namespace {
// Parses memcached connection configuration parameter |src_params|,
// and returns the result.
std::expected<MemcachedConnectionParams, Error>
parse_memcached_connection_params(std::string_view src_params,
                                  std::string_view opt) {
  MemcachedConnectionParams out;

  auto last = std::ranges::end(src_params);
  for (auto first = std::ranges::begin(src_params); first != last;) {
    auto end = std::ranges::find(first, last, ';');
    auto param = std::string_view{first, end};

    if (util::strieq("tls"sv, param)) {
      out.tls = true;
    } else if (util::strieq("no-tls"sv, param)) {
      out.tls = false;
    } else if (!param.empty()) {
      Log{ERROR} << opt << ": " << param << ": unknown keyword";
      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    if (end == last) {
      break;
    }

    first = end + 1;
  }

  return out;
}
} // namespace

struct UpstreamParams {
  UpstreamAltMode alt_mode{};
  bool tls{true};
  bool sni_fwd{};
  bool proxyproto{};
  bool quic{};
};

namespace {
// Parses upstream configuration parameter |src_params|, and returns
// the result.
std::expected<UpstreamParams, Error>
parse_upstream_params(std::string_view src_params) {
  UpstreamParams out;

  auto last = std::ranges::end(src_params);
  for (auto first = std::ranges::begin(src_params); first != last;) {
    auto end = std::ranges::find(first, last, ';');
    auto param = std::string_view{first, end};

    if (util::strieq("tls"sv, param)) {
      out.tls = true;
    } else if (util::strieq("sni-fwd"sv, param)) {
      out.sni_fwd = true;
    } else if (util::strieq("no-tls"sv, param)) {
      out.tls = false;
    } else if (util::strieq("api"sv, param)) {
      if (out.alt_mode != UpstreamAltMode::NONE &&
          out.alt_mode != UpstreamAltMode::API) {
        Log{ERROR} << "frontend: api and healthmon are mutually exclusive";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
      out.alt_mode = UpstreamAltMode::API;
    } else if (util::strieq("healthmon"sv, param)) {
      if (out.alt_mode != UpstreamAltMode::NONE &&
          out.alt_mode != UpstreamAltMode::HEALTHMON) {
        Log{ERROR} << "frontend: api and healthmon are mutually exclusive";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
      out.alt_mode = UpstreamAltMode::HEALTHMON;
    } else if (util::strieq("proxyproto"sv, param)) {
      out.proxyproto = true;
    } else if (util::strieq("quic"sv, param)) {
#ifdef ENABLE_HTTP3
      out.quic = true;
#else  // !defined(ENABLE_HTTP3)
      Log{ERROR} << "quic: QUIC is disabled at compile time";
      return std::unexpected{Error::INVALID_ARGUMENT};
#endif // !defined(ENABLE_HTTP3)
    } else if (!param.empty()) {
      Log{ERROR} << "frontend: " << param << ": unknown keyword";
      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    if (end == last) {
      break;
    }

    first = end + 1;
  }

  return out;
}
} // namespace

struct DownstreamParams {
  std::string_view sni;
  std::string_view mruby;
  std::string_view group;
  AffinityConfig affinity{};
  ev_tstamp read_timeout{};
  ev_tstamp write_timeout{};
  size_t fall{};
  size_t rise{};
  uint32_t weight{1};
  uint32_t group_weight{};
  Proto proto{Proto::HTTP1};
  bool tls{};
  bool dns{};
  bool redirect_if_not_tls{};
  bool upgrade_scheme{};
  bool dnf{};
};

namespace {
// Parses |value| of parameter named |name| as duration, and returns
// the result.
std::expected<ev_tstamp, Error>
parse_downstream_param_duration(std::string_view name, std::string_view value) {
  return util::parse_duration_with_unit(value).transform_error(
    [name, value](auto &&err) {
      Log{ERROR} << "backend: " << name << ": bad value: '" << value << "'";

      return err;
    });
}
} // namespace

namespace {
// Parses downstream configuration parameter |src_params|, and returns
// the result.
std::expected<DownstreamParams, Error>
parse_downstream_params(std::string_view src_params) {
  DownstreamParams out;

  auto last = std::ranges::end(src_params);
  for (auto first = std::ranges::begin(src_params); first != last;) {
    auto end = std::ranges::find(first, last, ';');
    auto param = std::string_view{first, end};

    if (util::istarts_with(param, "proto="sv)) {
      auto protostr = std::string_view{first + str_size("proto="), end};
      if (protostr.empty()) {
        Log{ERROR} << "backend: proto: protocol is empty";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }

      if ("h2"sv == protostr) {
        out.proto = Proto::HTTP2;
      } else if ("http/1.1"sv == protostr) {
        out.proto = Proto::HTTP1;
      } else {
        Log{ERROR} << "backend: proto: unknown protocol " << protostr;
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
    } else if (util::istarts_with(param, "fall="sv)) {
      auto valstr = std::string_view{first + str_size("fall="), end};
      if (valstr.empty()) {
        Log{ERROR} << "backend: fall: non-negative integer is expected";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }

      auto maybe_fall = util::parse_uint(valstr);
      if (!maybe_fall) {
        Log{ERROR} << "backend: fall: non-negative integer is expected";
        return std::unexpected{maybe_fall.error()};
      }

      out.fall = static_cast<size_t>(*maybe_fall);
    } else if (util::istarts_with(param, "rise="sv)) {
      auto valstr = std::string_view{first + str_size("rise="), end};
      if (valstr.empty()) {
        Log{ERROR} << "backend: rise: non-negative integer is expected";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }

      auto maybe_rise = util::parse_uint(valstr);
      if (!maybe_rise) {
        Log{ERROR} << "backend: rise: non-negative integer is expected";
        return std::unexpected{maybe_rise.error()};
      }

      out.rise = static_cast<size_t>(*maybe_rise);
    } else if (util::strieq("tls"sv, param)) {
      out.tls = true;
    } else if (util::strieq("no-tls"sv, param)) {
      out.tls = false;
    } else if (util::istarts_with(param, "sni="sv)) {
      out.sni = std::string_view{first + str_size("sni="), end};
    } else if (util::istarts_with(param, "affinity="sv)) {
      auto valstr = std::string_view{first + str_size("affinity="), end};
      if (util::strieq("none"sv, valstr)) {
        out.affinity.type = SessionAffinity::NONE;
      } else if (util::strieq("ip"sv, valstr)) {
        out.affinity.type = SessionAffinity::IP;
      } else if (util::strieq("cookie"sv, valstr)) {
        out.affinity.type = SessionAffinity::COOKIE;
      } else {
        Log{ERROR}
          << "backend: affinity: value must be one of none, ip, and cookie";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
    } else if (util::istarts_with(param, "affinity-cookie-name="sv)) {
      auto val =
        std::string_view{first + str_size("affinity-cookie-name="), end};
      if (val.empty()) {
        Log{ERROR}
          << "backend: affinity-cookie-name: non empty string is expected";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
      out.affinity.cookie.name = val;
    } else if (util::istarts_with(param, "affinity-cookie-path="sv)) {
      out.affinity.cookie.path =
        std::string_view{first + str_size("affinity-cookie-path="), end};
    } else if (util::istarts_with(param, "affinity-cookie-secure="sv)) {
      auto valstr =
        std::string_view{first + str_size("affinity-cookie-secure="), end};
      if (util::strieq("auto"sv, valstr)) {
        out.affinity.cookie.secure = SessionAffinityCookieSecure::AUTO;
      } else if (util::strieq("yes"sv, valstr)) {
        out.affinity.cookie.secure = SessionAffinityCookieSecure::YES;
      } else if (util::strieq("no"sv, valstr)) {
        out.affinity.cookie.secure = SessionAffinityCookieSecure::NO;
      } else {
        Log{ERROR} << "backend: affinity-cookie-secure: value must be one of "
                      "auto, yes, and no";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
    } else if (util::istarts_with(param, "affinity-cookie-stickiness="sv)) {
      auto valstr =
        std::string_view{first + str_size("affinity-cookie-stickiness="), end};
      if (util::strieq("loose"sv, valstr)) {
        out.affinity.cookie.stickiness = SessionAffinityCookieStickiness::LOOSE;
      } else if (util::strieq("strict"sv, valstr)) {
        out.affinity.cookie.stickiness =
          SessionAffinityCookieStickiness::STRICT;
      } else {
        Log{ERROR} << "backend: affinity-cookie-stickiness: value must be "
                      "either loose or strict";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
    } else if (util::strieq("dns"sv, param)) {
      out.dns = true;
    } else if (util::strieq("redirect-if-not-tls"sv, param)) {
      out.redirect_if_not_tls = true;
    } else if (util::strieq("upgrade-scheme"sv, param)) {
      out.upgrade_scheme = true;
    } else if (util::istarts_with(param, "mruby="sv)) {
      auto valstr = std::string_view{first + str_size("mruby="), end};
      out.mruby = valstr;
    } else if (util::istarts_with(param, "read-timeout="sv)) {
      auto maybe_timeout = parse_downstream_param_duration(
        "read-timeout"sv,
        std::string_view{first + str_size("read-timeout="), end});
      if (!maybe_timeout) {
        return std::unexpected{maybe_timeout.error()};
      }

      out.read_timeout = *maybe_timeout;
    } else if (util::istarts_with(param, "write-timeout="sv)) {
      auto maybe_timeout = parse_downstream_param_duration(
        "write-timeout"sv,
        std::string_view{first + str_size("write-timeout="), end});
      if (!maybe_timeout) {
        return std::unexpected{maybe_timeout.error()};
      }

      out.write_timeout = *maybe_timeout;
    } else if (util::istarts_with(param, "weight="sv)) {
      auto valstr = std::string_view{first + str_size("weight="), end};
      if (valstr.empty()) {
        Log{ERROR}
          << "backend: weight: non-negative integer [1, 256] is expected";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }

      auto n = util::parse_uint(valstr);
      if (!n || (*n < 1 || *n > 256)) {
        Log{ERROR}
          << "backend: weight: non-negative integer [1, 256] is expected";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
      out.weight = static_cast<uint32_t>(*n);
    } else if (util::istarts_with(param, "group="sv)) {
      auto valstr = std::string_view{first + str_size("group="), end};
      if (valstr.empty()) {
        Log{ERROR} << "backend: group: empty string is not allowed";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
      out.group = valstr;
    } else if (util::istarts_with(param, "group-weight="sv)) {
      auto valstr = std::string_view{first + str_size("group-weight="), end};
      if (valstr.empty()) {
        Log{ERROR} << "backend: group-weight: non-negative integer [1, 256] is "
                      "expected";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }

      auto n = util::parse_uint(valstr);
      if (!n || (*n < 1 || *n > 256)) {
        Log{ERROR} << "backend: group-weight: non-negative integer [1, 256] is "
                      "expected";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
      out.group_weight = static_cast<uint32_t>(*n);
    } else if (util::strieq("dnf"sv, param)) {
      out.dnf = true;
    } else if (!param.empty()) {
      Log{ERROR} << "backend: " << param << ": unknown keyword";
      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    if (end == last) {
      break;
    }

    first = end + 1;
  }

  return out;
}
} // namespace

namespace {
// Parses host-path mapping patterns in |src_pattern|, and stores
// mappings in config.  We will store each host-path pattern found in
// |src| with |addr|.  |addr| will be copied accordingly.  Also we
// make a group based on the pattern.  The "/" pattern is considered
// as catch-all.  We also parse protocol specified in |src_proto|.
std::expected<void, Error> parse_mapping(
  Config *config, DownstreamAddrConfig &addr,
  std::unordered_map<std::string_view, size_t> &pattern_addr_indexer,
  std::string_view src_pattern, std::string_view src_params) {
  // This could include an empty string.  We will append '/' to all
  // patterns, so it becomes catch-all pattern.
  auto mapping = util::split_str(src_pattern, ':');
  if (mapping.empty()) {
    mapping.emplace_back(""sv);
  }
  auto &downstreamconf = *config->conn.downstream;
  auto &addr_groups = downstreamconf.addr_groups;

  auto maybe_params = parse_downstream_params(src_params);
  if (!maybe_params) {
    return std::unexpected{maybe_params.error()};
  }

  const auto &params = *maybe_params;

  if (addr.host_unix && params.dns) {
    Log{ERROR} << "backend: dns: cannot be used for UNIX domain socket";
    return std::unexpected{Error::INVALID_CONFIG};
  }

  if (params.affinity.type == SessionAffinity::COOKIE &&
      params.affinity.cookie.name.empty()) {
    Log{ERROR} << "backend: affinity-cookie-name is mandatory if "
                  "affinity=cookie is specified";
    return std::unexpected{Error::INVALID_CONFIG};
  }

  addr.fall = params.fall;
  addr.rise = params.rise;
  addr.weight = params.weight;
  addr.group = make_string_ref(downstreamconf.balloc, params.group);
  addr.group_weight = params.group_weight;
  addr.proto = params.proto;
  addr.tls = params.tls;
  addr.sni = make_string_ref(downstreamconf.balloc, params.sni);
  addr.dns = params.dns;
  addr.upgrade_scheme = params.upgrade_scheme;
  addr.dnf = params.dnf;

  for (const auto &raw_pattern : mapping) {
    std::string_view pattern;
    auto slash = std::ranges::find(raw_pattern, '/');
    if (slash == std::ranges::end(raw_pattern)) {
      // This effectively makes empty pattern to "/".  2 for '/' and
      // terminal NULL character.
      auto iov = make_byte_ref(downstreamconf.balloc, raw_pattern.size() + 2);
      auto p = util::tolower(raw_pattern, std::ranges::begin(iov));
      *p++ = '/';
      *p = '\0';
      pattern = as_string_view(std::ranges::begin(iov), p);
    } else {
      auto path = http2::normalize_path_colon(
        downstreamconf.balloc,
        std::string_view{slash, std::ranges::end(raw_pattern)}, ""sv);
      auto iov = make_byte_ref(downstreamconf.balloc,
                               as_unsigned(std::ranges::distance(
                                 std::ranges::begin(raw_pattern), slash)) +
                                 path.size() + 1);
      auto p = util::tolower(std::ranges::begin(raw_pattern), slash,
                             std::ranges::begin(iov));
      p = std::ranges::copy(path, p).out;
      *p = '\0';
      pattern = as_string_view(std::ranges::begin(iov), p);
    }
    auto it = pattern_addr_indexer.find(pattern);
    if (it != std::ranges::end(pattern_addr_indexer)) {
      auto &g = addr_groups[(*it).second];
      // Last value wins if we have multiple different affinity
      // value under one group.
      if (params.affinity.type != SessionAffinity::NONE) {
        if (g.affinity.type == SessionAffinity::NONE) {
          g.affinity.type = params.affinity.type;
          if (params.affinity.type == SessionAffinity::COOKIE) {
            g.affinity.cookie.name = make_string_ref(
              downstreamconf.balloc, params.affinity.cookie.name);
            if (!params.affinity.cookie.path.empty()) {
              g.affinity.cookie.path = make_string_ref(
                downstreamconf.balloc, params.affinity.cookie.path);
            }
            g.affinity.cookie.secure = params.affinity.cookie.secure;
            g.affinity.cookie.stickiness = params.affinity.cookie.stickiness;
          }
        } else if (g.affinity.type != params.affinity.type ||
                   g.affinity.cookie.name != params.affinity.cookie.name ||
                   g.affinity.cookie.path != params.affinity.cookie.path ||
                   g.affinity.cookie.secure != params.affinity.cookie.secure ||
                   g.affinity.cookie.stickiness !=
                     params.affinity.cookie.stickiness) {
          Log{ERROR} << "backend: affinity: multiple different affinity "
                        "configurations found in a single group";
          return std::unexpected{Error::INVALID_CONFIG};
        }
      }
      // If at least one backend requires frontend TLS connection,
      // enable it for all backends sharing the same pattern.
      if (params.redirect_if_not_tls) {
        g.redirect_if_not_tls = true;
      }
      // All backends in the same group must have the same mruby path.
      // If some backends do not specify mruby file, and there is at
      // least one backend with mruby file, it is used for all
      // backends in the group.
      if (!params.mruby.empty()) {
        if (g.mruby_file.empty()) {
          g.mruby_file = make_string_ref(downstreamconf.balloc, params.mruby);
        } else if (g.mruby_file != params.mruby) {
          Log{ERROR} << "backend: mruby: multiple different mruby file found "
                        "in a single group";
          return std::unexpected{Error::INVALID_CONFIG};
        }
      }
      // All backends in the same group must have the same read/write
      // timeout.  If some backends do not specify read/write timeout,
      // and there is at least one backend with read/write timeout, it
      // is used for all backends in the group.
      if (params.read_timeout > 1e-9) {
        if (g.timeout.read < 1e-9) {
          g.timeout.read = params.read_timeout;
        } else if (fabs(g.timeout.read - params.read_timeout) > 1e-9) {
          Log{ERROR}
            << "backend: read-timeout: multiple different read-timeout "
               "found in a single group";
          return std::unexpected{Error::INVALID_CONFIG};
        }
      }
      if (params.write_timeout > 1e-9) {
        if (g.timeout.write < 1e-9) {
          g.timeout.write = params.write_timeout;
        } else if (fabs(g.timeout.write - params.write_timeout) > 1e-9) {
          Log{ERROR} << "backend: write-timeout: multiple different "
                        "write-timeout found in a single group";
          return std::unexpected{Error::INVALID_CONFIG};
        }
      }
      // All backends in the same group must have the same dnf
      // setting.  If some backends do not specify dnf, and there is
      // at least one backend with dnf, it is used for all backends in
      // the group.  In general, multiple backends are not necessary
      // for dnf because there is no need for load balancing.
      if (params.dnf) {
        g.dnf = true;
      }

      g.addrs.push_back(addr);
      continue;
    }

    auto idx = addr_groups.size();
    pattern_addr_indexer.emplace(pattern, idx);
    addr_groups.emplace_back(pattern);
    auto &g = addr_groups.back();
    g.addrs.push_back(addr);
    g.affinity.type = params.affinity.type;
    if (params.affinity.type == SessionAffinity::COOKIE) {
      g.affinity.cookie.name =
        make_string_ref(downstreamconf.balloc, params.affinity.cookie.name);
      if (!params.affinity.cookie.path.empty()) {
        g.affinity.cookie.path =
          make_string_ref(downstreamconf.balloc, params.affinity.cookie.path);
      }
      g.affinity.cookie.secure = params.affinity.cookie.secure;
      g.affinity.cookie.stickiness = params.affinity.cookie.stickiness;
    }
    g.redirect_if_not_tls = params.redirect_if_not_tls;
    g.mruby_file = make_string_ref(downstreamconf.balloc, params.mruby);
    g.timeout.read = params.read_timeout;
    g.timeout.write = params.write_timeout;
    g.dnf = params.dnf;
  }
  return {};
}
} // namespace

namespace {
std::expected<ForwardedNode, Error>
parse_forwarded_node_type(std::string_view optarg) {
  if (util::strieq("obfuscated"sv, optarg)) {
    return ForwardedNode::OBFUSCATED;
  }

  if (util::strieq("ip"sv, optarg)) {
    return ForwardedNode::IP;
  }

  if (optarg.size() < 2 || optarg[0] != '_') {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  if (std::ranges::find_if_not(optarg, [](auto c) {
        return util::is_alpha(c) || util::is_digit(c) || c == '.' || c == '_' ||
               c == '-';
      }) != std::ranges::end(optarg)) {
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  return ForwardedNode::OBFUSCATED;
}
} // namespace

namespace {
std::expected<ErrorPage, Error> parse_error_page(std::string_view opt,
                                                 std::string_view optarg) {
  std::array<char, STRERROR_BUFSIZE> errbuf;

  auto eq = std::ranges::find(optarg, '=');
  if (eq == std::ranges::end(optarg) || eq + 1 == std::ranges::end(optarg)) {
    Log{ERROR} << opt << ": bad value: '" << optarg << "'";
    return std::unexpected{Error::INVALID_ARGUMENT};
  }

  auto codestr = std::string_view{std::ranges::begin(optarg), eq};
  unsigned int code;

  if (codestr == "*"sv) {
    code = 0;
  } else {
    auto maybe_n = util::parse_uint(codestr);
    if (!maybe_n) {
      Log{ERROR} << opt << ": bad code: '" << codestr << "'";
      return std::unexpected{maybe_n.error()};
    }

    auto n = *maybe_n;
    if (n < 400 || n > 599) {
      Log{ERROR} << opt << ": bad code: '" << codestr << "'";
      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    code = static_cast<unsigned int>(n);
  }

  auto path = std::string_view{eq + 1, std::ranges::end(optarg)};

  std::vector<uint8_t> content;
  auto fd = open(path.data(), O_RDONLY);
  if (fd == -1) {
    auto error = errno;
    Log{ERROR} << opt << ": " << optarg << ": "
               << xsi_strerror(error, errbuf.data(), errbuf.size());
    return std::unexpected{Error::SYSCALL};
  }

  auto fd_closer = defer([fd] { close(fd); });

  std::array<uint8_t, 4096> buf;
  for (;;) {
    auto n = read(fd, buf.data(), buf.size());
    if (n == -1) {
      auto error = errno;
      Log{ERROR} << opt << ": " << optarg << ": "
                 << xsi_strerror(error, errbuf.data(), errbuf.size());
      return std::unexpected{Error::SYSCALL};
    }
    if (n == 0) {
      break;
    }
    content.insert(std::ranges::end(content), std::ranges::begin(buf),
                   std::ranges::begin(buf) + n);
  }

  return ErrorPage{std::move(content), code};
}
} // namespace

// Maximum size of SCT extension payload length.
constexpr size_t MAX_SCT_EXT_LEN = 16_k;

struct SubcertParams {
  std::string_view sct_dir;
};

namespace {
// Parses subcert parameter |src_params|, and returns the result.
std::expected<SubcertParams, Error>
parse_subcert_params(std::string_view src_params) {
  SubcertParams out;

  auto last = std::ranges::end(src_params);
  for (auto first = std::ranges::begin(src_params); first != last;) {
    auto end = std::ranges::find(first, last, ';');
    auto param = std::string_view{first, end};

    if (util::istarts_with(param, "sct-dir="sv)) {
#if defined(NGHTTP2_GENUINE_OPENSSL) || defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
      auto sct_dir =
        std::string_view{std::ranges::begin(param) + str_size("sct-dir="),
                         std::ranges::end(param)};
      if (sct_dir.empty()) {
        Log{ERROR} << "subcert: " << param << ": empty sct-dir";
        return std::unexpected{Error::INVALID_ARGUMENT};
      }
      out.sct_dir = sct_dir;
#else  // !defined(NGHTTP2_GENUINE_OPENSSL) &&
       // !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
      Log{WARN} << "subcert: sct-dir is ignored because underlying TLS library "
                   "does not support SCT";
#endif // !defined(NGHTTP2_GENUINE_OPENSSL) &&
       // !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
    } else if (!param.empty()) {
      Log{ERROR} << "subcert: " << param << ": unknown keyword";
      return std::unexpected{Error::INVALID_ARGUMENT};
    }

    if (end == last) {
      break;
    }

    first = end + 1;
  }

  return out;
}
} // namespace

namespace {
// Reads *.sct files from directory denoted by |dir_path|.  |dir_path|
// must be NULL-terminated string.
std::expected<std::vector<uint8_t>, Error>
read_tls_sct_from_dir(std::string_view opt, std::string_view dir_path) {
  std::array<char, STRERROR_BUFSIZE> errbuf;

  auto dir = opendir(dir_path.data());
  if (dir == nullptr) {
    auto error = errno;
    Log{ERROR} << opt << ": " << dir_path << ": "
               << xsi_strerror(error, errbuf.data(), errbuf.size());
    return std::unexpected{Error::LIBC};
  }

  auto closer = defer([dir] { closedir(dir); });

  // 2 bytes total length field
  std::vector<uint8_t> dst;
  dst.insert(std::ranges::end(dst), 2, 0);

  for (;;) {
    errno = 0;
    auto ent = readdir(dir);
    if (ent == nullptr) {
      if (errno != 0) {
        auto error = errno;
        Log{ERROR} << opt << ": failed to read directory " << dir_path << ": "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        return std::unexpected{Error::LIBC};
      }
      break;
    }

    auto name = std::string_view{ent->d_name};

    if (name[0] == '.' || !util::iends_with(name, ".sct"sv)) {
      continue;
    }

    std::string path;
    path.resize_and_overwrite(dir_path.size() + 1 + name.size(),
                              [dir_path, name](auto p, auto len) {
                                auto first = p;

                                p = std::ranges::copy(dir_path, p).out;
                                *p++ = '/';
                                p = std::ranges::copy(name, p).out;

                                return std::ranges::distance(first, p);
                              });

    auto fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
      auto error = errno;
      Log{ERROR} << opt << ": failed to read SCT from " << path << ": "
                 << xsi_strerror(error, errbuf.data(), errbuf.size());
      return std::unexpected{Error::SYSCALL};
    }

    auto closer = defer([fd] { close(fd); });

    // 2 bytes length field for this SCT.
    auto len_idx = dst.size();
    dst.insert(std::ranges::end(dst), 2, 0);

    // *.sct file tends to be small; around 110+ bytes.
    std::array<char, 256> buf;
    for (;;) {
      ssize_t nread;
      while ((nread = read(fd, buf.data(), buf.size())) == -1 && errno == EINTR)
        ;

      if (nread == -1) {
        auto error = errno;
        Log{ERROR} << opt << ": failed to read SCT data from " << path << ": "
                   << xsi_strerror(error, errbuf.data(), errbuf.size());
        return std::unexpected{Error::SYSCALL};
      }

      if (nread == 0) {
        break;
      }

      dst.insert(std::ranges::end(dst), std::ranges::begin(buf),
                 std::ranges::begin(buf) + nread);

      if (dst.size() > MAX_SCT_EXT_LEN) {
        Log{ERROR} << opt << ": the concatenated SCT data from " << dir_path
                   << " is too large.  Max " << MAX_SCT_EXT_LEN;
        return std::unexpected{Error::INVALID_CONFIG};
      }
    }

    auto len = dst.size() - len_idx - 2;

    if (len == 0) {
      dst.resize(dst.size() - 2);
      continue;
    }

    dst[len_idx] = static_cast<uint8_t>(len >> 8);
    dst[len_idx + 1] = static_cast<uint8_t>(len);
  }

  auto len = dst.size() - 2;

  if (len == 0) {
    return std::vector<uint8_t>{};
  }

  // Set length
  dst[0] = static_cast<uint8_t>(len >> 8);
  dst[1] = static_cast<uint8_t>(len);

  return dst;
}
} // namespace

#ifndef OPENSSL_NO_PSK
namespace {
// Reads PSK secrets from path, and parses each line.  The result is
// directly stored into config->tls.psk_secrets.
std::expected<void, Error> parse_psk_secrets(Config *config,
                                             std::string_view path) {
  auto &tlsconf = config->tls;

  std::ifstream f(path.data(), std::ios::binary);
  if (!f) {
    Log{ERROR} << SHRPX_OPT_PSK_SECRETS << ": could not open file " << path;
    return std::unexpected{Error::IO};
  }

  size_t lineno = 0;
  std::string line;
  while (std::getline(f, line)) {
    ++lineno;
    if (line.empty() || line[0] == '#') {
      continue;
    }

    auto sep_it = std::ranges::find(line, ':');
    if (sep_it == std::ranges::end(line)) {
      Log{ERROR} << SHRPX_OPT_PSK_SECRETS
                 << ": could not fine separator at line " << lineno;
      return std::unexpected{Error::INVALID_CONFIG};
    }

    if (sep_it == std::ranges::begin(line)) {
      Log{ERROR} << SHRPX_OPT_PSK_SECRETS << ": empty identity at line "
                 << lineno;
      return std::unexpected{Error::INVALID_CONFIG};
    }

    if (sep_it + 1 == std::ranges::end(line)) {
      Log{ERROR} << SHRPX_OPT_PSK_SECRETS << ": empty secret at line "
                 << lineno;
      return std::unexpected{Error::INVALID_CONFIG};
    }

    if (!util::is_hex_string(sep_it + 1, std::ranges::end(line))) {
      Log{ERROR} << SHRPX_OPT_PSK_SECRETS
                 << ": secret must be hex string at line " << lineno;
      return std::unexpected{Error::INVALID_CONFIG};
    }

    auto identity = make_string_ref(
      config->balloc, std::string_view{std::ranges::begin(line), sep_it});

    auto secret = as_string_view(
      util::decode_hex(config->balloc, sep_it + 1, std::ranges::end(line)));

    auto rv = tlsconf.psk_secrets.emplace(identity, secret);
    if (!rv.second) {
      Log{ERROR} << SHRPX_OPT_PSK_SECRETS
                 << ": identity has already been registered at line " << lineno;
      return std::unexpected{Error::INVALID_CONFIG};
    }
  }

  return {};
}
} // namespace
#endif // !defined(OPENSSL_NO_PSK)

#ifndef OPENSSL_NO_PSK
namespace {
// Reads PSK secrets from path, and parses each line.  The result is
// directly stored into config->tls.client.psk.
std::expected<void, Error> parse_client_psk_secrets(Config *config,
                                                    std::string_view path) {
  auto &tlsconf = config->tls;

  std::ifstream f(path.data(), std::ios::binary);
  if (!f) {
    Log{ERROR} << SHRPX_OPT_CLIENT_PSK_SECRETS << ": could not open file "
               << path;
    return std::unexpected{Error::IO};
  }

  size_t lineno = 0;
  std::string line;
  while (std::getline(f, line)) {
    ++lineno;
    if (line.empty() || line[0] == '#') {
      continue;
    }

    auto sep_it = std::ranges::find(line, ':');
    if (sep_it == std::ranges::end(line)) {
      Log{ERROR} << SHRPX_OPT_CLIENT_PSK_SECRETS
                 << ": could not find separator at line " << lineno;
      return std::unexpected{Error::INVALID_CONFIG};
    }

    if (sep_it == std::ranges::begin(line)) {
      Log{ERROR} << SHRPX_OPT_CLIENT_PSK_SECRETS << ": empty identity at line "
                 << lineno;
      return std::unexpected{Error::INVALID_CONFIG};
    }

    if (sep_it + 1 == std::ranges::end(line)) {
      Log{ERROR} << SHRPX_OPT_CLIENT_PSK_SECRETS << ": empty secret at line "
                 << lineno;
      return std::unexpected{Error::INVALID_CONFIG};
    }

    if (!util::is_hex_string(sep_it + 1, std::ranges::end(line))) {
      Log{ERROR} << SHRPX_OPT_CLIENT_PSK_SECRETS
                 << ": secret must be hex string at line " << lineno;
      return std::unexpected{Error::INVALID_CONFIG};
    }

    tlsconf.client.psk.identity = make_string_ref(
      config->balloc, std::string_view{std::ranges::begin(line), sep_it});

    tlsconf.client.psk.secret = as_string_view(
      util::decode_hex(config->balloc, sep_it + 1, std::ranges::end(line)));

    return {};
  }

  return {};
}
} // namespace
#endif // !defined(OPENSSL_NO_PSK)

namespace {
std::expected<void, Error> read_ech_config_file(Config *config,
                                                std::string_view opt,
                                                std::string_view path,
                                                bool retry = false) {
#ifdef NGHTTP2_OPENSSL_IS_BORINGSSL
  auto maybe_priv_key = tls::read_hpke_private_key_pem(config->balloc, path);
  if (!maybe_priv_key) {
    Log{ERROR} << opt << ": could not read HPKE private key from " << path;

    return std::unexpected{maybe_priv_key.error()};
  }

  auto maybe_ech_config_list =
    tls::read_pem(config->balloc, path, "ECHCONFIG"sv);
  if (!maybe_ech_config_list) {
    Log{ERROR} << opt << ": could not read ECHCONFIG from " << path;

    return std::unexpected{maybe_ech_config_list.error()};
  }

  auto ech_config_list = *maybe_ech_config_list;
  if (ech_config_list.size() < 2) {
    Log{ERROR} << opt << ": ECHCONFIG is malformed: " << path;

    return std::unexpected{Error::INVALID_CONFIG};
  }

  auto data = ech_config_list.subspan(2);

  if (auto len =
        static_cast<size_t>((ech_config_list[0] << 8) + ech_config_list[1]);
      len != data.size()) {
    Log{ERROR} << opt << ": ECHCONFIG is malformed: " << path;

    return std::unexpected{Error::INVALID_CONFIG};
  }

  std::vector<std::span<const uint8_t>> config_list;

  for (; !data.empty();) {
    // version and length, each 2 bytes
    if (data.size() < 4) {
      Log{ERROR} << opt << ": ECHCONFIG is malformed: " << path;

      return std::unexpected{Error::INVALID_CONFIG};
    }

    auto version = static_cast<uint16_t>((data[0] << 8) + data[1]);

    auto conflen = static_cast<size_t>(4 + (data[2] << 8) + data[3]);
    if (data.size() < conflen) {
      Log{ERROR} << opt << ": ECHCONFIG is malformed: " << path;

      return std::unexpected{Error::INVALID_CONFIG};
    }

    if (version == 0xFE0D) {
      config_list.emplace_back(data.first(conflen));
    } else {
      Log{WARN} << opt << ": skipping unsupported ECH version " << log::hex
                << version << ": " << path;
    }

    data = data.subspan(conflen);
  }

  if (config_list.empty()) {
    return {};
  }

  config->tls.ech_key_config_list.emplace_back(ECHKeyConfig{
    .private_key = *maybe_priv_key,
    .config_list = std::move(config_list),
    .retry = retry,
  });

  return {};
#elif OPENSSL_4_0_0_API
  auto &tlsconf = config->tls;
  if (!tlsconf.ech_store) {
    tlsconf.ech_store = OSSL_ECHSTORE_new(nullptr, nullptr);
  }

  auto f = BIO_new_file(path.data(), "r");
  if (!f) {
    Log{ERROR} << opt << ": could not open PEM ECH file " << path << ": "
               << ERR_error_string(ERR_get_error(), nullptr);

    return std::unexpected{Error::CRYPTO};
  }

  auto f_d = defer([f] { BIO_free(f); });

  if (OSSL_ECHSTORE_read_pem(tlsconf.ech_store, f, retry) != 1) {
    Log{ERROR} << opt << ": could not read PEM ECH file " << path << ": "
               << ERR_error_string(ERR_get_error(), nullptr);

    return std::unexpected{Error::CRYPTO};
  }

  return {};
#else  // !defined(NGHTTP2_OPENSSL_IS_BORINGSSL) && !OPENSSL_4_0_0_API
  Log{WARN} << "The underlying TLS stack does not support ECH";

  return {};
#endif // !defined(NGHTTP2_OPENSSL_IS_BORINGSSL) && !OPENSSL_4_0_0_API
}
} // namespace

// generated by gennghttpxfun.py
int option_lookup_token(std::string_view name) {
  switch (name.size()) {
  case 4:
    switch (name[3]) {
    case 'f':
      if (util::strieq("con"sv, name.substr(0, 3))) {
        return SHRPX_OPTID_CONF;
      }
      break;
    case 'r':
      if (util::strieq("use"sv, name.substr(0, 3))) {
        return SHRPX_OPTID_USER;
      }
      break;
    }
    break;
  case 6:
    switch (name[5]) {
    case 'a':
      if (util::strieq("no-vi"sv, name.substr(0, 5))) {
        return SHRPX_OPTID_NO_VIA;
      }
      break;
    case 'c':
      if (util::strieq("altsv"sv, name.substr(0, 5))) {
        return SHRPX_OPTID_ALTSVC;
      }
      break;
    case 'n':
      if (util::strieq("daemo"sv, name.substr(0, 5))) {
        return SHRPX_OPTID_DAEMON;
      }
      break;
    case 's':
      if (util::strieq("group"sv, name.substr(0, 5))) {
        return SHRPX_OPTID_GROUPS;
      }
      break;
    case 't':
      if (util::strieq("cacer"sv, name.substr(0, 5))) {
        return SHRPX_OPTID_CACERT;
      }
      if (util::strieq("clien"sv, name.substr(0, 5))) {
        return SHRPX_OPTID_CLIENT;
      }
      break;
    }
    break;
  case 7:
    switch (name[6]) {
    case 'd':
      if (util::strieq("backen"sv, name.substr(0, 6))) {
        return SHRPX_OPTID_BACKEND;
      }
      break;
    case 'e':
      if (util::strieq("includ"sv, name.substr(0, 6))) {
        return SHRPX_OPTID_INCLUDE;
      }
      break;
    case 'g':
      if (util::strieq("backlo"sv, name.substr(0, 6))) {
        return SHRPX_OPTID_BACKLOG;
      }
      if (util::strieq("paddin"sv, name.substr(0, 6))) {
        return SHRPX_OPTID_PADDING;
      }
      break;
    case 'p':
      if (util::strieq("no-ocs"sv, name.substr(0, 6))) {
        return SHRPX_OPTID_NO_OCSP;
      }
      break;
    case 's':
      if (util::strieq("cipher"sv, name.substr(0, 6))) {
        return SHRPX_OPTID_CIPHERS;
      }
      if (util::strieq("worker"sv, name.substr(0, 6))) {
        return SHRPX_OPTID_WORKERS;
      }
      break;
    case 't':
      if (util::strieq("subcer"sv, name.substr(0, 6))) {
        return SHRPX_OPTID_SUBCERT;
      }
      break;
    }
    break;
  case 8:
    switch (name[7]) {
    case 'd':
      if (util::strieq("fronten"sv, name.substr(0, 7))) {
        return SHRPX_OPTID_FRONTEND;
      }
      break;
    case 'e':
      if (util::strieq("insecur"sv, name.substr(0, 7))) {
        return SHRPX_OPTID_INSECURE;
      }
      if (util::strieq("pid-fil"sv, name.substr(0, 7))) {
        return SHRPX_OPTID_PID_FILE;
      }
      break;
    case 'n':
      if (util::strieq("fastope"sv, name.substr(0, 7))) {
        return SHRPX_OPTID_FASTOPEN;
      }
      break;
    case 's':
      if (util::strieq("tls-ktl"sv, name.substr(0, 7))) {
        return SHRPX_OPTID_TLS_KTLS;
      }
      break;
    case 't':
      if (util::strieq("npn-lis"sv, name.substr(0, 7))) {
        return SHRPX_OPTID_NPN_LIST;
      }
      break;
    }
    break;
  case 9:
    switch (name[8]) {
    case 'e':
      if (util::strieq("no-kqueu"sv, name.substr(0, 8))) {
        return SHRPX_OPTID_NO_KQUEUE;
      }
      if (util::strieq("read-rat"sv, name.substr(0, 8))) {
        return SHRPX_OPTID_READ_RATE;
      }
      break;
    case 'l':
      if (util::strieq("log-leve"sv, name.substr(0, 8))) {
        return SHRPX_OPTID_LOG_LEVEL;
      }
      break;
    case 't':
      if (util::strieq("alpn-lis"sv, name.substr(0, 8))) {
        return SHRPX_OPTID_ALPN_LIST;
      }
      break;
    }
    break;
  case 10:
    switch (name[9]) {
    case 'e':
      if (util::strieq("error-pag"sv, name.substr(0, 9))) {
        return SHRPX_OPTID_ERROR_PAGE;
      }
      if (util::strieq("mruby-fil"sv, name.substr(0, 9))) {
        return SHRPX_OPTID_MRUBY_FILE;
      }
      if (util::strieq("write-rat"sv, name.substr(0, 9))) {
        return SHRPX_OPTID_WRITE_RATE;
      }
      break;
    case 't':
      if (util::strieq("read-burs"sv, name.substr(0, 9))) {
        return SHRPX_OPTID_READ_BURST;
      }
      break;
    }
    break;
  case 11:
    switch (name[10]) {
    case 'e':
      if (util::strieq("server-nam"sv, name.substr(0, 10))) {
        return SHRPX_OPTID_SERVER_NAME;
      }
      break;
    case 'f':
      if (util::strieq("no-quic-bp"sv, name.substr(0, 10))) {
        return SHRPX_OPTID_NO_QUIC_BPF;
      }
      break;
    case 'r':
      if (util::strieq("tls-sct-di"sv, name.substr(0, 10))) {
        return SHRPX_OPTID_TLS_SCT_DIR;
      }
      break;
    case 's':
      if (util::strieq("backend-tl"sv, name.substr(0, 10))) {
        return SHRPX_OPTID_BACKEND_TLS;
      }
      if (util::strieq("ecdh-curve"sv, name.substr(0, 10))) {
        return SHRPX_OPTID_ECDH_CURVES;
      }
      if (util::strieq("psk-secret"sv, name.substr(0, 10))) {
        return SHRPX_OPTID_PSK_SECRETS;
      }
      break;
    case 't':
      if (util::strieq("write-burs"sv, name.substr(0, 10))) {
        return SHRPX_OPTID_WRITE_BURST;
      }
      break;
    case 'y':
      if (util::strieq("dns-max-tr"sv, name.substr(0, 10))) {
        return SHRPX_OPTID_DNS_MAX_TRY;
      }
      if (util::strieq("http2-prox"sv, name.substr(0, 10))) {
        return SHRPX_OPTID_HTTP2_PROXY;
      }
      break;
    }
    break;
  case 12:
    switch (name[11]) {
    case '4':
      if (util::strieq("backend-ipv"sv, name.substr(0, 11))) {
        return SHRPX_OPTID_BACKEND_IPV4;
      }
      break;
    case '6':
      if (util::strieq("backend-ipv"sv, name.substr(0, 11))) {
        return SHRPX_OPTID_BACKEND_IPV6;
      }
      break;
    case 'c':
      if (util::strieq("http2-altsv"sv, name.substr(0, 11))) {
        return SHRPX_OPTID_HTTP2_ALTSVC;
      }
      break;
    case 'e':
      if (util::strieq("host-rewrit"sv, name.substr(0, 11))) {
        return SHRPX_OPTID_HOST_REWRITE;
      }
      if (util::strieq("http2-bridg"sv, name.substr(0, 11))) {
        return SHRPX_OPTID_HTTP2_BRIDGE;
      }
      break;
    case 'p':
      if (util::strieq("ocsp-startu"sv, name.substr(0, 11))) {
        return SHRPX_OPTID_OCSP_STARTUP;
      }
      break;
    case 'y':
      if (util::strieq("client-prox"sv, name.substr(0, 11))) {
        return SHRPX_OPTID_CLIENT_PROXY;
      }
      if (util::strieq("forwarded-b"sv, name.substr(0, 11))) {
        return SHRPX_OPTID_FORWARDED_BY;
      }
      break;
    }
    break;
  case 13:
    switch (name[12]) {
    case 'd':
      if (util::strieq("add-forwarde"sv, name.substr(0, 12))) {
        return SHRPX_OPTID_ADD_FORWARDED;
      }
      if (util::strieq("single-threa"sv, name.substr(0, 12))) {
        return SHRPX_OPTID_SINGLE_THREAD;
      }
      break;
    case 'e':
      if (util::strieq("dh-param-fil"sv, name.substr(0, 12))) {
        return SHRPX_OPTID_DH_PARAM_FILE;
      }
      if (util::strieq("errorlog-fil"sv, name.substr(0, 12))) {
        return SHRPX_OPTID_ERRORLOG_FILE;
      }
      if (util::strieq("rlimit-nofil"sv, name.substr(0, 12))) {
        return SHRPX_OPTID_RLIMIT_NOFILE;
      }
      break;
    case 'r':
      if (util::strieq("forwarded-fo"sv, name.substr(0, 12))) {
        return SHRPX_OPTID_FORWARDED_FOR;
      }
      break;
    case 's':
      if (util::strieq("tls13-cipher"sv, name.substr(0, 12))) {
        return SHRPX_OPTID_TLS13_CIPHERS;
      }
      break;
    case 't':
      if (util::strieq("verify-clien"sv, name.substr(0, 12))) {
        return SHRPX_OPTID_VERIFY_CLIENT;
      }
      break;
    }
    break;
  case 14:
    switch (name[13]) {
    case 'd':
      if (util::strieq("quic-server-i"sv, name.substr(0, 13))) {
        return SHRPX_OPTID_QUIC_SERVER_ID;
      }
      break;
    case 'e':
      if (util::strieq("accesslog-fil"sv, name.substr(0, 13))) {
        return SHRPX_OPTID_ACCESSLOG_FILE;
      }
      break;
    case 'h':
      if (util::strieq("no-server-pus"sv, name.substr(0, 13))) {
        return SHRPX_OPTID_NO_SERVER_PUSH;
      }
      break;
    case 'k':
      if (util::strieq("rlimit-memloc"sv, name.substr(0, 13))) {
        return SHRPX_OPTID_RLIMIT_MEMLOCK;
      }
      break;
    case 'p':
      if (util::strieq("no-verify-ocs"sv, name.substr(0, 13))) {
        return SHRPX_OPTID_NO_VERIFY_OCSP;
      }
      break;
    case 's':
      if (util::strieq("backend-no-tl"sv, name.substr(0, 13))) {
        return SHRPX_OPTID_BACKEND_NO_TLS;
      }
      if (util::strieq("client-cipher"sv, name.substr(0, 13))) {
        return SHRPX_OPTID_CLIENT_CIPHERS;
      }
      if (util::strieq("single-proces"sv, name.substr(0, 13))) {
        return SHRPX_OPTID_SINGLE_PROCESS;
      }
      break;
    case 't':
      if (util::strieq("tls-proto-lis"sv, name.substr(0, 13))) {
        return SHRPX_OPTID_TLS_PROTO_LIST;
      }
      break;
    }
    break;
  case 15:
    switch (name[14]) {
    case 'e':
      if (util::strieq("ech-config-fil"sv, name.substr(0, 14))) {
        return SHRPX_OPTID_ECH_CONFIG_FILE;
      }
      if (util::strieq("no-host-rewrit"sv, name.substr(0, 14))) {
        return SHRPX_OPTID_NO_HOST_REWRITE;
      }
      break;
    case 'g':
      if (util::strieq("errorlog-syslo"sv, name.substr(0, 14))) {
        return SHRPX_OPTID_ERRORLOG_SYSLOG;
      }
      break;
    case 's':
      if (util::strieq("frontend-no-tl"sv, name.substr(0, 14))) {
        return SHRPX_OPTID_FRONTEND_NO_TLS;
      }
      break;
    case 'y':
      if (util::strieq("syslog-facilit"sv, name.substr(0, 14))) {
        return SHRPX_OPTID_SYSLOG_FACILITY;
      }
      break;
    }
    break;
  case 16:
    switch (name[15]) {
    case 'e':
      if (util::strieq("certificate-fil"sv, name.substr(0, 15))) {
        return SHRPX_OPTID_CERTIFICATE_FILE;
      }
      if (util::strieq("client-cert-fil"sv, name.substr(0, 15))) {
        return SHRPX_OPTID_CLIENT_CERT_FILE;
      }
      if (util::strieq("private-key-fil"sv, name.substr(0, 15))) {
        return SHRPX_OPTID_PRIVATE_KEY_FILE;
      }
      if (util::strieq("worker-read-rat"sv, name.substr(0, 15))) {
        return SHRPX_OPTID_WORKER_READ_RATE;
      }
      break;
    case 'g':
      if (util::strieq("accesslog-syslo"sv, name.substr(0, 15))) {
        return SHRPX_OPTID_ACCESSLOG_SYSLOG;
      }
      break;
    case 't':
      if (util::strieq("accesslog-forma"sv, name.substr(0, 15))) {
        return SHRPX_OPTID_ACCESSLOG_FORMAT;
      }
      break;
    }
    break;
  case 17:
    switch (name[16]) {
    case 'e':
      if (util::strieq("no-server-rewrit"sv, name.substr(0, 16))) {
        return SHRPX_OPTID_NO_SERVER_REWRITE;
      }
      if (util::strieq("worker-write-rat"sv, name.substr(0, 16))) {
        return SHRPX_OPTID_WORKER_WRITE_RATE;
      }
      break;
    case 's':
      if (util::strieq("backend-http1-tl"sv, name.substr(0, 16))) {
        return SHRPX_OPTID_BACKEND_HTTP1_TLS;
      }
      if (util::strieq("max-header-field"sv, name.substr(0, 16))) {
        return SHRPX_OPTID_MAX_HEADER_FIELDS;
      }
      break;
    case 't':
      if (util::strieq("dns-cache-timeou"sv, name.substr(0, 16))) {
        return SHRPX_OPTID_DNS_CACHE_TIMEOUT;
      }
      if (util::strieq("worker-read-burs"sv, name.substr(0, 16))) {
        return SHRPX_OPTID_WORKER_READ_BURST;
      }
      break;
    }
    break;
  case 18:
    switch (name[17]) {
    case 'a':
      if (util::strieq("tls-max-early-dat"sv, name.substr(0, 17))) {
        return SHRPX_OPTID_TLS_MAX_EARLY_DATA;
      }
      break;
    case 'r':
      if (util::strieq("add-request-heade"sv, name.substr(0, 17))) {
        return SHRPX_OPTID_ADD_REQUEST_HEADER;
      }
      break;
    case 's':
      if (util::strieq("client-psk-secret"sv, name.substr(0, 17))) {
        return SHRPX_OPTID_CLIENT_PSK_SECRETS;
      }
      break;
    case 't':
      if (util::strieq("dns-lookup-timeou"sv, name.substr(0, 17))) {
        return SHRPX_OPTID_DNS_LOOKUP_TIMEOUT;
      }
      if (util::strieq("worker-write-burs"sv, name.substr(0, 17))) {
        return SHRPX_OPTID_WORKER_WRITE_BURST;
      }
      break;
    }
    break;
  case 19:
    switch (name[18]) {
    case 'e':
      if (util::strieq("no-location-rewrit"sv, name.substr(0, 18))) {
        return SHRPX_OPTID_NO_LOCATION_REWRITE;
      }
      if (util::strieq("require-http-schem"sv, name.substr(0, 18))) {
        return SHRPX_OPTID_REQUIRE_HTTP_SCHEME;
      }
      if (util::strieq("tls-ticket-key-fil"sv, name.substr(0, 18))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_FILE;
      }
      break;
    case 'f':
      if (util::strieq("backend-max-backof"sv, name.substr(0, 18))) {
        return SHRPX_OPTID_BACKEND_MAX_BACKOFF;
      }
      break;
    case 'r':
      if (util::strieq("add-response-heade"sv, name.substr(0, 18))) {
        return SHRPX_OPTID_ADD_RESPONSE_HEADER;
      }
      if (util::strieq("add-x-forwarded-fo"sv, name.substr(0, 18))) {
        return SHRPX_OPTID_ADD_X_FORWARDED_FOR;
      }
      if (util::strieq("header-field-buffe"sv, name.substr(0, 18))) {
        return SHRPX_OPTID_HEADER_FIELD_BUFFER;
      }
      break;
    case 't':
      if (util::strieq("redirect-https-por"sv, name.substr(0, 18))) {
        return SHRPX_OPTID_REDIRECT_HTTPS_PORT;
      }
      if (util::strieq("stream-read-timeou"sv, name.substr(0, 18))) {
        return SHRPX_OPTID_STREAM_READ_TIMEOUT;
      }
      break;
    }
    break;
  case 20:
    switch (name[19]) {
    case 'g':
      if (util::strieq("frontend-frame-debu"sv, name.substr(0, 19))) {
        return SHRPX_OPTID_FRONTEND_FRAME_DEBUG;
      }
      break;
    case 'l':
      if (util::strieq("ocsp-update-interva"sv, name.substr(0, 19))) {
        return SHRPX_OPTID_OCSP_UPDATE_INTERVAL;
      }
      break;
    case 's':
      if (util::strieq("max-worker-processe"sv, name.substr(0, 19))) {
        return SHRPX_OPTID_MAX_WORKER_PROCESSES;
      }
      if (util::strieq("tls13-client-cipher"sv, name.substr(0, 19))) {
        return SHRPX_OPTID_TLS13_CLIENT_CIPHERS;
      }
      break;
    case 't':
      if (util::strieq("backend-read-timeou"sv, name.substr(0, 19))) {
        return SHRPX_OPTID_BACKEND_READ_TIMEOUT;
      }
      if (util::strieq("stream-write-timeou"sv, name.substr(0, 19))) {
        return SHRPX_OPTID_STREAM_WRITE_TIMEOUT;
      }
      if (util::strieq("verify-client-cacer"sv, name.substr(0, 19))) {
        return SHRPX_OPTID_VERIFY_CLIENT_CACERT;
      }
      break;
    case 'y':
      if (util::strieq("api-max-request-bod"sv, name.substr(0, 19))) {
        return SHRPX_OPTID_API_MAX_REQUEST_BODY;
      }
      break;
    }
    break;
  case 21:
    switch (name[20]) {
    case 'd':
      if (util::strieq("backend-tls-sni-fiel"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_BACKEND_TLS_SNI_FIELD;
      }
      break;
    case 'e':
      if (util::strieq("ech-retry-config-fil"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_ECH_RETRY_CONFIG_FILE;
      }
      if (util::strieq("quic-bpf-program-fil"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_QUIC_BPF_PROGRAM_FILE;
      }
      break;
    case 'l':
      if (util::strieq("accept-proxy-protoco"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_ACCEPT_PROXY_PROTOCOL;
      }
      break;
    case 'n':
      if (util::strieq("tls-max-proto-versio"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_TLS_MAX_PROTO_VERSION;
      }
      if (util::strieq("tls-min-proto-versio"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_TLS_MIN_PROTO_VERSION;
      }
      break;
    case 'r':
      if (util::strieq("tls-ticket-key-ciphe"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_CIPHER;
      }
      break;
    case 's':
      if (util::strieq("frontend-max-request"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_FRONTEND_MAX_REQUESTS;
      }
      break;
    case 't':
      if (util::strieq("backend-write-timeou"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_BACKEND_WRITE_TIMEOUT;
      }
      if (util::strieq("frontend-read-timeou"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_FRONTEND_READ_TIMEOUT;
      }
      break;
    case 'y':
      if (util::strieq("accesslog-write-earl"sv, name.substr(0, 20))) {
        return SHRPX_OPTID_ACCESSLOG_WRITE_EARLY;
      }
      break;
    }
    break;
  case 22:
    switch (name[21]) {
    case 'i':
      if (util::strieq("backend-http-proxy-ur"sv, name.substr(0, 21))) {
        return SHRPX_OPTID_BACKEND_HTTP_PROXY_URI;
      }
      break;
    case 'r':
      if (util::strieq("backend-request-buffe"sv, name.substr(0, 21))) {
        return SHRPX_OPTID_BACKEND_REQUEST_BUFFER;
      }
      if (util::strieq("frontend-quic-qlog-di"sv, name.substr(0, 21))) {
        return SHRPX_OPTID_FRONTEND_QUIC_QLOG_DIR;
      }
      break;
    case 't':
      if (util::strieq("frontend-write-timeou"sv, name.substr(0, 21))) {
        return SHRPX_OPTID_FRONTEND_WRITE_TIMEOUT;
      }
      break;
    case 'y':
      if (util::strieq("backend-address-famil"sv, name.substr(0, 21))) {
        return SHRPX_OPTID_BACKEND_ADDRESS_FAMILY;
      }
      break;
    }
    break;
  case 23:
    switch (name[22]) {
    case 'e':
      if (util::strieq("client-private-key-fil"sv, name.substr(0, 22))) {
        return SHRPX_OPTID_CLIENT_PRIVATE_KEY_FILE;
      }
      if (util::strieq("frontend-min-write-rat"sv, name.substr(0, 22))) {
        return SHRPX_OPTID_FRONTEND_MIN_WRITE_RATE;
      }
      if (util::strieq("private-key-passwd-fil"sv, name.substr(0, 22))) {
        return SHRPX_OPTID_PRIVATE_KEY_PASSWD_FILE;
      }
      break;
    case 'g':
      if (util::strieq("frontend-quic-debug-lo"sv, name.substr(0, 22))) {
        return SHRPX_OPTID_FRONTEND_QUIC_DEBUG_LOG;
      }
      break;
    case 'r':
      if (util::strieq("backend-response-buffe"sv, name.substr(0, 22))) {
        return SHRPX_OPTID_BACKEND_RESPONSE_BUFFER;
      }
      break;
    case 't':
      if (util::strieq("backend-connect-timeou"sv, name.substr(0, 22))) {
        return SHRPX_OPTID_BACKEND_CONNECT_TIMEOUT;
      }
      if (util::strieq("frontend-header-timeou"sv, name.substr(0, 22))) {
        return SHRPX_OPTID_FRONTEND_HEADER_TIMEOUT;
      }
      break;
    }
    break;
  case 24:
    switch (name[23]) {
    case 'a':
      if (util::strieq("frontend-quic-early-dat"sv, name.substr(0, 23))) {
        return SHRPX_OPTID_FRONTEND_QUIC_EARLY_DATA;
      }
      break;
    case 'd':
      if (util::strieq("strip-incoming-forwarde"sv, name.substr(0, 23))) {
        return SHRPX_OPTID_STRIP_INCOMING_FORWARDED;
      }
      if (util::strieq("tls-ticket-key-memcache"sv, name.substr(0, 23))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED;
      }
      break;
    case 'e':
      if (util::strieq("fetch-ocsp-response-fil"sv, name.substr(0, 23))) {
        return SHRPX_OPTID_FETCH_OCSP_RESPONSE_FILE;
      }
      break;
    case 'o':
      if (util::strieq("no-add-x-forwarded-prot"sv, name.substr(0, 23))) {
        return SHRPX_OPTID_NO_ADD_X_FORWARDED_PROTO;
      }
      break;
    case 't':
      if (util::strieq("listener-disable-timeou"sv, name.substr(0, 23))) {
        return SHRPX_OPTID_LISTENER_DISABLE_TIMEOUT;
      }
      if (util::strieq("tls-dyn-rec-idle-timeou"sv, name.substr(0, 23))) {
        return SHRPX_OPTID_TLS_DYN_REC_IDLE_TIMEOUT;
      }
      break;
    }
    break;
  case 25:
    switch (name[24]) {
    case 'e':
      if (util::strieq("backend-http2-window-siz"sv, name.substr(0, 24))) {
        return SHRPX_OPTID_BACKEND_HTTP2_WINDOW_SIZE;
      }
      if (util::strieq("frontend-quic-secret-fil"sv, name.substr(0, 24))) {
        return SHRPX_OPTID_FRONTEND_QUIC_SECRET_FILE;
      }
      break;
    case 'g':
      if (util::strieq("http2-no-cookie-crumblin"sv, name.substr(0, 24))) {
        return SHRPX_OPTID_HTTP2_NO_COOKIE_CRUMBLING;
      }
      break;
    case 's':
      if (util::strieq("backend-http2-window-bit"sv, name.substr(0, 24))) {
        return SHRPX_OPTID_BACKEND_HTTP2_WINDOW_BITS;
      }
      if (util::strieq("max-request-header-field"sv, name.substr(0, 24))) {
        return SHRPX_OPTID_MAX_REQUEST_HEADER_FIELDS;
      }
      break;
    case 't':
      if (util::strieq("frontend-quic-initial-rt"sv, name.substr(0, 24))) {
        return SHRPX_OPTID_FRONTEND_QUIC_INITIAL_RTT;
      }
      break;
    }
    break;
  case 26:
    switch (name[25]) {
    case 'a':
      if (util::strieq("tls-no-postpone-early-dat"sv, name.substr(0, 25))) {
        return SHRPX_OPTID_TLS_NO_POSTPONE_EARLY_DATA;
      }
      break;
    case 'e':
      if (util::strieq("frontend-http2-window-siz"sv, name.substr(0, 25))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_SIZE;
      }
      if (util::strieq("frontend-http3-window-siz"sv, name.substr(0, 25))) {
        return SHRPX_OPTID_FRONTEND_HTTP3_WINDOW_SIZE;
      }
      break;
    case 's':
      if (util::strieq("frontend-http2-window-bit"sv, name.substr(0, 25))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_BITS;
      }
      if (util::strieq("max-response-header-field"sv, name.substr(0, 25))) {
        return SHRPX_OPTID_MAX_RESPONSE_HEADER_FIELDS;
      }
      break;
    case 't':
      if (util::strieq("backend-keep-alive-timeou"sv, name.substr(0, 25))) {
        return SHRPX_OPTID_BACKEND_KEEP_ALIVE_TIMEOUT;
      }
      if (util::strieq("frontend-quic-idle-timeou"sv, name.substr(0, 25))) {
        return SHRPX_OPTID_FRONTEND_QUIC_IDLE_TIMEOUT;
      }
      if (util::strieq("no-http2-cipher-black-lis"sv, name.substr(0, 25))) {
        return SHRPX_OPTID_NO_HTTP2_CIPHER_BLACK_LIST;
      }
      if (util::strieq("no-http2-cipher-block-lis"sv, name.substr(0, 25))) {
        return SHRPX_OPTID_NO_HTTP2_CIPHER_BLOCK_LIST;
      }
      break;
    }
    break;
  case 27:
    switch (name[26]) {
    case 'd':
      if (util::strieq("tls-session-cache-memcache"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED;
      }
      break;
    case 'n':
      if (util::strieq("frontend-quic-require-toke"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_FRONTEND_QUIC_REQUIRE_TOKEN;
      }
      break;
    case 'r':
      if (util::strieq("request-header-field-buffe"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_REQUEST_HEADER_FIELD_BUFFER;
      }
      break;
    case 's':
      if (util::strieq("worker-frontend-connection"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_WORKER_FRONTEND_CONNECTIONS;
      }
      break;
    case 't':
      if (util::strieq("backend-stream-read-timeou"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_BACKEND_STREAM_READ_TIMEOUT;
      }
      if (util::strieq("frontend-http2-idle-timeou"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_IDLE_TIMEOUT;
      }
      if (util::strieq("frontend-http2-read-timeou"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_READ_TIMEOUT;
      }
      if (util::strieq("frontend-http3-idle-timeou"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_FRONTEND_HTTP3_IDLE_TIMEOUT;
      }
      if (util::strieq("frontend-http3-read-timeou"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_FRONTEND_HTTP3_READ_TIMEOUT;
      }
      if (util::strieq("frontend-keep-alive-timeou"sv, name.substr(0, 26))) {
        return SHRPX_OPTID_FRONTEND_KEEP_ALIVE_TIMEOUT;
      }
      break;
    }
    break;
  case 28:
    switch (name[27]) {
    case 'a':
      if (util::strieq("no-strip-incoming-early-dat"sv, name.substr(0, 27))) {
        return SHRPX_OPTID_NO_STRIP_INCOMING_EARLY_DATA;
      }
      break;
    case 'd':
      if (util::strieq("tls-dyn-rec-warmup-threshol"sv, name.substr(0, 27))) {
        return SHRPX_OPTID_TLS_DYN_REC_WARMUP_THRESHOLD;
      }
      break;
    case 'r':
      if (util::strieq("response-header-field-buffe"sv, name.substr(0, 27))) {
        return SHRPX_OPTID_RESPONSE_HEADER_FIELD_BUFFER;
      }
      break;
    case 's':
      if (util::strieq("http2-max-concurrent-stream"sv, name.substr(0, 27))) {
        return SHRPX_OPTID_HTTP2_MAX_CONCURRENT_STREAMS;
      }
      if (util::strieq("tls-ticket-key-memcached-tl"sv, name.substr(0, 27))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_TLS;
      }
      break;
    case 't':
      if (util::strieq("backend-connections-per-hos"sv, name.substr(0, 27))) {
        return SHRPX_OPTID_BACKEND_CONNECTIONS_PER_HOST;
      }
      if (util::strieq("backend-stream-write-timeou"sv, name.substr(0, 27))) {
        return SHRPX_OPTID_BACKEND_STREAM_WRITE_TIMEOUT;
      }
      if (util::strieq("frontend-stream-read-timeou"sv, name.substr(0, 27))) {
        return SHRPX_OPTID_FRONTEND_STREAM_READ_TIMEOUT;
      }
      break;
    }
    break;
  case 29:
    switch (name[28]) {
    case 't':
      if (util::strieq("frontend-stream-write-timeou"sv, name.substr(0, 28))) {
        return SHRPX_OPTID_FRONTEND_STREAM_WRITE_TIMEOUT;
      }
      break;
    }
    break;
  case 30:
    switch (name[29]) {
    case 'd':
      if (util::strieq("verify-client-tolerate-expire"sv, name.substr(0, 29))) {
        return SHRPX_OPTID_VERIFY_CLIENT_TOLERATE_EXPIRED;
      }
      break;
    case 'e':
      if (util::strieq("frontend-http3-max-window-siz"sv, name.substr(0, 29))) {
        return SHRPX_OPTID_FRONTEND_HTTP3_MAX_WINDOW_SIZE;
      }
      break;
    case 'r':
      if (util::strieq("ignore-per-pattern-mruby-erro"sv, name.substr(0, 29))) {
        return SHRPX_OPTID_IGNORE_PER_PATTERN_MRUBY_ERROR;
      }
      if (util::strieq("strip-incoming-x-forwarded-fo"sv, name.substr(0, 29))) {
        return SHRPX_OPTID_STRIP_INCOMING_X_FORWARDED_FOR;
      }
      break;
    case 't':
      if (util::strieq("backend-http2-settings-timeou"sv, name.substr(0, 29))) {
        return SHRPX_OPTID_BACKEND_HTTP2_SETTINGS_TIMEOUT;
      }
      break;
    }
    break;
  case 31:
    switch (name[30]) {
    case 's':
      if (util::strieq("tls-session-cache-memcached-tl"sv,
                       name.substr(0, 30))) {
        return SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED_TLS;
      }
      break;
    case 't':
      if (util::strieq("frontend-http2-settings-timeou"sv,
                       name.substr(0, 30))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_SETTINGS_TIMEOUT;
      }
      if (util::strieq("frontend-max-write-rate-timeou"sv,
                       name.substr(0, 30))) {
        return SHRPX_OPTID_FRONTEND_MAX_WRITE_RATE_TIMEOUT;
      }
      break;
    }
    break;
  case 32:
    switch (name[31]) {
    case 'd':
      if (util::strieq("backend-connections-per-fronten"sv,
                       name.substr(0, 31))) {
        return SHRPX_OPTID_BACKEND_CONNECTIONS_PER_FRONTEND;
      }
      break;
    }
    break;
  case 33:
    switch (name[32]) {
    case 'l':
      if (util::strieq("tls-ticket-key-memcached-interva"sv,
                       name.substr(0, 32))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_INTERVAL;
      }
      if (util::strieq("tls-ticket-key-memcached-max-fai"sv,
                       name.substr(0, 32))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_FAIL;
      }
      break;
    case 't':
      if (util::strieq("client-no-http2-cipher-black-lis"sv,
                       name.substr(0, 32))) {
        return SHRPX_OPTID_CLIENT_NO_HTTP2_CIPHER_BLACK_LIST;
      }
      if (util::strieq("client-no-http2-cipher-block-lis"sv,
                       name.substr(0, 32))) {
        return SHRPX_OPTID_CLIENT_NO_HTTP2_CIPHER_BLOCK_LIST;
      }
      break;
    }
    break;
  case 34:
    switch (name[33]) {
    case 'e':
      if (util::strieq("tls-ticket-key-memcached-cert-fil"sv,
                       name.substr(0, 33))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_CERT_FILE;
      }
      break;
    case 'r':
      if (util::strieq("frontend-http2-dump-request-heade"sv,
                       name.substr(0, 33))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_DUMP_REQUEST_HEADER;
      }
      break;
    case 't':
      if (util::strieq("backend-http1-connections-per-hos"sv,
                       name.substr(0, 33))) {
        return SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_HOST;
      }
      break;
    case 'y':
      if (util::strieq("tls-ticket-key-memcached-max-retr"sv,
                       name.substr(0, 33))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_RETRY;
      }
      break;
    }
    break;
  case 35:
    switch (name[34]) {
    case 'e':
      if (util::strieq("frontend-http2-optimize-window-siz"sv,
                       name.substr(0, 34))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_OPTIMIZE_WINDOW_SIZE;
      }
      break;
    case 'o':
      if (util::strieq("no-strip-incoming-x-forwarded-prot"sv,
                       name.substr(0, 34))) {
        return SHRPX_OPTID_NO_STRIP_INCOMING_X_FORWARDED_PROTO;
      }
      break;
    case 'r':
      if (util::strieq("frontend-http2-dump-response-heade"sv,
                       name.substr(0, 34))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_DUMP_RESPONSE_HEADER;
      }
      if (util::strieq("frontend-quic-congestion-controlle"sv,
                       name.substr(0, 34))) {
        return SHRPX_OPTID_FRONTEND_QUIC_CONGESTION_CONTROLLER;
      }
      break;
    case 't':
      if (util::strieq("frontend-initial-write-rate-timeou"sv,
                       name.substr(0, 34))) {
        return SHRPX_OPTID_FRONTEND_INITIAL_WRITE_RATE_TIMEOUT;
      }
      break;
    }
    break;
  case 36:
    switch (name[35]) {
    case 'd':
      if (util::strieq("worker-process-grace-shutdown-perio"sv,
                       name.substr(0, 35))) {
        return SHRPX_OPTID_WORKER_PROCESS_GRACE_SHUTDOWN_PERIOD;
      }
      break;
    case 'e':
      if (util::strieq("backend-http2-connection-window-siz"sv,
                       name.substr(0, 35))) {
        return SHRPX_OPTID_BACKEND_HTTP2_CONNECTION_WINDOW_SIZE;
      }
      break;
    case 'r':
      if (util::strieq("backend-http2-connections-per-worke"sv,
                       name.substr(0, 35))) {
        return SHRPX_OPTID_BACKEND_HTTP2_CONNECTIONS_PER_WORKER;
      }
      break;
    case 's':
      if (util::strieq("backend-http2-connection-window-bit"sv,
                       name.substr(0, 35))) {
        return SHRPX_OPTID_BACKEND_HTTP2_CONNECTION_WINDOW_BITS;
      }
      if (util::strieq("backend-http2-max-concurrent-stream"sv,
                       name.substr(0, 35))) {
        return SHRPX_OPTID_BACKEND_HTTP2_MAX_CONCURRENT_STREAMS;
      }
      break;
    }
    break;
  case 37:
    switch (name[36]) {
    case 'e':
      if (util::strieq("frontend-http2-connection-window-siz"sv,
                       name.substr(0, 36))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_SIZE;
      }
      if (util::strieq("frontend-http3-connection-window-siz"sv,
                       name.substr(0, 36))) {
        return SHRPX_OPTID_FRONTEND_HTTP3_CONNECTION_WINDOW_SIZE;
      }
      if (util::strieq("tls-session-cache-memcached-cert-fil"sv,
                       name.substr(0, 36))) {
        return SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED_CERT_FILE;
      }
      break;
    case 's':
      if (util::strieq("frontend-http2-connection-window-bit"sv,
                       name.substr(0, 36))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS;
      }
      if (util::strieq("frontend-http2-max-concurrent-stream"sv,
                       name.substr(0, 36))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_MAX_CONCURRENT_STREAMS;
      }
      if (util::strieq("frontend-http3-max-concurrent-stream"sv,
                       name.substr(0, 36))) {
        return SHRPX_OPTID_FRONTEND_HTTP3_MAX_CONCURRENT_STREAMS;
      }
      break;
    }
    break;
  case 38:
    switch (name[37]) {
    case 'd':
      if (util::strieq("backend-http1-connections-per-fronten"sv,
                       name.substr(0, 37))) {
        return SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_FRONTEND;
      }
      break;
    }
    break;
  case 39:
    switch (name[38]) {
    case 'y':
      if (util::strieq("tls-ticket-key-memcached-address-famil"sv,
                       name.substr(0, 38))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_ADDRESS_FAMILY;
      }
      break;
    }
    break;
  case 40:
    switch (name[39]) {
    case 'e':
      if (util::strieq("backend-http2-decoder-dynamic-table-siz"sv,
                       name.substr(0, 39))) {
        return SHRPX_OPTID_BACKEND_HTTP2_DECODER_DYNAMIC_TABLE_SIZE;
      }
      if (util::strieq("backend-http2-encoder-dynamic-table-siz"sv,
                       name.substr(0, 39))) {
        return SHRPX_OPTID_BACKEND_HTTP2_ENCODER_DYNAMIC_TABLE_SIZE;
      }
      break;
    }
    break;
  case 41:
    switch (name[40]) {
    case 'e':
      if (util::strieq("frontend-http2-decoder-dynamic-table-siz"sv,
                       name.substr(0, 40))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_DECODER_DYNAMIC_TABLE_SIZE;
      }
      if (util::strieq("frontend-http2-encoder-dynamic-table-siz"sv,
                       name.substr(0, 40))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_ENCODER_DYNAMIC_TABLE_SIZE;
      }
      if (util::strieq("frontend-http2-optimize-write-buffer-siz"sv,
                       name.substr(0, 40))) {
        return SHRPX_OPTID_FRONTEND_HTTP2_OPTIMIZE_WRITE_BUFFER_SIZE;
      }
      if (util::strieq("frontend-http3-max-connection-window-siz"sv,
                       name.substr(0, 40))) {
        return SHRPX_OPTID_FRONTEND_HTTP3_MAX_CONNECTION_WINDOW_SIZE;
      }
      if (util::strieq("tls-ticket-key-memcached-private-key-fil"sv,
                       name.substr(0, 40))) {
        return SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_PRIVATE_KEY_FILE;
      }
      break;
    }
    break;
  case 42:
    switch (name[41]) {
    case 'y':
      if (util::strieq("tls-session-cache-memcached-address-famil"sv,
                       name.substr(0, 41))) {
        return SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED_ADDRESS_FAMILY;
      }
      break;
    }
    break;
  case 44:
    switch (name[43]) {
    case 'e':
      if (util::strieq("tls-session-cache-memcached-private-key-fil"sv,
                       name.substr(0, 43))) {
        return SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED_PRIVATE_KEY_FILE;
      }
      break;
    }
    break;
  }
  return -1;
}

std::expected<void, Error> parse_config(
  Config *config, std::string_view opt, std::string_view optarg,
  std::unordered_set<std::string_view> &included_set,
  std::unordered_map<std::string_view, size_t> &pattern_addr_indexer) {
  auto optid = option_lookup_token(opt);
  return parse_config(config, optid, opt, optarg, included_set,
                      pattern_addr_indexer);
}

std::expected<void, Error> parse_config(
  Config *config, int optid, std::string_view opt, std::string_view optarg,
  std::unordered_set<std::string_view> &included_set,
  std::unordered_map<std::string_view, size_t> &pattern_addr_indexer) {
  std::array<char, STRERROR_BUFSIZE> errbuf;

  switch (optid) {
  case SHRPX_OPTID_BACKEND: {
    auto &downstreamconf = *config->conn.downstream;
    auto addr_end = std::ranges::find(optarg, ';');

    DownstreamAddrConfig addr{};
    if (util::istarts_with(optarg, SHRPX_UNIX_PATH_PREFIX)) {
      auto path = std::ranges::begin(optarg) + SHRPX_UNIX_PATH_PREFIX.size();
      addr.host = make_string_ref(downstreamconf.balloc,
                                  std::string_view{path, addr_end});
      addr.host_unix = true;
    } else {
      auto maybe_hp = split_host_port(
        downstreamconf.balloc,
        std::string_view{std::ranges::begin(optarg), addr_end}, opt);
      if (!maybe_hp) {
        return std::unexpected{maybe_hp.error()};
      }

      const auto &hp = *maybe_hp;

      addr.host = hp.host;
      addr.port = hp.port;
    }

    auto mapping =
      addr_end == std::ranges::end(optarg) ? addr_end : addr_end + 1;
    auto mapping_end =
      std::ranges::find(mapping, std::ranges::end(optarg), ';');

    auto params =
      mapping_end == std::ranges::end(optarg) ? mapping_end : mapping_end + 1;

    if (auto rv =
          parse_mapping(config, addr, pattern_addr_indexer,
                        std::string_view{mapping, mapping_end},
                        std::string_view{params, std::ranges::end(optarg)});
        !rv) {
      return rv;
    }

    return {};
  }
  case SHRPX_OPTID_FRONTEND: {
    auto &apiconf = config->api;

    auto addr_end = std::ranges::find(optarg, ';');
    auto src_params = std::string_view{addr_end, std::ranges::end(optarg)};

    auto maybe_params = parse_upstream_params(src_params);
    if (!maybe_params) {
      return std::unexpected{maybe_params.error()};
    }

    const auto &params = *maybe_params;

    if (params.sni_fwd && !params.tls) {
      Log{ERROR} << "frontend: sni_fwd requires tls";
      return std::unexpected{Error::INVALID_CONFIG};
    }

    if (params.quic) {
      if (params.alt_mode != UpstreamAltMode::NONE) {
        Log{ERROR} << "frontend: api or healthmon cannot be used with quic";
        return std::unexpected{Error::INVALID_CONFIG};
      }

      if (!params.tls) {
        Log{ERROR} << "frontend: quic requires TLS";
        return std::unexpected{Error::INVALID_CONFIG};
      }
    }

    UpstreamAddr addr{
      .alt_mode = params.alt_mode,
      .tls = params.tls,
      .sni_fwd = params.sni_fwd,
      .accept_proxy_protocol = params.proxyproto,
      .quic = params.quic,
      .fd = -1,
    };

    if (addr.alt_mode == UpstreamAltMode::API) {
      apiconf.enabled = true;
    }

#ifdef ENABLE_HTTP3
    auto &addrs = params.quic ? config->conn.quic_listener.addrs
                              : config->conn.listener.addrs;
#else  // !defined(ENABLE_HTTP3)
    auto &addrs = config->conn.listener.addrs;
#endif // !defined(ENABLE_HTTP3)

    if (util::istarts_with(optarg, SHRPX_UNIX_PATH_PREFIX)) {
      if (addr.quic) {
        Log{ERROR} << "frontend: quic cannot be used on UNIX domain socket";
        return std::unexpected{Error::INVALID_CONFIG};
      }

      auto path = std::ranges::begin(optarg) + SHRPX_UNIX_PATH_PREFIX.size();
      addr.host =
        make_string_ref(config->balloc, std::string_view{path, addr_end});
      addr.host_unix = true;
      addr.index = addrs.size();

      addrs.push_back(std::move(addr));

      return {};
    }

    auto maybe_hp = split_host_port(
      config->balloc, std::string_view{std::ranges::begin(optarg), addr_end},
      opt);
    if (!maybe_hp) {
      return std::unexpected{maybe_hp.error()};
    }

    const auto &hp = *maybe_hp;

    addr.host = hp.host;
    addr.port = hp.port;

    if (util::numeric_host(addr.host.data(), AF_INET)) {
      addr.family = AF_INET;
      addr.index = addrs.size();
      addrs.push_back(std::move(addr));
      return {};
    }

    if (util::numeric_host(addr.host.data(), AF_INET6)) {
      addr.family = AF_INET6;
      addr.index = addrs.size();
      addrs.push_back(std::move(addr));
      return {};
    }

    addr.family = AF_INET;
    addr.index = addrs.size();
    addrs.push_back(addr);

    addr.family = AF_INET6;
    addr.index = addrs.size();
    addrs.push_back(std::move(addr));

    return {};
  }
  case SHRPX_OPTID_WORKERS:
#ifdef NOTHREADS
    Log{WARN} << "Threading disabled at build time, no threads created.";
    return {};
#else  // !defined(NOTHREADS)
    return parse_uint<size_t>(opt, optarg)
      .and_then([config, opt](auto &&r) -> std::expected<void, Error> {
        if (r > 65530) {
          Log{ERROR} << opt << ": the number of workers must not exceed 65530";

          return std::unexpected{Error::INVALID_CONFIG};
        }

        config->num_worker = r;

        return {};
      });
#endif // !defined(NOTHREADS)
  case SHRPX_OPTID_HTTP2_MAX_CONCURRENT_STREAMS:
    Log{WARN} << opt << ": deprecated. Use "
              << SHRPX_OPT_FRONTEND_HTTP2_MAX_CONCURRENT_STREAMS << " and "
              << SHRPX_OPT_BACKEND_HTTP2_MAX_CONCURRENT_STREAMS << " instead.";

    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      auto &http2conf = config->http2;
      http2conf.upstream.max_concurrent_streams = r;
      http2conf.downstream.max_concurrent_streams = r;
    });
  case SHRPX_OPTID_LOG_LEVEL:
    return Log::get_severity_level_by_name(optarg)
      .transform([config](auto &&r) { config->logging.severity = r; })
      .transform_error([opt, optarg](auto &&err) {
        Log{ERROR} << opt << ": Invalid severity level: " << optarg;

        return err;
      });
  case SHRPX_OPTID_DAEMON:
    config->daemon = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_HTTP2_PROXY:
    config->http2_proxy = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_HTTP2_BRIDGE:
    Log{ERROR} << opt
               << ": deprecated.  Use backend=<addr>,<port>;;proto=h2;tls";
    return std::unexpected{Error::INVALID_CONFIG};
  case SHRPX_OPTID_CLIENT_PROXY:
    Log{ERROR}
      << opt
      << ": deprecated.  Use http2-proxy, frontend=<addr>,<port>;no-tls "
         "and backend=<addr>,<port>;;proto=h2;tls";
    return std::unexpected{Error::INVALID_CONFIG};
  case SHRPX_OPTID_ADD_X_FORWARDED_FOR:
    config->http.xff.add = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_STRIP_INCOMING_X_FORWARDED_FOR:
    config->http.xff.strip_incoming = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_NO_VIA:
    config->http.no_via = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_FRONTEND_HTTP2_READ_TIMEOUT:
    Log{WARN} << opt << ": deprecated.  Use frontend-http2-idle-timeout";
    // fall through
  case SHRPX_OPTID_FRONTEND_HTTP2_IDLE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.upstream.timeout.http2_idle = r;
    });
  case SHRPX_OPTID_FRONTEND_READ_TIMEOUT:
    Log{WARN} << opt << ": deprecated.  Use frontend-header-timeout";

    return {};
  case SHRPX_OPTID_FRONTEND_HEADER_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http.timeout.header = r;
    });
  case SHRPX_OPTID_FRONTEND_WRITE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.upstream.timeout.write = r;
    });
  case SHRPX_OPTID_BACKEND_READ_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.downstream->timeout.read = r;
    });
  case SHRPX_OPTID_BACKEND_WRITE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.downstream->timeout.write = r;
    });
  case SHRPX_OPTID_BACKEND_CONNECT_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.downstream->timeout.connect = r;
    });
  case SHRPX_OPTID_STREAM_READ_TIMEOUT:
    Log{WARN} << opt
              << ": deprecated.  Use --frontend-stream-read-timeout and "
                 "--backend-stream-read-timeout";

    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http.upstream.timeout.stream_read = r;
      config->http.downstream.timeout.stream_read = r;
    });
  case SHRPX_OPTID_STREAM_WRITE_TIMEOUT:
    Log{WARN} << opt
              << ": deprecated.  Use --frontend-stream-write-timeout and "
                 "--backend-stream-write-timeout";

    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http.upstream.timeout.stream_write = r;
      config->http.downstream.timeout.stream_write = r;
    });
  case SHRPX_OPTID_ACCESSLOG_FILE:
    config->logging.access.file = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_ACCESSLOG_SYSLOG:
    config->logging.access.syslog = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_ACCESSLOG_FORMAT:
    config->logging.access.format = parse_log_format(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_ERRORLOG_FILE:
    config->logging.error.file = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_ERRORLOG_SYSLOG:
    config->logging.error.syslog = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_FASTOPEN:
    return parse_uint<int>(opt, optarg).transform([config](auto &&r) {
      config->conn.listener.fastopen = r;
    });
  case SHRPX_OPTID_BACKEND_KEEP_ALIVE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.downstream->timeout.idle_read = r;
    });
  case SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_BITS:
  case SHRPX_OPTID_BACKEND_HTTP2_WINDOW_BITS: {
    Log{WARN} << opt << ": deprecated.  Use "
              << (optid == SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_BITS
                    ? SHRPX_OPT_FRONTEND_HTTP2_WINDOW_SIZE
                    : SHRPX_OPT_BACKEND_HTTP2_WINDOW_SIZE);
    int32_t *resp;

    if (optid == SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_BITS) {
      resp = &config->http2.upstream.window_size;
    } else {
      resp = &config->http2.downstream.window_size;
    }

    return parse_uint<uint32_t>(opt, optarg)
      .and_then([resp, opt](auto &&r) -> std::expected<void, Error> {
        if (r >= 31) {
          Log{ERROR} << opt
                     << ": specify the integer in the range [0, 30], inclusive";
          return std::unexpected{Error::INVALID_CONFIG};
        }

        // Make 16 bits to the HTTP/2 default 64KiB - 1.  This is the
        // same behaviour of previous code.
        *resp = (1 << r) - 1;

        return {};
      });
  }
  case SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS:
  case SHRPX_OPTID_BACKEND_HTTP2_CONNECTION_WINDOW_BITS: {
    Log{WARN} << opt << ": deprecated.  Use "
              << (optid == SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS
                    ? SHRPX_OPT_FRONTEND_HTTP2_CONNECTION_WINDOW_SIZE
                    : SHRPX_OPT_BACKEND_HTTP2_CONNECTION_WINDOW_SIZE);
    int32_t *resp;

    if (optid == SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS) {
      resp = &config->http2.upstream.connection_window_size;
    } else {
      resp = &config->http2.downstream.connection_window_size;
    }

    return parse_uint<uint32_t>(opt, optarg)
      .and_then([resp, opt](auto &&r) -> std::expected<void, Error> {
        if (r < 16 || r >= 31) {
          Log{ERROR}
            << opt << ": specify the integer in the range [16, 30], inclusive";
          return std::unexpected{Error::INVALID_CONFIG};
        }

        *resp = (1 << r) - 1;

        return {};
      });
  }
  case SHRPX_OPTID_FRONTEND_NO_TLS:
    Log{WARN} << opt << ": deprecated.  Use no-tls keyword in "
              << SHRPX_OPT_FRONTEND;
    return {};
  case SHRPX_OPTID_BACKEND_NO_TLS:
    Log{WARN} << opt
              << ": deprecated.  backend connection is not encrypted by "
                 "default.  See also "
              << SHRPX_OPT_BACKEND_TLS;
    return {};
  case SHRPX_OPTID_BACKEND_TLS_SNI_FIELD:
    Log{WARN} << opt
              << ": deprecated.  Use sni keyword in --backend option.  "
                 "For now, all sni values of all backends are "
                 "overridden by the given value "
              << optarg;
    config->tls.backend_sni_name = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_PID_FILE:
    config->pid_file = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_USER: {
    auto pwd = getpwnam(optarg.data());
    if (!pwd) {
      Log{ERROR} << opt << ": failed to get uid from " << optarg << ": "
                 << xsi_strerror(errno, errbuf.data(), errbuf.size());
      return std::unexpected{Error::LIBC};
    }
    config->user =
      make_string_ref(config->balloc, std::string_view{pwd->pw_name});
    config->uid = pwd->pw_uid;
    config->gid = pwd->pw_gid;

    return {};
  }
  case SHRPX_OPTID_PRIVATE_KEY_FILE:
    config->tls.private_key_file = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_PRIVATE_KEY_PASSWD_FILE:
    return read_passwd_from_file(opt, optarg)
      .transform([config](auto &&r) {
        config->tls.private_key_passwd =
          make_string_ref(config->balloc, std::forward<decltype(r)>(r));
      })
      .transform_error([opt, optarg](auto &&err) {
        Log{ERROR} << opt << ": Couldn't read key file's passwd from "
                   << optarg;

        return err;
      });
  case SHRPX_OPTID_CERTIFICATE_FILE:
    config->tls.cert_file = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_DH_PARAM_FILE:
    config->tls.dh_param_file = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_SUBCERT: {
    auto end_keys = std::ranges::find(optarg, ';');
    auto src_params = std::string_view{end_keys, std::ranges::end(optarg)};

    auto maybe_params = parse_subcert_params(src_params);
    if (!maybe_params) {
      return std::unexpected{maybe_params.error()};
    }

    const auto &params = *maybe_params;

    std::vector<uint8_t> sct_data;

    if (!params.sct_dir.empty()) {
      // Make sure that dir_path is NULL terminated string.
      auto maybe_sct_data =
        read_tls_sct_from_dir(opt, std::string{params.sct_dir});
      if (!maybe_sct_data) {
        return std::unexpected{maybe_sct_data.error()};
      }

      sct_data = std::move(*maybe_sct_data);
    }

    // Private Key file and certificate file separated by ':'.
    auto sp = std::ranges::find(std::ranges::begin(optarg), end_keys, ':');
    if (sp == end_keys) {
      Log{ERROR} << opt << ": missing ':' in "
                 << std::string_view{std::ranges::begin(optarg), end_keys};
      return std::unexpected{Error::INVALID_CONFIG};
    }

    auto private_key_file = std::string_view{std::ranges::begin(optarg), sp};

    if (private_key_file.empty()) {
      Log{ERROR} << opt << ": missing private key file: "
                 << std::string_view{std::ranges::begin(optarg), end_keys};
      return std::unexpected{Error::INVALID_CONFIG};
    }

    auto cert_file = std::string_view{sp + 1, end_keys};

    if (cert_file.empty()) {
      Log{ERROR} << opt << ": missing certificate file: "
                 << std::string_view{std::ranges::begin(optarg), end_keys};
      return std::unexpected{Error::INVALID_CONFIG};
    }

    config->tls.subcerts.emplace_back(
      make_string_ref(config->balloc, private_key_file),
      make_string_ref(config->balloc, cert_file), std::move(sct_data));

    return {};
  }
  case SHRPX_OPTID_SYSLOG_FACILITY:
    return int_syslog_facility(optarg)
      .transform([config](auto &&r) { config->logging.syslog_facility = r; })
      .transform_error([opt, optarg](auto &&err) {
        Log{ERROR} << opt << ": Unknown syslog facility: " << optarg;

        return err;
      });
  case SHRPX_OPTID_BACKLOG:
    return parse_uint<int>(opt, optarg).transform([config](auto &&r) {
      config->conn.listener.backlog = r;
    });
  case SHRPX_OPTID_CIPHERS:
    config->tls.ciphers = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_TLS13_CIPHERS:
    config->tls.tls13_ciphers = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_CLIENT:
    Log{ERROR} << opt
               << ": deprecated.  Use frontend=<addr>,<port>;no-tls, "
                  "backend=<addr>,<port>;;proto=h2;tls";
    return std::unexpected{Error::INVALID_CONFIG};
  case SHRPX_OPTID_INSECURE:
    config->tls.insecure = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_CACERT:
    config->tls.cacert = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_BACKEND_IPV4:
    Log{WARN} << opt
              << ": deprecated.  Use backend-address-family=IPv4 instead.";

    config->conn.downstream->family = AF_INET;

    return {};
  case SHRPX_OPTID_BACKEND_IPV6:
    Log{WARN} << opt
              << ": deprecated.  Use backend-address-family=IPv6 instead.";

    config->conn.downstream->family = AF_INET6;

    return {};
  case SHRPX_OPTID_BACKEND_HTTP_PROXY_URI: {
    auto &proxy = config->downstream_http_proxy;
    // Reset here so that multiple option occurrence does not merge
    // the results.
    proxy = {};
    // parse URI and get hostname, port and optionally userinfo.
    urlparse_url u;
    int rv = urlparse_parse_url(optarg.data(), optarg.size(), 0, &u);
    if (rv == 0) {
      if (u.field_set & URLPARSE_USERINFO) {
        auto uf = util::get_uri_field(optarg.data(), u, URLPARSE_USERINFO);
        // Surprisingly, u.field_set & URLPARSE_USERINFO is nonzero even if
        // userinfo component is empty string.
        if (!uf.empty()) {
          proxy.userinfo = util::percent_decode(config->balloc, uf);
        }
      }
      if (u.field_set & URLPARSE_HOST) {
        proxy.host = make_string_ref(
          config->balloc, util::get_uri_field(optarg.data(), u, URLPARSE_HOST));
      } else {
        Log{ERROR} << opt << ": no hostname specified";
        return std::unexpected{Error::INVALID_CONFIG};
      }
      if (u.field_set & URLPARSE_PORT) {
        proxy.port = u.port;
      } else {
        Log{ERROR} << opt << ": no port specified";
        return std::unexpected{Error::INVALID_CONFIG};
      }
    } else {
      Log{ERROR} << opt << ": parse error";
      return std::unexpected{Error::INVALID_CONFIG};
    }

    return {};
  }
  case SHRPX_OPTID_READ_RATE:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->conn.upstream.ratelimit.read.rate = r; });
  case SHRPX_OPTID_READ_BURST:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->conn.upstream.ratelimit.read.burst = r; });
  case SHRPX_OPTID_WRITE_RATE:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->conn.upstream.ratelimit.write.rate = r; });
  case SHRPX_OPTID_WRITE_BURST:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform([config](auto &&r) {
        config->conn.upstream.ratelimit.write.burst = r;
      });
  case SHRPX_OPTID_WORKER_READ_RATE:
    Log{WARN} << opt << ": not implemented yet";
    return {};
  case SHRPX_OPTID_WORKER_READ_BURST:
    Log{WARN} << opt << ": not implemented yet";
    return {};
  case SHRPX_OPTID_WORKER_WRITE_RATE:
    Log{WARN} << opt << ": not implemented yet";
    return {};
  case SHRPX_OPTID_WORKER_WRITE_BURST:
    Log{WARN} << opt << ": not implemented yet";
    return {};
  case SHRPX_OPTID_TLS_PROTO_LIST:
    Log{WARN} << opt
              << ": deprecated.  Use tls-min-proto-version and "
                 "tls-max-proto-version instead.";
    config->tls.tls_proto_list = util::split_str(config->balloc, optarg, ',');

    return {};
  case SHRPX_OPTID_VERIFY_CLIENT:
    config->tls.client_verify.enabled = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_VERIFY_CLIENT_CACERT:
    config->tls.client_verify.cacert = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_CLIENT_PRIVATE_KEY_FILE:
    config->tls.client.private_key_file =
      make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_CLIENT_CERT_FILE:
    config->tls.client.cert_file = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_FRONTEND_HTTP2_DUMP_REQUEST_HEADER:
    config->http2.upstream.debug.dump.request_header_file =
      make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_FRONTEND_HTTP2_DUMP_RESPONSE_HEADER:
    config->http2.upstream.debug.dump.response_header_file =
      make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_HTTP2_NO_COOKIE_CRUMBLING:
    config->http2.no_cookie_crumbling = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_FRONTEND_FRAME_DEBUG:
    config->http2.upstream.debug.frame_debug = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_PADDING:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->padding = r;
    });
  case SHRPX_OPTID_ALTSVC:
    return parse_altsvc(opt, optarg).transform([config](auto &&r) {
      config->http.altsvcs.emplace_back(std::forward<decltype(r)>(r));
    });
  case SHRPX_OPTID_ADD_REQUEST_HEADER:
  case SHRPX_OPTID_ADD_RESPONSE_HEADER: {
    auto maybe_hd = parse_header(config->balloc, optarg);
    if (!maybe_hd) {
      Log{ERROR} << opt << ": invalid header field: " << optarg;
      return std::unexpected{maybe_hd.error()};
    }
    if (optid == SHRPX_OPTID_ADD_REQUEST_HEADER) {
      config->http.add_request_headers.push_back(std::move(*maybe_hd));
    } else {
      config->http.add_response_headers.push_back(std::move(*maybe_hd));
    }
    return {};
  }
  case SHRPX_OPTID_WORKER_FRONTEND_CONNECTIONS:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->conn.upstream.worker_connections = r;
    });
  case SHRPX_OPTID_NO_LOCATION_REWRITE:
    config->http.no_location_rewrite = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_NO_HOST_REWRITE:
    Log{WARN} << SHRPX_OPT_NO_HOST_REWRITE
              << ": deprecated.  :authority and host header fields are NOT "
                 "altered by default.  To rewrite these headers, use "
                 "--host-rewrite option.";

    return {};
  case SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_HOST:
    Log{WARN} << opt
              << ": deprecated.  Use backend-connections-per-host instead.";
  // fall through
  case SHRPX_OPTID_BACKEND_CONNECTIONS_PER_HOST:
    return parse_uint<size_t>(opt, optarg)
      .and_then([config, opt](auto &&r) -> std::expected<void, Error> {
        if (r == 0) {
          Log{ERROR} << opt << ": specify an integer strictly more than 0";

          return std::unexpected{Error::INVALID_CONFIG};
        }

        config->conn.downstream->connections_per_host = r;

        return {};
      });
  case SHRPX_OPTID_BACKEND_HTTP1_CONNECTIONS_PER_FRONTEND:
    Log{WARN} << opt << ": deprecated.  Use "
              << SHRPX_OPT_BACKEND_CONNECTIONS_PER_FRONTEND << " instead.";
  // fall through
  case SHRPX_OPTID_BACKEND_CONNECTIONS_PER_FRONTEND:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->conn.downstream->connections_per_frontend = r;
    });
  case SHRPX_OPTID_LISTENER_DISABLE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.listener.timeout.sleep = r;
    });
  case SHRPX_OPTID_TLS_TICKET_KEY_FILE:
    config->tls.ticket.files.emplace_back(
      make_string_ref(config->balloc, optarg));
    return {};
  case SHRPX_OPTID_RLIMIT_NOFILE:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->rlimit_nofile = r;
    });
  case SHRPX_OPTID_BACKEND_REQUEST_BUFFER:
  case SHRPX_OPTID_BACKEND_RESPONSE_BUFFER:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .and_then([config, opt, optid](auto &&r) -> std::expected<void, Error> {
        if (r == 0) {
          Log{ERROR} << opt << ": specify an integer strictly more than 0";

          return std::unexpected{Error::INVALID_CONFIG};
        }

        if (optid == SHRPX_OPTID_BACKEND_REQUEST_BUFFER) {
          config->conn.downstream->request_buffer_size = r;
        } else {
          config->conn.downstream->response_buffer_size = r;
        }

        return {};
      });
  case SHRPX_OPTID_NO_SERVER_PUSH:
    config->http2.no_server_push = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_BACKEND_HTTP2_CONNECTIONS_PER_WORKER:
    Log{WARN} << opt << ": deprecated.";
    return {};
  case SHRPX_OPTID_FETCH_OCSP_RESPONSE_FILE:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_OCSP_UPDATE_INTERVAL:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_NO_OCSP:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_HEADER_FIELD_BUFFER:
    Log{WARN} << opt
              << ": deprecated.  Use request-header-field-buffer instead.";
  // fall through
  case SHRPX_OPTID_REQUEST_HEADER_FIELD_BUFFER:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->http.request_header_field_buffer = r; });
  case SHRPX_OPTID_MAX_HEADER_FIELDS:
    Log{WARN} << opt << ": deprecated.  Use max-request-header-fields instead.";
  // fall through
  case SHRPX_OPTID_MAX_REQUEST_HEADER_FIELDS:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->http.max_request_header_fields = r;
    });
  case SHRPX_OPTID_RESPONSE_HEADER_FIELD_BUFFER:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->http.response_header_field_buffer = r; });
  case SHRPX_OPTID_MAX_RESPONSE_HEADER_FIELDS:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->http.max_response_header_fields = r;
    });
  case SHRPX_OPTID_INCLUDE: {
    if (included_set.contains(optarg)) {
      Log{ERROR} << opt << ": " << optarg << " has already been included";
      return std::unexpected{Error::INVALID_CONFIG};
    }

    included_set.insert(optarg);
    auto rv =
      load_config(config, optarg.data(), included_set, pattern_addr_indexer);
    included_set.erase(optarg);

    return rv;
  }
  case SHRPX_OPTID_TLS_TICKET_KEY_CIPHER:
    if (util::strieq("aes-128-cbc"sv, optarg)) {
      config->tls.ticket.cipher = nghttp2::tls::aes_128_cbc();
    } else if (util::strieq("aes-256-cbc"sv, optarg)) {
      config->tls.ticket.cipher = nghttp2::tls::aes_256_cbc();
    } else {
      Log{ERROR} << opt
                 << ": unsupported cipher for ticket encryption: " << optarg;
      return std::unexpected{Error::INVALID_CONFIG};
    }
    config->tls.ticket.cipher_given = true;

    return {};
  case SHRPX_OPTID_HOST_REWRITE:
    config->http.no_host_rewrite = !util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED: {
    auto addr_end = std::ranges::find(optarg, ';');
    auto src_params = std::string_view{addr_end, std::ranges::end(optarg)};

    auto maybe_params = parse_memcached_connection_params(src_params, opt);
    if (!maybe_params) {
      return std::unexpected{maybe_params.error()};
    }

    const auto &params = *maybe_params;

    auto maybe_hp = split_host_port(
      config->balloc, std::string_view{std::ranges::begin(optarg), addr_end},
      opt);
    if (!maybe_hp) {
      return std::unexpected{maybe_hp.error()};
    }

    const auto &hp = *maybe_hp;

    auto &memcachedconf = config->tls.ticket.memcached;
    memcachedconf.host = hp.host;
    memcachedconf.port = hp.port;
    memcachedconf.tls = params.tls;

    return {};
  }
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_INTERVAL:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->tls.ticket.memcached.interval = r;
    });
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_RETRY:
    return parse_uint<size_t>(opt, optarg)
      .and_then([config, opt](auto &&r) -> std::expected<void, Error> {
        if (r > 30) {
          Log{ERROR} << opt << ": must be smaller than or equal to 30";
          return std::unexpected{Error::INVALID_CONFIG};
        }

        config->tls.ticket.memcached.max_retry = r;

        return {};
      });
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_MAX_FAIL:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->tls.ticket.memcached.max_fail = r;
    });
  case SHRPX_OPTID_TLS_DYN_REC_WARMUP_THRESHOLD:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->tls.dyn_rec.warmup_threshold = r; });
  case SHRPX_OPTID_TLS_DYN_REC_IDLE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->tls.dyn_rec.idle_timeout = r;
    });
  case SHRPX_OPTID_MRUBY_FILE:
#ifdef HAVE_MRUBY
    config->mruby_file = make_string_ref(config->balloc, optarg);
#else  // !defined(HAVE_MRUBY)
    Log{WARN} << opt
              << ": ignored because mruby support is disabled at build time.";
#endif // !defined(HAVE_MRUBY)
    return {};
  case SHRPX_OPTID_ACCEPT_PROXY_PROTOCOL:
    Log{WARN} << opt << ": deprecated.  Use proxyproto keyword in "
              << SHRPX_OPT_FRONTEND << " instead.";
    config->conn.upstream.accept_proxy_protocol = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_ADD_FORWARDED: {
    auto &fwdconf = config->http.forwarded;
    fwdconf.params = FORWARDED_NONE;
    for (const auto &param : util::split_str(optarg, ',')) {
      if (util::strieq("by"sv, param)) {
        fwdconf.params |= FORWARDED_BY;
        continue;
      }
      if (util::strieq("for"sv, param)) {
        fwdconf.params |= FORWARDED_FOR;
        continue;
      }
      if (util::strieq("host"sv, param)) {
        fwdconf.params |= FORWARDED_HOST;
        continue;
      }
      if (util::strieq("proto"sv, param)) {
        fwdconf.params |= FORWARDED_PROTO;
        continue;
      }

      Log{ERROR} << opt << ": unknown parameter " << optarg;

      return std::unexpected{Error::INVALID_CONFIG};
    }

    return {};
  }
  case SHRPX_OPTID_STRIP_INCOMING_FORWARDED:
    config->http.forwarded.strip_incoming = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_FORWARDED_BY:
  case SHRPX_OPTID_FORWARDED_FOR: {
    auto maybe_type = parse_forwarded_node_type(optarg);
    if (!maybe_type) {
      Log{ERROR} << opt << ": unknown node type " << optarg;
      return std::unexpected{maybe_type.error()};
    }

    if (optid == SHRPX_OPTID_FORWARDED_FOR && optarg[0] == '_') {
      Log{ERROR} << opt << ": unknown node type or illegal obfuscated string "
                 << optarg;
      return std::unexpected{Error::INVALID_CONFIG};
    }

    auto type = *maybe_type;
    auto &fwdconf = config->http.forwarded;

    switch (optid) {
    case SHRPX_OPTID_FORWARDED_BY:
      fwdconf.by_node_type = type;
      if (optarg[0] == '_') {
        fwdconf.by_obfuscated = make_string_ref(config->balloc, optarg);
      } else {
        fwdconf.by_obfuscated = ""sv;
      }
      break;
    case SHRPX_OPTID_FORWARDED_FOR:
      fwdconf.for_node_type = type;
      break;
    }

    return {};
  }
  case SHRPX_OPTID_NO_HTTP2_CIPHER_BLACK_LIST:
    Log{WARN} << opt << ": deprecated.  Use "
              << SHRPX_OPT_NO_HTTP2_CIPHER_BLOCK_LIST << " instead.";
    // fall through
  case SHRPX_OPTID_NO_HTTP2_CIPHER_BLOCK_LIST:
    config->tls.no_http2_cipher_block_list = util::strieq("yes"sv, optarg);
    return {};
  case SHRPX_OPTID_BACKEND_HTTP1_TLS:
  case SHRPX_OPTID_BACKEND_TLS:
    Log{WARN} << opt << ": deprecated.  Use tls keyword in "
              << SHRPX_OPT_BACKEND << " instead.";
    return {};
  case SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED_TLS:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED_CERT_FILE:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED_PRIVATE_KEY_FILE:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_TLS:
    Log{WARN} << opt << ": deprecated.  Use tls keyword in "
              << SHRPX_OPT_TLS_TICKET_KEY_MEMCACHED;
    return {};
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_CERT_FILE:
    config->tls.ticket.memcached.cert_file =
      make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_PRIVATE_KEY_FILE:
    config->tls.ticket.memcached.private_key_file =
      make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_TLS_TICKET_KEY_MEMCACHED_ADDRESS_FAMILY:
    return parse_address_family(opt, optarg).transform([config](auto &&r) {
      config->tls.ticket.memcached.family = r;
    });
  case SHRPX_OPTID_TLS_SESSION_CACHE_MEMCACHED_ADDRESS_FAMILY:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_BACKEND_ADDRESS_FAMILY:
    return parse_address_family(opt, optarg).transform([config](auto &&r) {
      config->conn.downstream->family = r;
    });
  case SHRPX_OPTID_FRONTEND_HTTP2_MAX_CONCURRENT_STREAMS:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->http2.upstream.max_concurrent_streams = r;
    });
  case SHRPX_OPTID_BACKEND_HTTP2_MAX_CONCURRENT_STREAMS:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->http2.downstream.max_concurrent_streams = r;
    });
  case SHRPX_OPTID_ERROR_PAGE:
    return parse_error_page(opt, optarg).transform([config](auto &&r) {
      config->http.error_pages.emplace_back(std::forward<decltype(r)>(r));
    });
  case SHRPX_OPTID_NO_KQUEUE:
    if ((ev_supported_backends() & EVBACKEND_KQUEUE) == 0) {
      Log{WARN} << opt << ": kqueue is not supported on this platform";
      return {};
    }

    config->ev_loop_flags =
      ev_recommended_backends() & static_cast<uint32_t>(~EVBACKEND_KQUEUE);

    return {};
  case SHRPX_OPTID_FRONTEND_HTTP2_SETTINGS_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http2.upstream.timeout.settings = r;
    });
  case SHRPX_OPTID_BACKEND_HTTP2_SETTINGS_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http2.downstream.timeout.settings = r;
    });
  case SHRPX_OPTID_API_MAX_REQUEST_BODY:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform([config](auto &&r) { config->api.max_request_body = r; });
  case SHRPX_OPTID_BACKEND_MAX_BACKOFF:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.downstream->timeout.max_backoff = r;
    });
  case SHRPX_OPTID_SERVER_NAME:
    config->http.server_name = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_NO_SERVER_REWRITE:
    config->http.no_server_rewrite = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_FRONTEND_HTTP2_OPTIMIZE_WRITE_BUFFER_SIZE:
    config->http2.upstream.optimize_write_buffer_size =
      util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_FRONTEND_HTTP2_OPTIMIZE_WINDOW_SIZE:
    config->http2.upstream.optimize_window_size = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_FRONTEND_HTTP2_WINDOW_SIZE:
    return parse_uint_with_unit<int32_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->http2.upstream.window_size = r; });
  case SHRPX_OPTID_FRONTEND_HTTP2_CONNECTION_WINDOW_SIZE:
    return parse_uint_with_unit<int32_t>(opt, optarg)
      .transform([config](auto &&r) {
        config->http2.upstream.connection_window_size = r;
      });
  case SHRPX_OPTID_BACKEND_HTTP2_WINDOW_SIZE:
    return parse_uint_with_unit<int32_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->http2.downstream.window_size = r; });
  case SHRPX_OPTID_BACKEND_HTTP2_CONNECTION_WINDOW_SIZE:
    return parse_uint_with_unit<int32_t>(opt, optarg)
      .transform([config](auto &&r) {
        config->http2.downstream.connection_window_size = r;
      });
  case SHRPX_OPTID_FRONTEND_HTTP2_ENCODER_DYNAMIC_TABLE_SIZE:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform([config](auto &&r) {
        config->http2.upstream.encoder_dynamic_table_size = r;

        nghttp2_option_set_max_deflate_dynamic_table_size(
          config->http2.upstream.option, r);
        nghttp2_option_set_max_deflate_dynamic_table_size(
          config->http2.upstream.alt_mode_option, r);
      });
  case SHRPX_OPTID_FRONTEND_HTTP2_DECODER_DYNAMIC_TABLE_SIZE:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform([config](auto &&r) {
        config->http2.upstream.decoder_dynamic_table_size = r;
      });
  case SHRPX_OPTID_BACKEND_HTTP2_ENCODER_DYNAMIC_TABLE_SIZE:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform([config](auto &&r) {
        config->http2.downstream.encoder_dynamic_table_size = r;

        nghttp2_option_set_max_deflate_dynamic_table_size(
          config->http2.downstream.option, r);
      });
  case SHRPX_OPTID_BACKEND_HTTP2_DECODER_DYNAMIC_TABLE_SIZE:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform([config](auto &&r) {
        config->http2.downstream.decoder_dynamic_table_size = r;
      });
  case SHRPX_OPTID_ECDH_CURVES:
    Log{WARN} << opt << ": deprecated.  Use " << SHRPX_OPT_GROUPS
              << " instead.";
    // fall through
  case SHRPX_OPTID_GROUPS:
    config->tls.groups = make_string_ref(config->balloc, optarg);
    return {};
  case SHRPX_OPTID_TLS_SCT_DIR:
#if defined(NGHTTP2_GENUINE_OPENSSL) || defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
    return read_tls_sct_from_dir(opt, optarg).transform([config](auto &&r) {
      std::ranges::copy(std::forward<decltype(r)>(r),
                        std::back_inserter(config->tls.sct_data));
    });
#else  // !defined(NGHTTP2_GENUINE_OPENSSL) &&
       // !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
    Log{WARN}
      << opt << ": ignored because underlying TLS library does not support SCT";
    return {};
#endif // !defined(NGHTTP2_GENUINE_OPENSSL) &&
       // !defined(NGHTTP2_OPENSSL_IS_BORINGSSL)
  case SHRPX_OPTID_DNS_CACHE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->dns.timeout.cache = r;
    });
  case SHRPX_OPTID_DNS_LOOKUP_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->dns.timeout.lookup = r;
    });
  case SHRPX_OPTID_DNS_MAX_TRY:
    return parse_uint<size_t>(opt, optarg)
      .and_then([config, opt](auto &&r) -> std::expected<void, Error> {
        if (r > 5) {
          Log{ERROR} << opt << ": must be smaller than or equal to 5";
          return std::unexpected{Error::INVALID_CONFIG};
        }

        config->dns.max_try = r;

        return {};
      });
  case SHRPX_OPTID_FRONTEND_KEEP_ALIVE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.upstream.timeout.idle = r;
    });
  case SHRPX_OPTID_PSK_SECRETS:
#ifndef OPENSSL_NO_PSK
    return parse_psk_secrets(config, optarg);
#else  // defined(OPENSSL_NO_PSK)
    Log{WARN}
      << opt << ": ignored because underlying TLS library does not support PSK";
    return {};
#endif // defined(OPENSSL_NO_PSK)
  case SHRPX_OPTID_CLIENT_PSK_SECRETS:
#ifndef OPENSSL_NO_PSK
    return parse_client_psk_secrets(config, optarg);
#else  // defined(OPENSSL_NO_PSK)
    Log{WARN}
      << opt << ": ignored because underlying TLS library does not support PSK";
    return {};
#endif // defined(OPENSSL_NO_PSK)
  case SHRPX_OPTID_CLIENT_NO_HTTP2_CIPHER_BLACK_LIST:
    Log{WARN} << opt << ": deprecated.  Use "
              << SHRPX_OPT_CLIENT_NO_HTTP2_CIPHER_BLOCK_LIST << " instead.";
    // fall through
  case SHRPX_OPTID_CLIENT_NO_HTTP2_CIPHER_BLOCK_LIST:
    config->tls.client.no_http2_cipher_block_list =
      util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_CLIENT_CIPHERS:
    config->tls.client.ciphers = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_TLS13_CLIENT_CIPHERS:
    config->tls.client.tls13_ciphers = make_string_ref(config->balloc, optarg);

    return {};
  case SHRPX_OPTID_ACCESSLOG_WRITE_EARLY:
    config->logging.access.write_early = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_TLS_MIN_PROTO_VERSION:
    return parse_tls_proto_version(opt, optarg).transform([config](auto &&r) {
      config->tls.min_proto_version = r;
    });
  case SHRPX_OPTID_TLS_MAX_PROTO_VERSION:
    return parse_tls_proto_version(opt, optarg).transform([config](auto &&r) {
      config->tls.max_proto_version = r;
    });
  case SHRPX_OPTID_REDIRECT_HTTPS_PORT:
    return parse_uint<uint16_t>(opt, optarg)
      .transform([config, optarg](auto &&) {
        config->http.redirect_https_port =
          make_string_ref(config->balloc, optarg);
      });
  case SHRPX_OPTID_FRONTEND_MAX_REQUESTS:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->http.max_requests = r;
    });
  case SHRPX_OPTID_SINGLE_THREAD:
    config->single_thread = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_SINGLE_PROCESS:
    config->single_process = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_NO_ADD_X_FORWARDED_PROTO:
    config->http.xfp.add = !util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_NO_STRIP_INCOMING_X_FORWARDED_PROTO:
    config->http.xfp.strip_incoming = !util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_OCSP_STARTUP:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_NO_VERIFY_OCSP:
    Log{WARN} << opt << ": deprecated.  It has no effect";
    return {};
  case SHRPX_OPTID_VERIFY_CLIENT_TOLERATE_EXPIRED:
    config->tls.client_verify.tolerate_expired = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_IGNORE_PER_PATTERN_MRUBY_ERROR:
    config->ignore_per_pattern_mruby_error = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_TLS_NO_POSTPONE_EARLY_DATA:
    config->tls.no_postpone_early_data = util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_TLS_MAX_EARLY_DATA:
    return parse_uint_with_unit<uint32_t>(opt, optarg)
      .transform([config](auto &&r) { config->tls.max_early_data = r; });
  case SHRPX_OPTID_NO_STRIP_INCOMING_EARLY_DATA:
    config->http.early_data.strip_incoming = !util::strieq("yes"sv, optarg);

    return {};
  case SHRPX_OPTID_QUIC_BPF_PROGRAM_FILE:
#ifdef ENABLE_HTTP3
    config->quic.bpf.prog_file = make_string_ref(config->balloc, optarg);
#endif // defined(ENABLE_HTTP3)

    return {};
  case SHRPX_OPTID_NO_QUIC_BPF:
#ifdef ENABLE_HTTP3
    config->quic.bpf.disabled = util::strieq("yes"sv, optarg);
#endif // defined(ENABLE_HTTP3)

    return {};
  case SHRPX_OPTID_HTTP2_ALTSVC:
    return parse_altsvc(opt, optarg).transform([config](auto &&r) {
      config->http.http2_altsvcs.emplace_back(std::forward<decltype(r)>(r));
    });
  case SHRPX_OPTID_FRONTEND_HTTP3_READ_TIMEOUT:
    Log{WARN} << opt << ": deprecated.  Use frontend-http3-idle-timeout";
    // fall through
  case SHRPX_OPTID_FRONTEND_HTTP3_IDLE_TIMEOUT:
#ifdef ENABLE_HTTP3
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->conn.upstream.timeout.http3_idle = r;
    });
#else  // !defined(ENABLE_HTTP3)
    return {};
#endif // !defined(ENABLE_HTTP3)
  case SHRPX_OPTID_FRONTEND_QUIC_IDLE_TIMEOUT:
#ifdef ENABLE_HTTP3
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->quic.upstream.timeout.idle = r;
    });
#else  // !defined(ENABLE_HTTP3)
    return {};
#endif // !defined(ENABLE_HTTP3)
  case SHRPX_OPTID_FRONTEND_QUIC_DEBUG_LOG:
#ifdef ENABLE_HTTP3
    config->quic.upstream.debug.log = util::strieq("yes"sv, optarg);
#endif // defined(ENABLE_HTTP3)

    return {};
  case SHRPX_OPTID_FRONTEND_HTTP3_WINDOW_SIZE:
#ifdef ENABLE_HTTP3
    return parse_uint_with_unit<int32_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->http3.upstream.window_size = r; });
#else  // !defined(ENABLE_HTTP3)
    return {};
#endif // !defined(ENABLE_HTTP3)
  case SHRPX_OPTID_FRONTEND_HTTP3_CONNECTION_WINDOW_SIZE:
#ifdef ENABLE_HTTP3
    return parse_uint_with_unit<int32_t>(opt, optarg)
      .transform([config](auto &&r) {
        config->http3.upstream.connection_window_size = r;
      });
#else  // !defined(ENABLE_HTTP3)
    return {};
#endif // !defined(ENABLE_HTTP3)
  case SHRPX_OPTID_FRONTEND_HTTP3_MAX_WINDOW_SIZE:
#ifdef ENABLE_HTTP3
    return parse_uint_with_unit<int32_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->http3.upstream.max_window_size = r; });
#else  // !defined(ENABLE_HTTP3)
    return {};
#endif // !defined(ENABLE_HTTP3)
  case SHRPX_OPTID_FRONTEND_HTTP3_MAX_CONNECTION_WINDOW_SIZE:
#ifdef ENABLE_HTTP3
    return parse_uint_with_unit<int32_t>(opt, optarg)
      .transform([config](auto &&r) {
        config->http3.upstream.max_connection_window_size = r;
      });
#else  // !defined(ENABLE_HTTP3)
    return {};
#endif // !defined(ENABLE_HTTP3)
  case SHRPX_OPTID_FRONTEND_HTTP3_MAX_CONCURRENT_STREAMS:
#ifdef ENABLE_HTTP3
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->http3.upstream.max_concurrent_streams = r;
    });
#else  // !defined(ENABLE_HTTP3)
    return {};
#endif // !defined(ENABLE_HTTP3)
  case SHRPX_OPTID_FRONTEND_QUIC_EARLY_DATA:
#ifdef ENABLE_HTTP3
    config->quic.upstream.early_data = util::strieq("yes"sv, optarg);
#endif // defined(ENABLE_HTTP3)

    return {};
  case SHRPX_OPTID_FRONTEND_QUIC_QLOG_DIR:
#ifdef ENABLE_HTTP3
    config->quic.upstream.qlog.dir = make_string_ref(config->balloc, optarg);
#endif // defined(ENABLE_HTTP3)

    return {};
  case SHRPX_OPTID_FRONTEND_QUIC_REQUIRE_TOKEN:
#ifdef ENABLE_HTTP3
    config->quic.upstream.require_token = util::strieq("yes"sv, optarg);
#endif // defined(ENABLE_HTTP3)

    return {};
  case SHRPX_OPTID_FRONTEND_QUIC_CONGESTION_CONTROLLER:
#ifdef ENABLE_HTTP3
    if (util::strieq("cubic"sv, optarg)) {
      config->quic.upstream.congestion_controller = NGTCP2_CC_ALGO_CUBIC;

      return {};
    }

    if (util::strieq("bbr"sv, optarg)) {
      config->quic.upstream.congestion_controller = NGTCP2_CC_ALGO_BBR;

      return {};
    }

    Log{ERROR} << opt << ": must be either cubic or bbr";

    return std::unexpected{Error::INVALID_CONFIG};
#else  // !defined(ENABLE_HTTP3)
    return {};
#endif // !defined(ENABLE_HTTP3)
  case SHRPX_OPTID_QUIC_SERVER_ID:
#ifdef ENABLE_HTTP3
    if (optarg.size() != sizeof(config->quic.server_id) * 2 ||
        !util::is_hex_string(optarg)) {
      Log{ERROR} << opt << ": must be a hex-string";
      return std::unexpected{Error::INVALID_CONFIG};
    }
    util::decode_hex(optarg,
                     reinterpret_cast<uint8_t *>(&config->quic.server_id));
#endif // defined(ENABLE_HTTP3)

    return {};
  case SHRPX_OPTID_FRONTEND_QUIC_SECRET_FILE:
#ifdef ENABLE_HTTP3
    config->quic.upstream.secret_file = make_string_ref(config->balloc, optarg);
#endif // defined(ENABLE_HTTP3)

    return {};
  case SHRPX_OPTID_RLIMIT_MEMLOCK:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->rlimit_memlock = r;
    });
  case SHRPX_OPTID_MAX_WORKER_PROCESSES:
    return parse_uint<size_t>(opt, optarg).transform([config](auto &&r) {
      config->max_worker_processes = r;
    });
  case SHRPX_OPTID_WORKER_PROCESS_GRACE_SHUTDOWN_PERIOD:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->worker_process_grace_shutdown_period = r;
    });
  case SHRPX_OPTID_FRONTEND_QUIC_INITIAL_RTT:
#ifdef ENABLE_HTTP3
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->quic.upstream.initial_rtt = r;
    });
#else  // !defined(ENABLE_HTTP3)
    return {};
#endif // !defined(ENABLE_HTTP3)
  case SHRPX_OPTID_REQUIRE_HTTP_SCHEME:
    config->http.require_http_scheme = util::strieq("yes"sv, optarg);
    return {};
  case SHRPX_OPTID_TLS_KTLS:
    config->tls.ktls = util::strieq("yes"sv, optarg);
    return {};
  case SHRPX_OPTID_NPN_LIST:
    Log{WARN} << opt << ": deprecated.  Use alpn-list instead.";
    // fall through
  case SHRPX_OPTID_ALPN_LIST:
    config->tls.alpn_list = util::split_str(config->balloc, optarg, ',');

    return {};
  case SHRPX_OPTID_ECH_CONFIG_FILE:
    return read_ech_config_file(config, opt, optarg);
  case SHRPX_OPTID_ECH_RETRY_CONFIG_FILE:
    return read_ech_config_file(config, opt, optarg, /* retry = */ true);
  case SHRPX_OPTID_FRONTEND_STREAM_READ_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http.upstream.timeout.stream_read = r;
    });
  case SHRPX_OPTID_FRONTEND_STREAM_WRITE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http.upstream.timeout.stream_write = r;
    });
  case SHRPX_OPTID_BACKEND_STREAM_READ_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http.downstream.timeout.stream_read = r;
    });
  case SHRPX_OPTID_BACKEND_STREAM_WRITE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http.downstream.timeout.stream_write = r;
    });
  case SHRPX_OPTID_FRONTEND_MIN_WRITE_RATE:
    return parse_uint_with_unit<size_t>(opt, optarg)
      .transform(
        [config](auto &&r) { config->http.upstream.min_write_rate = r; });
  case SHRPX_OPTID_FRONTEND_INITIAL_WRITE_RATE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http.upstream.timeout.initial_write_rate = r;
    });
  case SHRPX_OPTID_FRONTEND_MAX_WRITE_RATE_TIMEOUT:
    return parse_duration(opt, optarg).transform([config](auto &&r) {
      config->http.upstream.timeout.max_write_rate = r;
    });
  case SHRPX_OPTID_CONF:
    Log{WARN} << "conf: ignored";

    return {};
  }

  Log{ERROR} << "Unknown option: " << opt;

  return std::unexpected{Error::INVALID_CONFIG};
}

std::expected<void, Error> load_config(
  Config *config, const char *filename,
  std::unordered_set<std::string_view> &include_set,
  std::unordered_map<std::string_view, size_t> &pattern_addr_indexer) {
  std::ifstream in(filename, std::ios::binary);
  if (!in) {
    Log{ERROR} << "Could not open config file " << filename;
    return std::unexpected{Error::IO};
  }
  std::string line;
  int linenum = 0;
  while (std::getline(in, line)) {
    ++linenum;
    if (line.empty() || line[0] == '#') {
      continue;
    }
    auto eq = std::ranges::find(line, '=');
    if (eq == std::ranges::end(line)) {
      Log{ERROR} << "Bad configuration format in " << filename << " at line "
                 << linenum;
      return std::unexpected{Error::INVALID_CONFIG};
    }
    *eq = '\0';

    if (auto rv =
          parse_config(config, std::string_view{std::ranges::begin(line), eq},
                       std::string_view{eq + 1, std::ranges::end(line)},
                       include_set, pattern_addr_indexer);
        !rv) {
      return rv;
    }
  }

  if (util::stream_error(in)) {
    Log{ERROR} << "Could not read the configuration file " << filename;
    return std::unexpected{Error::IO};
  }

  return {};
}

std::string_view str_syslog_facility(int facility) {
  switch (facility) {
  case (LOG_AUTH):
    return "auth"sv;
#ifdef LOG_AUTHPRIV
  case (LOG_AUTHPRIV):
    return "authpriv"sv;
#endif // defined(LOG_AUTHPRIV)
  case (LOG_CRON):
    return "cron"sv;
  case (LOG_DAEMON):
    return "daemon"sv;
#ifdef LOG_FTP
  case (LOG_FTP):
    return "ftp"sv;
#endif // defined(LOG_FTP)
  case (LOG_KERN):
    return "kern"sv;
  case (LOG_LOCAL0):
    return "local0"sv;
  case (LOG_LOCAL1):
    return "local1"sv;
  case (LOG_LOCAL2):
    return "local2"sv;
  case (LOG_LOCAL3):
    return "local3"sv;
  case (LOG_LOCAL4):
    return "local4"sv;
  case (LOG_LOCAL5):
    return "local5"sv;
  case (LOG_LOCAL6):
    return "local6"sv;
  case (LOG_LOCAL7):
    return "local7"sv;
  case (LOG_LPR):
    return "lpr"sv;
  case (LOG_MAIL):
    return "mail"sv;
  case (LOG_SYSLOG):
    return "syslog"sv;
  case (LOG_USER):
    return "user"sv;
  case (LOG_UUCP):
    return "uucp"sv;
  default:
    return "(unknown)"sv;
  }
}

std::expected<int, Error> int_syslog_facility(std::string_view strfacility) {
  if (util::strieq("auth"sv, strfacility)) {
    return LOG_AUTH;
  }

#ifdef LOG_AUTHPRIV
  if (util::strieq("authpriv"sv, strfacility)) {
    return LOG_AUTHPRIV;
  }
#endif // defined(LOG_AUTHPRIV)

  if (util::strieq("cron"sv, strfacility)) {
    return LOG_CRON;
  }

  if (util::strieq("daemon"sv, strfacility)) {
    return LOG_DAEMON;
  }

#ifdef LOG_FTP
  if (util::strieq("ftp"sv, strfacility)) {
    return LOG_FTP;
  }
#endif // defined(LOG_FTP)

  if (util::strieq("kern"sv, strfacility)) {
    return LOG_KERN;
  }

  if (util::strieq("local0"sv, strfacility)) {
    return LOG_LOCAL0;
  }

  if (util::strieq("local1"sv, strfacility)) {
    return LOG_LOCAL1;
  }

  if (util::strieq("local2"sv, strfacility)) {
    return LOG_LOCAL2;
  }

  if (util::strieq("local3"sv, strfacility)) {
    return LOG_LOCAL3;
  }

  if (util::strieq("local4"sv, strfacility)) {
    return LOG_LOCAL4;
  }

  if (util::strieq("local5"sv, strfacility)) {
    return LOG_LOCAL5;
  }

  if (util::strieq("local6"sv, strfacility)) {
    return LOG_LOCAL6;
  }

  if (util::strieq("local7"sv, strfacility)) {
    return LOG_LOCAL7;
  }

  if (util::strieq("lpr"sv, strfacility)) {
    return LOG_LPR;
  }

  if (util::strieq("mail"sv, strfacility)) {
    return LOG_MAIL;
  }

  if (util::strieq("news"sv, strfacility)) {
    return LOG_NEWS;
  }

  if (util::strieq("syslog"sv, strfacility)) {
    return LOG_SYSLOG;
  }

  if (util::strieq("user"sv, strfacility)) {
    return LOG_USER;
  }

  if (util::strieq("uucp"sv, strfacility)) {
    return LOG_UUCP;
  }

  return std::unexpected{Error::INVALID_ARGUMENT};
}

std::string_view strproto(Proto proto) {
  switch (proto) {
  case Proto::NONE:
    return "none"sv;
  case Proto::HTTP1:
    return "http/1.1"sv;
  case Proto::HTTP2:
    return "h2"sv;
  case Proto::HTTP3:
    return "h3"sv;
  case Proto::MEMCACHED:
    return "memcached"sv;
  }

  // gcc needs this.
  assert(0);
  abort();
}

namespace {
// Consistent hashing method described in
// https://github.com/RJ/ketama.  Generate 160 32-bit hashes per |s|,
// which is usually backend address.  The each hash is associated to
// index of backend address.  When all hashes for every backend
// address are calculated, sort it in ascending order of hash.  To
// choose the index, compute 32-bit hash based on client IP address,
// and do lower bound search in the array. The returned index is the
// backend to use.
std::expected<void, Error> compute_affinity_hash(std::vector<AffinityHash> &res,
                                                 size_t idx,
                                                 std::string_view s) {
  std::array<uint8_t, 32> buf;
  std::string t;

  t.resize_and_overwrite(s.size() + 1, [s](auto p, auto len) {
    std::ranges::copy(s, p);
    return len;
  });

  for (auto i = 0; i < 20; ++i) {
    t.back() = static_cast<char>(i);

    if (auto rv = util::sha256(buf, t); !rv) {
      return rv;
    }

    for (size_t i = 0; i < 8; ++i) {
      auto h = (static_cast<uint32_t>(buf[4 * i]) << 24) |
               (static_cast<uint32_t>(buf[4 * i + 1]) << 16) |
               (static_cast<uint32_t>(buf[4 * i + 2]) << 8) |
               static_cast<uint32_t>(buf[4 * i + 3]);

      res.emplace_back(idx, h);
    }
  }

  return {};
}
} // namespace

// Configures the following member in |config|:
// conn.downstream_router, conn.downstream.addr_groups,
// conn.downstream.addr_group_catch_all.
std::expected<void, Error>
configure_downstream_group(Config *config, bool http2_proxy,
                           bool numeric_addr_only, const TLSConfig &tlsconf) {
  auto &downstreamconf = *config->conn.downstream;
  auto &addr_groups = downstreamconf.addr_groups;
  auto &routerconf = downstreamconf.router;
  auto &router = routerconf.router;
  auto &rw_router = routerconf.rev_wildcard_router;
  auto &wildcard_patterns = routerconf.wildcard_patterns;

  if (addr_groups.empty()) {
    DownstreamAddrConfig addr{
      .host = DEFAULT_DOWNSTREAM_HOST,
      .weight = 1,
      .group_weight = 1,
      .proto = Proto::HTTP1,
      .port = DEFAULT_DOWNSTREAM_PORT,
    };

    DownstreamAddrGroupConfig g("/"sv);
    g.addrs.push_back(std::move(addr));
    router.add_route(g.pattern, addr_groups.size());
    addr_groups.push_back(std::move(g));
  }

  // backward compatibility: override all SNI fields with the option
  // value --backend-tls-sni-field
  if (!tlsconf.backend_sni_name.empty()) {
    auto &sni = tlsconf.backend_sni_name;
    for (auto &addr_group : addr_groups) {
      for (auto &addr : addr_group.addrs) {
        addr.sni = sni;
      }
    }
  }

  if (log_enabled(INFO)) {
    Log{INFO} << "Resolving backend address";
  }

  // Sort by pattern so that later we can compare the old and new
  // backends efficiently in Worker::replace_downstream_config.
  std::ranges::sort(addr_groups, [](const auto &lhs, const auto &rhs) {
    return lhs.pattern < rhs.pattern;
  });

  for (size_t idx = 0; idx < addr_groups.size(); ++idx) {
    auto &g = addr_groups[idx];

    // Sort by group so that later we can see the group in the
    // particular order in Worker::replace_downstream_config.
    std::ranges::sort(g.addrs, [](const auto &lhs, const auto &rhs) {
      return lhs.group < rhs.group;
    });

    if (g.pattern[0] == '*') {
      // wildcard pattern
      auto path_first = std::ranges::find(g.pattern, '/');

      auto host =
        std::string_view{std::ranges::begin(g.pattern) + 1, path_first};
      auto path = std::string_view{path_first, std::ranges::end(g.pattern)};

      auto path_is_wildcard = false;
      if (path[path.size() - 1] == '*') {
        path = path.substr(0, path.size() - 1);
        path_is_wildcard = true;
      }

      auto it = std::ranges::find_if(
        wildcard_patterns,
        [&host](const WildcardPattern &wp) { return wp.host == host; });

      if (it == std::ranges::end(wildcard_patterns)) {
        wildcard_patterns.emplace_back(host);

        auto &router = wildcard_patterns.back().router;
        router.add_route(path, idx, path_is_wildcard);

        auto iov = make_byte_ref(downstreamconf.balloc, host.size() + 1);
        auto p = std::ranges::reverse_copy(host, std::ranges::begin(iov)).out;
        *p = '\0';
        auto rev_host = as_string_view(std::ranges::begin(iov), p);

        rw_router.add_route(rev_host, wildcard_patterns.size() - 1);
      } else {
        (*it).router.add_route(path, idx, path_is_wildcard);
      }

      continue;
    }

    auto path_is_wildcard = false;
    auto pattern = g.pattern;

    if (pattern[pattern.size() - 1] == '*') {
      pattern = pattern.substr(0, pattern.size() - 1);
      path_is_wildcard = true;
    }

    router.add_route(pattern, idx, path_is_wildcard);
  }

  ssize_t catch_all_group = -1;
  for (size_t i = 0; i < addr_groups.size(); ++i) {
    auto &g = addr_groups[i];
    if (g.pattern == "/"sv) {
      catch_all_group = as_signed(i);
    }
    if (log_enabled(INFO)) {
      Log{INFO} << "Host-path pattern: group " << i << ": '" << g.pattern
                << "'";
      for (auto &addr : g.addrs) {
        Log{INFO} << "group " << i << " -> " << addr.host.data()
                  << (addr.host_unix ? "" : ":" + util::utos(addr.port))
                  << ", proto=" << strproto(addr.proto)
                  << (addr.tls ? ", tls" : "");
      }
    }
#ifdef HAVE_MRUBY
    // Try compile mruby script and catch compile error early.
    if (!g.mruby_file.empty()) {
      if (auto maybe_mruby = mruby::create_mruby_context(g.mruby_file);
          !maybe_mruby) {
        Log{config->ignore_per_pattern_mruby_error ? ERROR : FATAL}
          << "backend: Could not compile mruby file for pattern " << g.pattern;
        if (!config->ignore_per_pattern_mruby_error) {
          return std::unexpected{maybe_mruby.error()};
        }
        g.mruby_file = ""sv;
      }
    }
#endif // defined(HAVE_MRUBY)
  }

#ifdef HAVE_MRUBY
  // Try compile mruby script (--mruby-file) here to catch compile
  // error early.
  if (!config->mruby_file.empty()) {
    if (auto maybe_mruby = mruby::create_mruby_context(config->mruby_file);
        !maybe_mruby) {
      Log{FATAL} << "mruby-file: Could not compile mruby file";
      return std::unexpected{maybe_mruby.error()};
    }
  }
#endif // defined(HAVE_MRUBY)

  if (catch_all_group == -1) {
    Log{FATAL} << "backend: No catch-all backend address is configured";
    return std::unexpected{Error::INVALID_CONFIG};
  }

  downstreamconf.addr_group_catch_all = as_unsigned(catch_all_group);

  if (log_enabled(INFO)) {
    Log{INFO} << "Catch-all pattern is group " << catch_all_group;
  }

  auto resolve_flags = numeric_addr_only ? AI_NUMERICHOST | AI_NUMERICSERV : 0;

  std::array<char, util::max_hostport> hostport_buf;

  for (auto &g : addr_groups) {
    std::unordered_map<std::string_view, uint32_t> wgchk;
    for (auto &addr : g.addrs) {
      if (addr.group_weight) {
        auto it = wgchk.find(addr.group);
        if (it == std::ranges::end(wgchk)) {
          wgchk.emplace(addr.group, addr.group_weight);
        } else if ((*it).second != addr.group_weight) {
          Log{FATAL} << "backend: inconsistent group-weight for a single group";
          return std::unexpected{Error::INVALID_CONFIG};
        }
      }

      if (addr.host_unix) {
        // for AF_UNIX socket, we use "localhost" as host for backend
        // hostport.  This is used as Host header field to backend and
        // not going to be passed to any syscalls.
        addr.hostport = "localhost"sv;

        auto path = addr.host.data();
        auto pathlen = addr.host.size();
        auto &unaddr = addr.addr.skaddr.emplace<sockaddr_un>();

        if (pathlen + 1 > sizeof(unaddr.sun_path)) {
          Log{FATAL} << "UNIX domain socket path " << path << " is too long > "
                     << sizeof(unaddr.sun_path);
          return std::unexpected{Error::INVALID_CONFIG};
        }

        if (log_enabled(INFO)) {
          Log{INFO} << "Use UNIX domain socket path " << path
                    << " for backend connection";
        }

        unaddr.sun_family = AF_UNIX;
        // copy path including terminal NULL
        std::ranges::copy_n(path, as_signed(pathlen + 1), unaddr.sun_path);

        continue;
      }

      addr.hostport =
        util::make_http_hostport(downstreamconf.balloc, addr.host, addr.port);

      auto hostport = util::make_hostport(addr.host, addr.port,
                                          std::ranges::begin(hostport_buf));

      if (!addr.dns) {
        auto maybe_addr = resolve_hostname(
          addr.host.data(), addr.port, downstreamconf.family, resolve_flags);
        if (!maybe_addr) {
          Log{FATAL} << "Resolving backend address failed: " << hostport;
          return std::unexpected{maybe_addr.error()};
        }

        addr.addr = std::move(*maybe_addr);

        if (log_enabled(INFO)) {
          Log{INFO} << "Resolved backend address: " << hostport << " -> "
                    << util::to_numeric_addr(&addr.addr);
        }
      } else {
        Log{INFO} << "Resolving backend address " << hostport
                  << " takes place dynamically";
      }
    }

    for (auto &addr : g.addrs) {
      if (addr.group_weight == 0) {
        auto it = wgchk.find(addr.group);
        if (it == std::ranges::end(wgchk)) {
          addr.group_weight = 1;
        } else {
          addr.group_weight = (*it).second;
        }
      }
    }

    if (g.affinity.type != SessionAffinity::NONE) {
      size_t idx = 0;
      for (auto &addr : g.addrs) {
        std::string_view key;
        if (addr.dns) {
          if (addr.host_unix) {
            key = addr.host;
          } else {
            key = addr.hostport;
          }
        } else {
          key = std::string_view{
            reinterpret_cast<const char *>(addr.addr.as_sockaddr()),
            addr.addr.size()};
        }
        if (auto rv = compute_affinity_hash(g.affinity_hash, idx, key); !rv) {
          return rv;
        }

        if (g.affinity.cookie.stickiness ==
            SessionAffinityCookieStickiness::STRICT) {
          addr.affinity_hash = util::hash32(key);
          g.affinity_hash_map.emplace(addr.affinity_hash, idx);
        }

        ++idx;
      }

      std::ranges::sort(g.affinity_hash, [](const auto &lhs, const auto &rhs) {
        return lhs.hash < rhs.hash;
      });
    }

    auto &timeout = g.timeout;
    if (timeout.read < 1e-9) {
      timeout.read = downstreamconf.timeout.read;
    }
    if (timeout.write < 1e-9) {
      timeout.write = downstreamconf.timeout.write;
    }
  }

  return {};
}

std::expected<Address, Error> resolve_hostname(const char *hostname,
                                               uint16_t port, int family,
                                               int additional_flags) {
  int rv;

  auto service = util::utos(port);

  addrinfo hints{
    .ai_flags = additional_flags
#ifdef AI_ADDRCONFIG
                | AI_ADDRCONFIG
#endif // defined(AI_ADDRCONFIG)
    ,
    .ai_family = family,
    .ai_socktype = SOCK_STREAM,
  };
  addrinfo *res;

  rv = getaddrinfo(hostname, service.c_str(), &hints, &res);
#ifdef AI_ADDRCONFIG
  if (rv != 0) {
    // Retry without AI_ADDRCONFIG
    hints.ai_flags &= ~AI_ADDRCONFIG;
    rv = getaddrinfo(hostname, service.c_str(), &hints, &res);
  }
#endif // defined(AI_ADDRCONFIG)
  if (rv != 0) {
    Log{FATAL} << "Unable to resolve address for " << hostname << ": "
               << gai_strerror(rv);
    return std::unexpected{Error::LIBC};
  }

  auto res_d = defer([res] { freeaddrinfo(res); });

  std::array<char, NI_MAXHOST> host;
  rv = getnameinfo(res->ai_addr, res->ai_addrlen, host.data(), host.size(),
                   nullptr, 0, NI_NUMERICHOST);
  if (rv != 0) {
    Log{FATAL} << "Address resolution for " << hostname
               << " failed: " << gai_strerror(rv);

    return std::unexpected{Error::LIBC};
  }

  if (log_enabled(INFO)) {
    Log{INFO} << "Address resolution for " << hostname
              << " succeeded: " << host.data();
  }

  return Address{res->ai_addr};
}

#ifdef ENABLE_HTTP3
QUICKeyingMaterial::QUICKeyingMaterial(const QUICKeyingMaterial &other) noexcept
  : reserved{other.reserved},
    secret{other.secret},
    salt{other.salt},
    cid_encryption_key{other.cid_encryption_key},
    id{other.id} {}

QUICKeyingMaterial::QUICKeyingMaterial(QUICKeyingMaterial &&other) noexcept
  : cid_encryption_ctx{std::exchange(other.cid_encryption_ctx, nullptr)},
    cid_decryption_ctx{std::exchange(other.cid_decryption_ctx, nullptr)},
    reserved{other.reserved},
    secret{other.secret},
    salt{other.salt},
    cid_encryption_key{other.cid_encryption_key},
    id{other.id} {}

QUICKeyingMaterial::~QUICKeyingMaterial() noexcept {
  if (cid_encryption_ctx) {
    EVP_CIPHER_CTX_free(cid_encryption_ctx);
  }

  if (cid_decryption_ctx) {
    EVP_CIPHER_CTX_free(cid_decryption_ctx);
  }
}

QUICKeyingMaterial &
QUICKeyingMaterial::operator=(const QUICKeyingMaterial &other) noexcept {
  if (this == &other) {
    return *this;
  }

  if (cid_encryption_ctx) {
    EVP_CIPHER_CTX_free(cid_encryption_ctx);
    cid_encryption_ctx = nullptr;
  }

  if (cid_decryption_ctx) {
    EVP_CIPHER_CTX_free(cid_decryption_ctx);
    cid_decryption_ctx = nullptr;
  }

  reserved = other.reserved;
  secret = other.secret;
  salt = other.salt;
  cid_encryption_key = other.cid_encryption_key;
  id = other.id;

  return *this;
}

QUICKeyingMaterial &
QUICKeyingMaterial::operator=(QUICKeyingMaterial &&other) noexcept {
  if (this == &other) {
    return *this;
  }

  if (cid_encryption_ctx) {
    EVP_CIPHER_CTX_free(cid_encryption_ctx);
  }

  if (cid_decryption_ctx) {
    EVP_CIPHER_CTX_free(cid_decryption_ctx);
  }

  cid_encryption_ctx = std::exchange(other.cid_encryption_ctx, nullptr);
  cid_decryption_ctx = std::exchange(other.cid_decryption_ctx, nullptr);
  reserved = other.reserved;
  secret = other.secret;
  salt = other.salt;
  cid_encryption_key = other.cid_encryption_key;
  id = other.id;

  return *this;
}

std::expected<void, Error> QUICKeyingMaterial::init_ciphers() {
  if (auto rv = generate_quic_connection_id_encryption_key(cid_encryption_key,
                                                           secret, salt);
      !rv) {
    Log{ERROR} << "Failed to generate QUIC Connection ID encryption key";
    return rv;
  }

  cid_encryption_ctx = EVP_CIPHER_CTX_new();
  if (!cid_encryption_ctx ||
      !EVP_EncryptInit_ex(cid_encryption_ctx, nghttp2::tls::aes_128_ecb(),
                          nullptr, cid_encryption_key.data(), nullptr)) {
    Log{ERROR} << "Failed to initialize QUIC Connection ID encryption context";
    return std::unexpected{Error::CRYPTO};
  }

  EVP_CIPHER_CTX_set_padding(cid_encryption_ctx, 0);

  cid_decryption_ctx = EVP_CIPHER_CTX_new();
  if (!cid_decryption_ctx ||
      !EVP_DecryptInit_ex(cid_decryption_ctx, nghttp2::tls::aes_128_ecb(),
                          nullptr, cid_encryption_key.data(), nullptr)) {
    Log{ERROR} << "Failed to initialize QUIC Connection ID decryption context";
    return std::unexpected{Error::CRYPTO};
  }

  EVP_CIPHER_CTX_set_padding(cid_decryption_ctx, 0);

  return {};
}
#endif // defined(ENABLE_HTTP3)

} // namespace shrpx
