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
#include "shrpx.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif // HAVE_SYS_SOCKET_H
#include <sys/un.h>
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif // HAVE_NETDB_H
#include <signal.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif // HAVE_NETINET_IN_H
#include <netinet/tcp.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif // HAVE_ARPA_INET_H
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif // HAVE_UNISTD_H
#include <getopt.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif // HAVE_SYSLOG_H
#include <signal.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif // HAVE_LIMITS_H
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif // HAVE_SYS_TIME_H
#include <sys/resource.h>
#include <grp.h>

#include <cinttypes>
#include <limits>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <initializer_list>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/rand.h>

#include <ev.h>

#include <nghttp2/nghttp2.h>

#include "shrpx_config.h"
#include "shrpx_connection_handler.h"
#include "shrpx_ssl.h"
#include "shrpx_log_config.h"
#include "shrpx_worker.h"
#include "shrpx_accept_handler.h"
#include "shrpx_http2_upstream.h"
#include "shrpx_http2_session.h"
#include "shrpx_memcached_dispatcher.h"
#include "shrpx_memcached_request.h"
#include "util.h"
#include "app_helper.h"
#include "ssl.h"
#include "template.h"

extern char **environ;

using namespace nghttp2;

namespace shrpx {

namespace {
const int REOPEN_LOG_SIGNAL = SIGUSR1;
const int EXEC_BINARY_SIGNAL = SIGUSR2;
const int GRACEFUL_SHUTDOWN_SIGNAL = SIGQUIT;
} // namespace

// Environment variables to tell new binary the listening socket's
// file descriptors.  They are not close-on-exec.
#define ENV_LISTENER4_FD "NGHTTPX_LISTENER4_FD"
#define ENV_LISTENER6_FD "NGHTTPX_LISTENER6_FD"

// Environment variable to tell new binary the port number the current
// binary is listening to.
#define ENV_PORT "NGHTTPX_PORT"

// Environment variable to tell new binary the listening socket's file
// descriptor if frontend listens UNIX domain socket.
#define ENV_UNIX_FD "NGHTTP2_UNIX_FD"
// Environment variable to tell new binary the UNIX domain socket
// path.
#define ENV_UNIX_PATH "NGHTTP2_UNIX_PATH"

namespace {
int resolve_hostname(Address *addr, const char *hostname, uint16_t port,
                     int family) {
  int rv;

  auto service = util::utos(port);

  addrinfo hints{};
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG
  addrinfo *res;

  rv = getaddrinfo(hostname, service.c_str(), &hints, &res);
  if (rv != 0) {
    LOG(FATAL) << "Unable to resolve address for " << hostname << ": "
               << gai_strerror(rv);
    return -1;
  }

  char host[NI_MAXHOST];
  rv = getnameinfo(res->ai_addr, res->ai_addrlen, host, sizeof(host), 0, 0,
                   NI_NUMERICHOST);
  if (rv != 0) {
    LOG(FATAL) << "Address resolution for " << hostname
               << " failed: " << gai_strerror(rv);

    freeaddrinfo(res);

    return -1;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Address resolution for " << hostname
              << " succeeded: " << host;
  }

  memcpy(&addr->su, res->ai_addr, res->ai_addrlen);
  addr->len = res->ai_addrlen;
  freeaddrinfo(res);
  return 0;
}
} // namespace

namespace {
void close_env_fd(std::initializer_list<const char *> envnames) {
  for (auto envname : envnames) {
    auto envfd = getenv(envname);
    if (!envfd) {
      continue;
    }
    auto fd = strtol(envfd, nullptr, 10);
    close(fd);
  }
}
} // namespace

namespace {
std::unique_ptr<AcceptHandler>
create_unix_domain_acceptor(ConnectionHandler *handler) {
  auto path = get_config()->host.get();
  auto pathlen = strlen(path);
  {
    auto envfd = getenv(ENV_UNIX_FD);
    auto envpath = getenv(ENV_UNIX_PATH);
    if (envfd && envpath) {
      auto fd = strtoul(envfd, nullptr, 10);

      if (util::streq(envpath, path)) {
        LOG(NOTICE) << "Listening on UNIX domain socket " << path;

        return make_unique<AcceptHandler>(fd, handler);
      }

      LOG(WARN) << "UNIX domain socket path was changed between old binary ("
                << envpath << ") and new binary (" << path << ")";
      close(fd);
    }
  }

#ifdef SOCK_NONBLOCK
  auto fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (fd == -1) {
    return nullptr;
  }
#else  // !SOCK_NONBLOCK
  auto fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1) {
    return nullptr;
  }
  util::make_socket_nonblocking(fd);
#endif // !SOCK_NONBLOCK
  int val = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                 static_cast<socklen_t>(sizeof(val))) == -1) {
    close(fd);
    return nullptr;
  }

  sockaddr_union addr;
  addr.un.sun_family = AF_UNIX;
  if (pathlen + 1 > sizeof(addr.un.sun_path)) {
    LOG(FATAL) << "UNIX domain socket path " << path << " is too long > "
               << sizeof(addr.un.sun_path);
    close(fd);
    return nullptr;
  }
  // copy path including terminal NULL
  std::copy_n(path, pathlen + 1, addr.un.sun_path);

  // unlink (remove) already existing UNIX domain socket path
  unlink(path);

  if (bind(fd, &addr.sa, sizeof(addr.un)) != 0) {
    auto error = errno;
    LOG(FATAL) << "Failed to bind UNIX domain socket, error=" << error;
    close(fd);
    return nullptr;
  }

  if (listen(fd, get_config()->backlog) != 0) {
    auto error = errno;
    LOG(FATAL) << "Failed to listen to UNIX domain socket, error=" << error;
    close(fd);
    return nullptr;
  }

  LOG(NOTICE) << "Listening on UNIX domain socket " << path;

  return make_unique<AcceptHandler>(fd, handler);
}
} // namespace

namespace {
std::unique_ptr<AcceptHandler> create_acceptor(ConnectionHandler *handler,
                                               int family) {
  {
    auto envfd =
        getenv(family == AF_INET ? ENV_LISTENER4_FD : ENV_LISTENER6_FD);
    auto envport = getenv(ENV_PORT);

    if (envfd && envport) {
      auto fd = strtoul(envfd, nullptr, 10);
      auto port = strtoul(envport, nullptr, 10);

      // Only do this iff NGHTTPX_PORT == get_config()->port.
      // Otherwise, close fd, and create server socket as usual.

      if (port == get_config()->port) {
        LOG(NOTICE) << "Listening on port " << get_config()->port;

        return make_unique<AcceptHandler>(fd, handler);
      }

      LOG(WARN) << "Port was changed between old binary (" << port
                << ") and new binary (" << get_config()->port << ")";
      close(fd);
    }
  }

  int fd = -1;
  int rv;

  auto service = util::utos(get_config()->port);
  addrinfo hints{};
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG

  auto node = strcmp("*", get_config()->host.get()) == 0
                  ? nullptr
                  : get_config()->host.get();

  addrinfo *res, *rp;
  rv = getaddrinfo(node, service.c_str(), &hints, &res);
  if (rv != 0) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Unable to get IPv" << (family == AF_INET ? "4" : "6")
                << " address for " << get_config()->host.get() << ": "
                << gai_strerror(rv);
    }
    return nullptr;
  }
  for (rp = res; rp; rp = rp->ai_next) {
#ifdef SOCK_NONBLOCK
    fd =
        socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      LOG(WARN) << "socket() syscall failed, error=" << error;
      continue;
    }
#else  // !SOCK_NONBLOCK
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      LOG(WARN) << "socket() syscall failed, error=" << error;
      continue;
    }
    util::make_socket_nonblocking(fd);
#endif // !SOCK_NONBLOCK
    int val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      LOG(WARN)
          << "Failed to set SO_REUSEADDR option to listener socket, error="
          << error;
      close(fd);
      continue;
    }

#ifdef IPV6_V6ONLY
    if (family == AF_INET6) {
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        LOG(WARN)
            << "Failed to set IPV6_V6ONLY option to listener socket, error="
            << error;
        close(fd);
        continue;
      }
    }
#endif // IPV6_V6ONLY

#ifdef TCP_DEFER_ACCEPT
    val = 3;
    if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      LOG(WARN) << "Failed to set TCP_DEFER_ACCEPT option to listener socket";
    }
#endif // TCP_DEFER_ACCEPT

    // When we are executing new binary, and the old binary did not
    // bind privileged port (< 1024) for some reason, binding to those
    // ports will fail with permission denied error.
    if (bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
      auto error = errno;
      LOG(WARN) << "bind() syscall failed, error=" << error;
      close(fd);
      continue;
    }

    if (listen(fd, get_config()->backlog) == -1) {
      auto error = errno;
      LOG(WARN) << "listen() syscall failed, error=" << error;
      close(fd);
      continue;
    }

    break;
  }

  if (!rp) {
    LOG(WARN) << "Listening " << (family == AF_INET ? "IPv4" : "IPv6")
              << " socket failed";

    freeaddrinfo(res);

    return nullptr;
  }

  char host[NI_MAXHOST];
  rv = getnameinfo(rp->ai_addr, rp->ai_addrlen, host, sizeof(host), nullptr, 0,
                   NI_NUMERICHOST);

  freeaddrinfo(res);

  if (rv != 0) {
    LOG(WARN) << gai_strerror(rv);

    close(fd);

    return nullptr;
  }

  LOG(NOTICE) << "Listening on " << host << ", port " << get_config()->port;

  return make_unique<AcceptHandler>(fd, handler);
}
} // namespace

namespace {
void drop_privileges() {
  if (getuid() == 0 && get_config()->uid != 0) {
    if (initgroups(get_config()->user.get(), get_config()->gid) != 0) {
      auto error = errno;
      LOG(FATAL) << "Could not change supplementary groups: "
                 << strerror(error);
      exit(EXIT_FAILURE);
    }
    if (setgid(get_config()->gid) != 0) {
      auto error = errno;
      LOG(FATAL) << "Could not change gid: " << strerror(error);
      exit(EXIT_FAILURE);
    }
    if (setuid(get_config()->uid) != 0) {
      auto error = errno;
      LOG(FATAL) << "Could not change uid: " << strerror(error);
      exit(EXIT_FAILURE);
    }
    if (setuid(0) != -1) {
      LOG(FATAL) << "Still have root privileges?";
      exit(EXIT_FAILURE);
    }
  }
}
} // namespace

namespace {
void save_pid() {
  std::ofstream out(get_config()->pid_file.get(), std::ios::binary);
  out << get_config()->pid << "\n";
  out.close();
  if (!out) {
    LOG(ERROR) << "Could not save PID to file " << get_config()->pid_file.get();
    exit(EXIT_FAILURE);
  }

  if (get_config()->uid != 0) {
    if (chown(get_config()->pid_file.get(), get_config()->uid,
              get_config()->gid) == -1) {
      auto error = errno;
      LOG(WARN) << "Changing owner of pid file " << get_config()->pid_file.get()
                << " failed: " << strerror(error);
    }
  }
}
} // namespace

namespace {
void reopen_log_signal_cb(struct ev_loop *loop, ev_signal *w, int revents) {
  auto conn_handler = static_cast<ConnectionHandler *>(w->data);

  LOG(NOTICE) << "Reopening log files: main";

  (void)reopen_log_files();
  redirect_stderr_to_errorlog();

  if (get_config()->num_worker > 1) {
    conn_handler->worker_reopen_log_files();
  }
}
} // namespace

namespace {
void exec_binary_signal_cb(struct ev_loop *loop, ev_signal *w, int revents) {
  auto conn_handler = static_cast<ConnectionHandler *>(w->data);

  LOG(NOTICE) << "Executing new binary";

  auto pid = fork();

  if (pid == -1) {
    auto error = errno;
    LOG(ERROR) << "fork() failed errno=" << error;
    return;
  }

  if (pid != 0) {
    return;
  }

  auto exec_path = util::get_exec_path(get_config()->argc, get_config()->argv,
                                       get_config()->cwd);

  if (!exec_path) {
    LOG(ERROR) << "Could not resolve the executable path";
    return;
  }

  auto argv = make_unique<char *[]>(get_config()->argc + 1);

  argv[0] = exec_path;
  for (int i = 1; i < get_config()->argc; ++i) {
    argv[i] = strdup(get_config()->argv[i]);
  }
  argv[get_config()->argc] = nullptr;

  size_t envlen = 0;
  for (char **p = environ; *p; ++p, ++envlen)
    ;
  // 3 for missing (fd4, fd6 and port) or (unix fd and unix path)
  auto envp = make_unique<char *[]>(envlen + 3 + 1);
  size_t envidx = 0;

  if (get_config()->host_unix) {
    auto acceptor = conn_handler->get_acceptor();
    std::string fd = ENV_UNIX_FD "=";
    fd += util::utos(acceptor->get_fd());
    envp[envidx++] = strdup(fd.c_str());

    std::string path = ENV_UNIX_PATH "=";
    path += get_config()->host.get();
    envp[envidx++] = strdup(path.c_str());
  } else {
    auto acceptor4 = conn_handler->get_acceptor();
    if (acceptor4) {
      std::string fd4 = ENV_LISTENER4_FD "=";
      fd4 += util::utos(acceptor4->get_fd());
      envp[envidx++] = strdup(fd4.c_str());
    }

    auto acceptor6 = conn_handler->get_acceptor6();
    if (acceptor6) {
      std::string fd6 = ENV_LISTENER6_FD "=";
      fd6 += util::utos(acceptor6->get_fd());
      envp[envidx++] = strdup(fd6.c_str());
    }

    std::string port = ENV_PORT "=";
    port += util::utos(get_config()->port);
    envp[envidx++] = strdup(port.c_str());
  }

  for (size_t i = 0; i < envlen; ++i) {
    if (util::startsWith(environ[i], ENV_LISTENER4_FD) ||
        util::startsWith(environ[i], ENV_LISTENER6_FD) ||
        util::startsWith(environ[i], ENV_PORT) ||
        util::startsWith(environ[i], ENV_UNIX_FD) ||
        util::startsWith(environ[i], ENV_UNIX_PATH)) {
      continue;
    }

    envp[envidx++] = environ[i];
  }

  envp[envidx++] = nullptr;

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "cmdline";
    for (int i = 0; argv[i]; ++i) {
      LOG(INFO) << i << ": " << argv[i];
    }
    LOG(INFO) << "environ";
    for (int i = 0; envp[i]; ++i) {
      LOG(INFO) << i << ": " << envp[i];
    }
  }

  if (execve(argv[0], argv.get(), envp.get()) == -1) {
    auto error = errno;
    LOG(ERROR) << "execve failed: errno=" << error;
    _Exit(EXIT_FAILURE);
  }
}
} // namespace

namespace {
void graceful_shutdown_signal_cb(struct ev_loop *loop, ev_signal *w,
                                 int revents) {
  auto conn_handler = static_cast<ConnectionHandler *>(w->data);

  if (conn_handler->get_graceful_shutdown()) {
    return;
  }

  LOG(NOTICE) << "Graceful shutdown signal received";

  conn_handler->set_graceful_shutdown(true);

  conn_handler->disable_acceptor();

  // After disabling accepting new connection, disptach incoming
  // connection in backlog.

  conn_handler->accept_pending_connection();

  conn_handler->graceful_shutdown_worker();

  if (get_config()->num_worker == 1 &&
      conn_handler->get_single_worker()->get_worker_stat()->num_connections >
          0) {
    return;
  }

  // We have accepted all pending connections.  Shutdown main event
  // loop.
  ev_break(loop);
}
} // namespace

namespace {
int generate_ticket_key(TicketKey &ticket_key) {
  ticket_key.cipher = get_config()->tls_ticket_key_cipher;
  ticket_key.hmac = EVP_sha256();
  ticket_key.hmac_keylen = EVP_MD_size(ticket_key.hmac);

  assert(static_cast<size_t>(EVP_CIPHER_key_length(ticket_key.cipher)) <=
         ticket_key.data.enc_key.size());
  assert(ticket_key.hmac_keylen <= ticket_key.data.hmac_key.size());

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "enc_keylen=" << EVP_CIPHER_key_length(ticket_key.cipher)
              << ", hmac_keylen=" << ticket_key.hmac_keylen;
  }

  if (RAND_bytes(reinterpret_cast<unsigned char *>(&ticket_key.data),
                 sizeof(ticket_key.data)) == 0) {
    return -1;
  }

  return 0;
}
} // namespace

namespace {
void renew_ticket_key_cb(struct ev_loop *loop, ev_timer *w, int revents) {
  auto conn_handler = static_cast<ConnectionHandler *>(w->data);
  const auto &old_ticket_keys = conn_handler->get_ticket_keys();

  auto ticket_keys = std::make_shared<TicketKeys>();
  LOG(NOTICE) << "Renew new ticket keys";

  // If old_ticket_keys is not empty, it should contain at least 2
  // keys: one for encryption, and last one for the next encryption
  // key but decryption only.  The keys in between are old keys and
  // decryption only.  The next key is provided to ensure to mitigate
  // possible problem when one worker encrypt new key, but one worker,
  // which did not take the that key yet, and cannot decrypt it.
  //
  // We keep keys for get_config()->tls_session_timeout seconds.  The
  // default is 12 hours.  Thus the maximum ticket vector size is 12.
  if (old_ticket_keys) {
    auto &old_keys = old_ticket_keys->keys;
    auto &new_keys = ticket_keys->keys;

    assert(!old_keys.empty());

    auto max_tickets =
        static_cast<size_t>(std::chrono::duration_cast<std::chrono::hours>(
                                get_config()->tls_session_timeout).count());

    new_keys.resize(std::min(max_tickets, old_keys.size() + 1));
    std::copy_n(std::begin(old_keys), new_keys.size() - 1,
                std::begin(new_keys) + 1);
  } else {
    ticket_keys->keys.resize(1);
  }

  auto &new_key = ticket_keys->keys[0];

  if (generate_ticket_key(new_key) != 0) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "failed to generate ticket key";
    }
    conn_handler->set_ticket_keys(nullptr);
    conn_handler->set_ticket_keys_to_worker(nullptr);
    return;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "ticket keys generation done";
    assert(ticket_keys->keys.size() >= 1);
    LOG(INFO) << 0 << " enc+dec: "
              << util::format_hex(ticket_keys->keys[0].data.name);
    for (size_t i = 1; i < ticket_keys->keys.size(); ++i) {
      auto &key = ticket_keys->keys[i];
      LOG(INFO) << i << " dec: " << util::format_hex(key.data.name);
    }
  }

  conn_handler->set_ticket_keys(ticket_keys);
  conn_handler->set_ticket_keys_to_worker(ticket_keys);
}
} // namespace

namespace {
void memcached_get_ticket_key_cb(struct ev_loop *loop, ev_timer *w,
                                 int revents) {
  auto conn_handler = static_cast<ConnectionHandler *>(w->data);
  auto dispatcher = conn_handler->get_tls_ticket_key_memcached_dispatcher();

  auto req = make_unique<MemcachedRequest>();
  req->key = "nghttpx:tls-ticket-key";
  req->op = MEMCACHED_OP_GET;
  req->cb = [conn_handler, dispatcher, w](MemcachedRequest *req,
                                          MemcachedResult res) {
    switch (res.status_code) {
    case MEMCACHED_ERR_NO_ERROR:
      break;
    case MEMCACHED_ERR_EXT_NETWORK_ERROR:
      conn_handler->on_tls_ticket_key_network_error(w);
      return;
    default:
      conn_handler->on_tls_ticket_key_not_found(w);
      return;
    }

    // |version (4bytes)|len (2bytes)|key (variable length)|...
    // (len, key) pairs are repeated as necessary.

    auto &value = res.value;
    if (value.size() < 4) {
      LOG(WARN) << "Memcached: tls ticket key value is too small: got "
                << value.size();
      conn_handler->on_tls_ticket_key_not_found(w);
      return;
    }
    auto p = value.data();
    auto version = util::get_uint32(p);
    // Currently supported version is 1.
    if (version != 1) {
      LOG(WARN) << "Memcached: tls ticket key version: want 1, got " << version;
      conn_handler->on_tls_ticket_key_not_found(w);
      return;
    }

    auto end = p + value.size();
    p += 4;

    size_t expectedlen;
    size_t enc_keylen;
    size_t hmac_keylen;
    if (get_config()->tls_ticket_key_cipher == EVP_aes_128_cbc()) {
      expectedlen = 48;
      enc_keylen = 16;
      hmac_keylen = 16;
    } else if (get_config()->tls_ticket_key_cipher == EVP_aes_256_cbc()) {
      expectedlen = 80;
      enc_keylen = 32;
      hmac_keylen = 32;
    } else {
      return;
    }

    auto ticket_keys = std::make_shared<TicketKeys>();

    for (; p != end;) {
      if (end - p < 2) {
        LOG(WARN) << "Memcached: tls ticket key data is too small";
        conn_handler->on_tls_ticket_key_not_found(w);
        return;
      }
      auto len = util::get_uint16(p);
      p += 2;
      if (len != expectedlen) {
        LOG(WARN) << "Memcached: wrong tls ticket key size: want "
                  << expectedlen << ", got " << len;
        conn_handler->on_tls_ticket_key_not_found(w);
        return;
      }
      if (p + len > end) {
        LOG(WARN) << "Memcached: too short tls ticket key payload: want " << len
                  << ", got " << (end - p);
        conn_handler->on_tls_ticket_key_not_found(w);
        return;
      }
      auto key = TicketKey();
      key.cipher = get_config()->tls_ticket_key_cipher;
      key.hmac = EVP_sha256();
      key.hmac_keylen = hmac_keylen;

      std::copy_n(p, key.data.name.size(), key.data.name.data());
      p += key.data.name.size();

      std::copy_n(p, enc_keylen, key.data.enc_key.data());
      p += enc_keylen;

      std::copy_n(p, hmac_keylen, key.data.hmac_key.data());
      p += hmac_keylen;

      ticket_keys->keys.push_back(std::move(key));
    }

    conn_handler->on_tls_ticket_key_get_success(ticket_keys, w);
  };

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Memcached: tls ticket key get request sent";
  }

  dispatcher->add_request(std::move(req));
}

} // namespace

namespace {
int call_daemon() {
#ifdef __sgi
  return _daemonize(0, 0, 0, 0);
#else  // !__sgi
  return daemon(0, 0);
#endif // !__sgi
}
} // namespace

namespace {
int event_loop() {
  auto loop = EV_DEFAULT;

  auto conn_handler = make_unique<ConnectionHandler>(loop);
  if (get_config()->daemon) {
    if (call_daemon() == -1) {
      auto error = errno;
      LOG(FATAL) << "Failed to daemonize: " << strerror(error);
      exit(EXIT_FAILURE);
    }

    // We get new PID after successful daemon().
    mod_config()->pid = getpid();

    // daemon redirects stderr file descriptor to /dev/null, so we
    // need this.
    redirect_stderr_to_errorlog();
  }

  if (get_config()->pid_file) {
    save_pid();
  }

  if (get_config()->host_unix) {
    close_env_fd({ENV_LISTENER4_FD, ENV_LISTENER6_FD});
    auto acceptor = create_unix_domain_acceptor(conn_handler.get());
    if (!acceptor) {
      LOG(FATAL) << "Failed to listen on UNIX domain socket "
                 << get_config()->host.get();
      exit(EXIT_FAILURE);
    }

    conn_handler->set_acceptor(std::move(acceptor));
  } else {
    close_env_fd({ENV_UNIX_FD});
    auto acceptor6 = create_acceptor(conn_handler.get(), AF_INET6);
    auto acceptor4 = create_acceptor(conn_handler.get(), AF_INET);
    if (!acceptor6 && !acceptor4) {
      LOG(FATAL) << "Failed to listen on address " << get_config()->host.get()
                 << ", port " << get_config()->port;
      exit(EXIT_FAILURE);
    }

    conn_handler->set_acceptor(std::move(acceptor4));
    conn_handler->set_acceptor6(std::move(acceptor6));
  }

  ev_timer renew_ticket_key_timer;
  if (!get_config()->upstream_no_tls) {
    if (get_config()->tls_ticket_key_memcached_host) {
      conn_handler->set_tls_ticket_key_memcached_dispatcher(
          make_unique<MemcachedDispatcher>(
              &get_config()->tls_ticket_key_memcached_addr, loop));

      ev_timer_init(&renew_ticket_key_timer, memcached_get_ticket_key_cb, 0.,
                    0.);
      renew_ticket_key_timer.data = conn_handler.get();
      // Get first ticket keys.
      memcached_get_ticket_key_cb(loop, &renew_ticket_key_timer, 0);
    } else {
      bool auto_tls_ticket_key = true;
      if (!get_config()->tls_ticket_key_files.empty()) {
        if (!get_config()->tls_ticket_key_cipher_given) {
          LOG(WARN)
              << "It is strongly recommended to specify "
                 "--tls-ticket-key-cipher=aes-128-cbc (or "
                 "tls-ticket-key-cipher=aes-128-cbc in configuration file) "
                 "when --tls-ticket-key-file is used for the smooth "
                 "transition when the default value of --tls-ticket-key-cipher "
                 "becomes aes-256-cbc";
        }
        auto ticket_keys = read_tls_ticket_key_file(
            get_config()->tls_ticket_key_files,
            get_config()->tls_ticket_key_cipher, EVP_sha256());
        if (!ticket_keys) {
          LOG(WARN) << "Use internal session ticket key generator";
        } else {
          conn_handler->set_ticket_keys(std::move(ticket_keys));
          auto_tls_ticket_key = false;
        }
      }
      if (auto_tls_ticket_key) {
        // Generate new ticket key every 1hr.
        ev_timer_init(&renew_ticket_key_timer, renew_ticket_key_cb, 0., 1_h);
        renew_ticket_key_timer.data = conn_handler.get();
        ev_timer_again(loop, &renew_ticket_key_timer);

        // Generate first session ticket key before running workers.
        renew_ticket_key_cb(loop, &renew_ticket_key_timer, 0);
      }
    }
  }

  // ListenHandler loads private key, and we listen on a priveleged port.
  // After that, we drop the root privileges if needed.
  drop_privileges();

#ifndef NOTHREADS
  int rv;
  sigset_t signals;
  sigemptyset(&signals);
  sigaddset(&signals, REOPEN_LOG_SIGNAL);
  sigaddset(&signals, EXEC_BINARY_SIGNAL);
  sigaddset(&signals, GRACEFUL_SHUTDOWN_SIGNAL);
  rv = pthread_sigmask(SIG_BLOCK, &signals, nullptr);
  if (rv != 0) {
    LOG(ERROR) << "Blocking signals failed: " << strerror(rv);
  }
#endif // !NOTHREADS

  if (get_config()->num_worker == 1) {
    conn_handler->create_single_worker();
  } else {
    conn_handler->create_worker_thread(get_config()->num_worker);
  }

#ifndef NOTHREADS
  rv = pthread_sigmask(SIG_UNBLOCK, &signals, nullptr);
  if (rv != 0) {
    LOG(ERROR) << "Unblocking signals failed: " << strerror(rv);
  }
#endif // !NOTHREADS

  ev_signal reopen_log_sig;
  ev_signal_init(&reopen_log_sig, reopen_log_signal_cb, REOPEN_LOG_SIGNAL);
  reopen_log_sig.data = conn_handler.get();
  ev_signal_start(loop, &reopen_log_sig);

  ev_signal exec_bin_sig;
  ev_signal_init(&exec_bin_sig, exec_binary_signal_cb, EXEC_BINARY_SIGNAL);
  exec_bin_sig.data = conn_handler.get();
  ev_signal_start(loop, &exec_bin_sig);

  ev_signal graceful_shutdown_sig;
  ev_signal_init(&graceful_shutdown_sig, graceful_shutdown_signal_cb,
                 GRACEFUL_SHUTDOWN_SIGNAL);
  graceful_shutdown_sig.data = conn_handler.get();
  ev_signal_start(loop, &graceful_shutdown_sig);

  if (!get_config()->upstream_no_tls && !get_config()->no_ocsp) {
    conn_handler->proceed_next_cert_ocsp();
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Entering event loop";
  }

  ev_run(loop, 0);

  conn_handler->join_worker();
  conn_handler->cancel_ocsp_update();

  return 0;
}
} // namespace

namespace {
// Returns true if regular file or symbolic link |path| exists.
bool conf_exists(const char *path) {
  struct stat buf;
  int rv = stat(path, &buf);
  return rv == 0 && (buf.st_mode & (S_IFREG | S_IFLNK));
}
} // namespace

namespace {
constexpr char DEFAULT_NPN_LIST[] = "h2,h2-16,h2-14,"
#ifdef HAVE_SPDYLAY
                                    "spdy/3.1,"
#endif // HAVE_SPDYLAY
                                    "http/1.1";
} // namespace

namespace {
constexpr char DEFAULT_TLS_PROTO_LIST[] = "TLSv1.2,TLSv1.1";
} // namespace

namespace {
constexpr char DEFAULT_ACCESSLOG_FORMAT[] =
    R"($remote_addr - - [$time_local] )"
    R"("$request" $status $body_bytes_sent )"
    R"("$http_referer" "$http_user_agent")";
} // namespace

namespace {
constexpr char DEFAULT_DOWNSTREAM_HOST[] = "127.0.0.1";
int16_t DEFAULT_DOWNSTREAM_PORT = 80;
} // namespace;

namespace {
void fill_default_config() {
  *mod_config() = {};

  mod_config()->verbose = false;
  mod_config()->daemon = false;

  mod_config()->server_name = "nghttpx nghttp2/" NGHTTP2_VERSION;
  mod_config()->host = strcopy("*");
  mod_config()->port = 3000;
  mod_config()->private_key_file = nullptr;
  mod_config()->private_key_passwd = nullptr;
  mod_config()->cert_file = nullptr;

  // Read timeout for HTTP2 upstream connection
  mod_config()->http2_upstream_read_timeout = 3_min;

  // Read timeout for non-HTTP2 upstream connection
  mod_config()->upstream_read_timeout = 3_min;

  // Write timeout for HTTP2/non-HTTP2 upstream connection
  mod_config()->upstream_write_timeout = 30.;

  // Read/Write timeouts for downstream connection
  mod_config()->downstream_read_timeout = 3_min;
  mod_config()->downstream_write_timeout = 30.;

  // Read timeout for HTTP/2 stream
  mod_config()->stream_read_timeout = 0.;

  // Write timeout for HTTP/2 stream
  mod_config()->stream_write_timeout = 0.;

  // Timeout for pooled (idle) connections
  mod_config()->downstream_idle_read_timeout = 2.;

  // window bits for HTTP/2 and SPDY upstream/downstream connection
  // per stream. 2**16-1 = 64KiB-1, which is HTTP/2 default. Please
  // note that SPDY/3 default is 64KiB.
  mod_config()->http2_upstream_window_bits = 16;
  mod_config()->http2_downstream_window_bits = 16;

  // HTTP/2 SPDY/3.1 has connection-level flow control. The default
  // window size for HTTP/2 is 64KiB - 1. SPDY/3's default is 64KiB
  mod_config()->http2_upstream_connection_window_bits = 16;
  mod_config()->http2_downstream_connection_window_bits = 16;

  mod_config()->upstream_no_tls = false;
  mod_config()->downstream_no_tls = false;

  mod_config()->num_worker = 1;
  mod_config()->http2_max_concurrent_streams = 100;
  mod_config()->add_x_forwarded_for = false;
  mod_config()->strip_incoming_x_forwarded_for = false;
  mod_config()->no_via = false;
  mod_config()->accesslog_file = nullptr;
  mod_config()->accesslog_syslog = false;
  mod_config()->accesslog_format = parse_log_format(DEFAULT_ACCESSLOG_FORMAT);
#if defined(__ANDROID__) || defined(ANDROID)
  // Android does not have /dev/stderr.  Use /proc/self/fd/2 instead.
  mod_config()->errorlog_file = strcopy("/proc/self/fd/2");
#else  // !__ANDROID__ && ANDROID
  mod_config()->errorlog_file = strcopy("/dev/stderr");
#endif // !__ANDROID__ && ANDROID
  mod_config()->errorlog_syslog = false;
  mod_config()->conf_path = strcopy("/etc/nghttpx/nghttpx.conf");
  mod_config()->syslog_facility = LOG_DAEMON;
  // Default accept() backlog
  mod_config()->backlog = 512;
  mod_config()->ciphers = nullptr;
  mod_config()->http2_proxy = false;
  mod_config()->http2_bridge = false;
  mod_config()->client_proxy = false;
  mod_config()->client = false;
  mod_config()->client_mode = false;
  mod_config()->insecure = false;
  mod_config()->cacert = nullptr;
  mod_config()->pid_file = nullptr;
  mod_config()->user = nullptr;
  mod_config()->uid = 0;
  mod_config()->gid = 0;
  mod_config()->pid = getpid();
  mod_config()->backend_ipv4 = false;
  mod_config()->backend_ipv6 = false;
  mod_config()->downstream_http_proxy_userinfo = nullptr;
  mod_config()->downstream_http_proxy_host = nullptr;
  mod_config()->downstream_http_proxy_port = 0;
  mod_config()->read_rate = 0;
  mod_config()->read_burst = 0;
  mod_config()->write_rate = 0;
  mod_config()->write_burst = 0;
  mod_config()->worker_read_rate = 0;
  mod_config()->worker_read_burst = 0;
  mod_config()->worker_write_rate = 0;
  mod_config()->worker_write_burst = 0;
  mod_config()->verify_client = false;
  mod_config()->verify_client_cacert = nullptr;
  mod_config()->client_private_key_file = nullptr;
  mod_config()->client_cert_file = nullptr;
  mod_config()->http2_upstream_dump_request_header = nullptr;
  mod_config()->http2_upstream_dump_response_header = nullptr;
  mod_config()->http2_no_cookie_crumbling = false;
  mod_config()->upstream_frame_debug = false;
  mod_config()->padding = 0;
  mod_config()->worker_frontend_connections = 0;

  mod_config()->http2_upstream_callbacks = create_http2_upstream_callbacks();
  mod_config()->http2_downstream_callbacks =
      create_http2_downstream_callbacks();

  nghttp2_option_new(&mod_config()->http2_option);
  nghttp2_option_set_no_auto_window_update(get_config()->http2_option, 1);
  nghttp2_option_set_no_recv_client_magic(get_config()->http2_option, 1);

  nghttp2_option_new(&mod_config()->http2_client_option);
  nghttp2_option_set_no_auto_window_update(get_config()->http2_client_option,
                                           1);
  nghttp2_option_set_peer_max_concurrent_streams(
      get_config()->http2_client_option, 100);

  mod_config()->tls_proto_mask = 0;
  mod_config()->no_location_rewrite = false;
  mod_config()->no_host_rewrite = true;
  mod_config()->argc = 0;
  mod_config()->argv = nullptr;
  mod_config()->downstream_connections_per_host = 8;
  mod_config()->downstream_connections_per_frontend = 0;
  mod_config()->listener_disable_timeout = 0.;
  mod_config()->downstream_request_buffer_size = 16_k;
  mod_config()->downstream_response_buffer_size = 16_k;
  mod_config()->no_server_push = false;
  mod_config()->host_unix = false;
  mod_config()->http2_downstream_connections_per_worker = 0;
  // ocsp update interval = 14400 secs = 4 hours, borrowed from h2o
  mod_config()->ocsp_update_interval = 4_h;
  mod_config()->fetch_ocsp_response_file =
      strcopy(PKGDATADIR "/fetch-ocsp-response");
  mod_config()->no_ocsp = false;
  mod_config()->header_field_buffer = 64_k;
  mod_config()->max_header_fields = 100;
  mod_config()->downstream_addr_group_catch_all = 0;
  mod_config()->tls_ticket_key_cipher = EVP_aes_128_cbc();
  mod_config()->tls_ticket_key_cipher_given = false;
  mod_config()->tls_session_timeout = std::chrono::hours(12);
  mod_config()->tls_ticket_key_memcached_max_retry = 3;
  mod_config()->tls_ticket_key_memcached_max_fail = 2;
  mod_config()->tls_ticket_key_memcached_interval = 10_min;
}
} // namespace

namespace {
void print_version(std::ostream &out) {
  out << get_config()->server_name << std::endl;
}
} // namespace

namespace {
void print_usage(std::ostream &out) {
  out << R"(Usage: nghttpx [OPTIONS]... [<PRIVATE_KEY> <CERT>]
A reverse proxy for HTTP/2, HTTP/1 and SPDY.)" << std::endl;
}
} // namespace

namespace {
void print_help(std::ostream &out) {
  print_usage(out);
  out << R"(
  <PRIVATE_KEY>
              Set path  to server's private key.   Required unless -p,
              --client or --frontend-no-tls are given.
  <CERT>      Set path  to server's certificate.  Required  unless -p,
              --client or  --frontend-no-tls are given.  To  make OCSP
              stapling work, this must be absolute path.

Options:
  The options are categorized into several groups.

Connections:
  -b, --backend=(<HOST>,<PORT>|unix:<PATH>)[;<PATTERN>[:...]]
              Set  backend  host  and   port.   The  multiple  backend
              addresses are  accepted by repeating this  option.  UNIX
              domain socket  can be  specified by prefixing  path name
              with "unix:" (e.g., unix:/var/run/backend.sock).

              Optionally, if <PATTERN>s are given, the backend address
              is only used  if request matches the pattern.   If -s or
              -p  is  used,  <PATTERN>s   are  ignored.   The  pattern
              matching  is closely  designed to  ServeMux in  net/http
              package of Go  programming language.  <PATTERN> consists
              of path, host + path or  just host.  The path must start
              with "/".  If  it ends with "/", it  matches all request
              path in  its subtree.  To  deal with the request  to the
              directory without  trailing slash,  the path  which ends
              with "/" also matches the  request path which only lacks
              trailing '/'  (e.g., path  "/foo/" matches  request path
              "/foo").  If it does not end with "/", it performs exact
              match against  the request path.   If host is  given, it
              performs exact match against  the request host.  If host
              alone  is given,  "/"  is  appended to  it,  so that  it
              matches  all   request  paths  under  the   host  (e.g.,
              specifying "nghttp2.org" equals to "nghttp2.org/").

              Patterns with  host take  precedence over  patterns with
              just path.   Then, longer patterns take  precedence over
              shorter  ones,  breaking  a  tie by  the  order  of  the
              appearance in the configuration.

              If <PATTERN> is  omitted, "/" is used  as pattern, which
              matches  all  request  paths (catch-all  pattern).   The
              catch-all backend must be given.

              When doing  a match, nghttpx made  some normalization to
              pattern, request host and path.  For host part, they are
              converted to lower case.  For path part, percent-encoded
              unreserved characters  defined in RFC 3986  are decoded,
              and any  dot-segments (".."  and ".")   are resolved and
              removed.

              For   example,   -b'127.0.0.1,8080;nghttp2.org/httpbin/'
              matches the  request host "nghttp2.org" and  the request
              path "/httpbin/get", but does not match the request host
              "nghttp2.org" and the request path "/index.html".

              The  multiple <PATTERN>s  can  be specified,  delimiting
              them            by           ":".             Specifying
              -b'127.0.0.1,8080;nghttp2.org:www.nghttp2.org'  has  the
              same  effect  to specify  -b'127.0.0.1,8080;nghttp2.org'
              and -b'127.0.0.1,8080;www.nghttp2.org'.

              The backend addresses sharing same <PATTERN> are grouped
              together forming  load balancing  group.

              Since ";" and ":" are  used as delimiter, <PATTERN> must
              not  contain these  characters.  Since  ";" has  special
              meaning in shell, the option value must be quoted.

              Default: )" << DEFAULT_DOWNSTREAM_HOST << ","
      << DEFAULT_DOWNSTREAM_PORT << R"(
  -f, --frontend=(<HOST>,<PORT>|unix:<PATH>)
              Set  frontend  host and  port.   If  <HOST> is  '*',  it
              assumes  all addresses  including  both  IPv4 and  IPv6.
              UNIX domain  socket can  be specified by  prefixing path
              name with "unix:" (e.g., unix:/var/run/nghttpx.sock)
              Default: )" << get_config()->host.get() << ","
      << get_config()->port << R"(
  --backlog=<N>
              Set listen backlog size.
              Default: )" << get_config()->backlog << R"(
  --backend-ipv4
              Resolve backend hostname to IPv4 address only.
  --backend-ipv6
              Resolve backend hostname to IPv6 address only.
  --backend-http-proxy-uri=<URI>
              Specify      proxy       URI      in       the      form
              http://[<USER>:<PASS>@]<PROXY>:<PORT>.    If   a   proxy
              requires  authentication,  specify  <USER>  and  <PASS>.
              Note that  they must be properly  percent-encoded.  This
              proxy  is used  when the  backend connection  is HTTP/2.
              First,  make  a CONNECT  request  to  the proxy  and  it
              connects  to the  backend  on behalf  of nghttpx.   This
              forms  tunnel.   After  that, nghttpx  performs  SSL/TLS
              handshake with  the downstream through the  tunnel.  The
              timeouts when connecting and  making CONNECT request can
              be     specified    by     --backend-read-timeout    and
              --backend-write-timeout options.

Performance:
  -n, --workers=<N>
              Set the number of worker threads.
              Default: )" << get_config()->num_worker << R"(
  --read-rate=<SIZE>
              Set maximum  average read  rate on  frontend connection.
              Setting 0 to this option means read rate is unlimited.
              Default: )" << get_config()->read_rate << R"(
  --read-burst=<SIZE>
              Set  maximum read  burst  size  on frontend  connection.
              Setting  0  to this  option  means  read burst  size  is
              unlimited.
              Default: )" << get_config()->read_burst << R"(
  --write-rate=<SIZE>
              Set maximum  average write rate on  frontend connection.
              Setting 0 to this option means write rate is unlimited.
              Default: )" << get_config()->write_rate << R"(
  --write-burst=<SIZE>
              Set  maximum write  burst size  on frontend  connection.
              Setting  0 to  this  option means  write  burst size  is
              unlimited.
              Default: )" << get_config()->write_burst << R"(
  --worker-read-rate=<SIZE>
              Set maximum average read rate on frontend connection per
              worker.  Setting  0 to  this option  means read  rate is
              unlimited.  Not implemented yet.
              Default: )" << get_config()->worker_read_rate << R"(
  --worker-read-burst=<SIZE>
              Set maximum  read burst size on  frontend connection per
              worker.  Setting 0 to this  option means read burst size
              is unlimited.  Not implemented yet.
              Default: )" << get_config()->worker_read_burst << R"(
  --worker-write-rate=<SIZE>
              Set maximum  average write  rate on  frontend connection
              per worker.  Setting  0 to this option  means write rate
              is unlimited.  Not implemented yet.
              Default: )" << get_config()->worker_write_rate << R"(
  --worker-write-burst=<SIZE>
              Set maximum write burst  size on frontend connection per
              worker.  Setting 0 to this option means write burst size
              is unlimited.  Not implemented yet.
              Default: )" << get_config()->worker_write_burst << R"(
  --worker-frontend-connections=<N>
              Set maximum number  of simultaneous connections frontend
              accepts.  Setting 0 means unlimited.
              Default: )" << get_config()->worker_frontend_connections << R"(
  --backend-http2-connections-per-worker=<N>
              Set   maximum   number   of  backend   HTTP/2   physical
              connections  per  worker.   If  pattern is  used  in  -b
              option, this limit is applied  to each pattern group (in
              other  words, each  pattern group  can have  maximum <N>
              HTTP/2  connections).  The  default  value  is 0,  which
              means  that  the value  is  adjusted  to the  number  of
              backend addresses.  If pattern  is used, this adjustment
              is done for each pattern group.
  --backend-http1-connections-per-host=<N>
              Set   maximum  number   of  backend   concurrent  HTTP/1
              connections per origin host.   This option is meaningful
              when -s option  is used.  The origin  host is determined
              by  authority  portion  of requset  URI  (or  :authority
              header  field  for  HTTP/2).   To limit  the  number  of
              connections   per  frontend   for   default  mode,   use
              --backend-http1-connections-per-frontend.
              Default: )" << get_config()->downstream_connections_per_host
      << R"(
  --backend-http1-connections-per-frontend=<N>
              Set   maximum  number   of  backend   concurrent  HTTP/1
              connections per frontend.  This  option is only used for
              default mode.   0 means unlimited.  To  limit the number
              of connections  per host for  HTTP/2 or SPDY  proxy mode
              (-s option), use --backend-http1-connections-per-host.
              Default: )" << get_config()->downstream_connections_per_frontend
      << R"(
  --rlimit-nofile=<N>
              Set maximum number of open files (RLIMIT_NOFILE) to <N>.
              If 0 is given, nghttpx does not set the limit.
              Default: )" << get_config()->rlimit_nofile << R"(
  --backend-request-buffer=<SIZE>
              Set buffer size used to store backend request.
              Default: )"
      << util::utos_with_unit(get_config()->downstream_request_buffer_size)
      << R"(
  --backend-response-buffer=<SIZE>
              Set buffer size used to store backend response.
              Default: )"
      << util::utos_with_unit(get_config()->downstream_response_buffer_size)
      << R"(

Timeout:
  --frontend-http2-read-timeout=<DURATION>
              Specify  read  timeout  for  HTTP/2  and  SPDY  frontend
              connection.
              Default: )"
      << util::duration_str(get_config()->http2_upstream_read_timeout) << R"(
  --frontend-read-timeout=<DURATION>
              Specify read timeout for HTTP/1.1 frontend connection.
              Default: )"
      << util::duration_str(get_config()->upstream_read_timeout) << R"(
  --frontend-write-timeout=<DURATION>
              Specify write timeout for all frontend connections.
              Default: )"
      << util::duration_str(get_config()->upstream_write_timeout) << R"(
  --stream-read-timeout=<DURATION>
              Specify  read timeout  for HTTP/2  and SPDY  streams.  0
              means no timeout.
              Default: )"
      << util::duration_str(get_config()->stream_read_timeout) << R"(
  --stream-write-timeout=<DURATION>
              Specify write  timeout for  HTTP/2 and SPDY  streams.  0
              means no timeout.
              Default: )"
      << util::duration_str(get_config()->stream_write_timeout) << R"(
  --backend-read-timeout=<DURATION>
              Specify read timeout for backend connection.
              Default: )"
      << util::duration_str(get_config()->downstream_read_timeout) << R"(
  --backend-write-timeout=<DURATION>
              Specify write timeout for backend connection.
              Default: )"
      << util::duration_str(get_config()->downstream_write_timeout) << R"(
  --backend-keep-alive-timeout=<DURATION>
              Specify keep-alive timeout for backend connection.
              Default: )"
      << util::duration_str(get_config()->downstream_idle_read_timeout) << R"(
  --listener-disable-timeout=<DURATION>
              After accepting  connection failed,  connection listener
              is disabled  for a given  amount of time.   Specifying 0
              disables this feature.
              Default: )"
      << util::duration_str(get_config()->listener_disable_timeout) << R"(

SSL/TLS:
  --ciphers=<SUITE>
              Set allowed  cipher list.  The  format of the  string is
              described in OpenSSL ciphers(1).
  -k, --insecure
              Don't  verify   backend  server's  certificate   if  -p,
              --client    or    --http2-bridge     are    given    and
              --backend-no-tls is not given.
  --cacert=<PATH>
              Set path to trusted CA  certificate file if -p, --client
              or --http2-bridge are given  and --backend-no-tls is not
              given.  The file must be  in PEM format.  It can contain
              multiple  certificates.    If  the  linked   OpenSSL  is
              configured to  load system  wide certificates,  they are
              loaded at startup regardless of this option.
  --private-key-passwd-file=<PATH>
              Path  to file  that contains  password for  the server's
              private key.   If none is  given and the private  key is
              password protected it'll be requested interactively.
  --subcert=<KEYPATH>:<CERTPATH>
              Specify  additional certificate  and  private key  file.
              nghttpx will  choose certificates based on  the hostname
              indicated  by  client  using TLS  SNI  extension.   This
              option  can  be  used  multiple  times.   To  make  OCSP
              stapling work, <CERTPATH> must be absolute path.
  --backend-tls-sni-field=<HOST>
              Explicitly  set the  content of  the TLS  SNI extension.
              This will default to the backend HOST name.
  --dh-param-file=<PATH>
              Path to file that contains  DH parameters in PEM format.
              Without  this   option,  DHE   cipher  suites   are  not
              available.
  --npn-list=<LIST>
              Comma delimited list of  ALPN protocol identifier sorted
              in the  order of preference.  That  means most desirable
              protocol comes  first.  This  is used  in both  ALPN and
              NPN.  The parameter must be  delimited by a single comma
              only  and any  white spaces  are  treated as  a part  of
              protocol string.
              Default: )" << DEFAULT_NPN_LIST << R"(
  --verify-client
              Require and verify client certificate.
  --verify-client-cacert=<PATH>
              Path  to file  that contains  CA certificates  to verify
              client certificate.  The file must be in PEM format.  It
              can contain multiple certificates.
  --client-private-key-file=<PATH>
              Path to  file that contains  client private key  used in
              backend client authentication.
  --client-cert-file=<PATH>
              Path to  file that  contains client certificate  used in
              backend client authentication.
  --tls-proto-list=<LIST>
              Comma delimited list of  SSL/TLS protocol to be enabled.
              The following protocols  are available: TLSv1.2, TLSv1.1
              and   TLSv1.0.    The   name   matching   is   done   in
              case-insensitive   manner.    The  parameter   must   be
              delimited by  a single comma  only and any  white spaces
              are treated as a part of protocol string.
              Default: )" << DEFAULT_TLS_PROTO_LIST << R"(
  --tls-ticket-key-file=<PATH>
              Path to file that contains  random data to construct TLS
              session ticket  parameters.  If aes-128-cbc is  given in
              --tls-ticket-key-cipher, the  file must  contain exactly
              48    bytes.     If     aes-256-cbc    is    given    in
              --tls-ticket-key-cipher, the  file must  contain exactly
              80  bytes.   This  options  can be  used  repeatedly  to
              specify  multiple ticket  parameters.  If  several files
              are given,  only the  first key is  used to  encrypt TLS
              session  tickets.  Other  keys are  accepted but  server
              will  issue new  session  ticket with  first key.   This
              allows  session  key  rotation.  Please  note  that  key
              rotation  does  not  occur automatically.   User  should
              rearrange  files or  change options  values and  restart
              nghttpx gracefully.   If opening  or reading  given file
              fails, all loaded  keys are discarded and  it is treated
              as if none  of this option is given.  If  this option is
              not given or an error  occurred while opening or reading
              a file,  key is  generated every  1 hour  internally and
              they are  valid for  12 hours.   This is  recommended if
              ticket  key sharing  between  nghttpx  instances is  not
              required.
  --tls-ticket-key-memcached=<HOST>,<PORT>
              Specify  address of  memcached server  to store  session
              cache.   This  enables  shared TLS  ticket  key  between
              multiple nghttpx  instances.  nghttpx  does not  set TLS
              ticket  key  to  memcached.   The  external  ticket  key
              generator  is required.   nghttpx just  gets TLS  ticket
              keys from  memcached, and  use them,  possibly replacing
              current set of keys.  It is  up to extern TLS ticket key
              generator to  rotate keys frequently.  See  "TLS SESSION
              TICKET RESUMPTION"  section in  manual page to  know the
              data format in memcached entry.
  --tls-ticket-key-memcached-interval=<DURATION>
              Set interval to get TLS ticket keys from memcached.
              Default: )"
      << util::duration_str(get_config()->tls_ticket_key_memcached_interval)
      << R"(
  --tls-ticket-key-memcached-max-retry=<N>
              Set  maximum   number  of  consecutive   retries  before
              abandoning TLS ticket key  retrieval.  If this number is
              reached,  the  attempt  is considered  as  failure,  and
              "failure" count  is incremented by 1,  which contributed
              to            the            value            controlled
              --tls-ticket-key-memcached-max-fail option.
              Default: )" << get_config()->tls_ticket_key_memcached_max_retry
      << R"(
  --tls-ticket-key-memcached-max-fail=<N>
              Set  maximum   number  of  consecutive   failure  before
              disabling TLS ticket until next scheduled key retrieval.
              Default: )" << get_config()->tls_ticket_key_memcached_max_fail
      << R"(
  --tls-ticket-key-cipher=<CIPHER>
              Specify cipher  to encrypt TLS session  ticket.  Specify
              either   aes-128-cbc   or  aes-256-cbc.    By   default,
              aes-128-cbc is used.
  --fetch-ocsp-response-file=<PATH>
              Path to  fetch-ocsp-response script file.  It  should be
              absolute path.
              Default: )" << get_config()->fetch_ocsp_response_file.get() << R"(
  --ocsp-update-interval=<DURATION>
              Set interval to update OCSP response cache.
              Default: )"
      << util::duration_str(get_config()->ocsp_update_interval) << R"(
  --no-ocsp   Disable OCSP stapling.
  --tls-session-cache-memcached=<HOST>,<PORT>
              Specify  address of  memcached server  to store  session
              cache.   This  enables   shared  session  cache  between
              multiple nghttpx instances.

HTTP/2 and SPDY:
  -c, --http2-max-concurrent-streams=<N>
              Set the maximum number of  the concurrent streams in one
              HTTP/2 and SPDY session.
              Default: )" << get_config()->http2_max_concurrent_streams << R"(
  --frontend-http2-window-bits=<N>
              Sets the  per-stream initial window size  of HTTP/2 SPDY
              frontend connection.  For HTTP/2,  the size is 2**<N>-1.
              For SPDY, the size is 2**<N>.
              Default: )" << get_config()->http2_upstream_window_bits << R"(
  --frontend-http2-connection-window-bits=<N>
              Sets the  per-connection window size of  HTTP/2 and SPDY
              frontend   connection.    For   HTTP/2,  the   size   is
              2**<N>-1. For SPDY, the size is 2**<N>.
              Default: )" << get_config()->http2_upstream_connection_window_bits
      << R"(
  --frontend-no-tls
              Disable SSL/TLS on frontend connections.
  --backend-http2-window-bits=<N>
              Sets  the   initial  window   size  of   HTTP/2  backend
              connection to 2**<N>-1.
              Default: )" << get_config()->http2_downstream_window_bits << R"(
  --backend-http2-connection-window-bits=<N>
              Sets the  per-connection window  size of  HTTP/2 backend
              connection to 2**<N>-1.
              Default: )"
      << get_config()->http2_downstream_connection_window_bits << R"(
  --backend-no-tls
              Disable SSL/TLS on backend connections.
  --http2-no-cookie-crumbling
              Don't crumble cookie header field.
  --padding=<N>
              Add  at most  <N> bytes  to  a HTTP/2  frame payload  as
              padding.  Specify 0 to  disable padding.  This option is
              meant for debugging purpose  and not intended to enhance
              protocol security.
  --no-server-push
              Disable  HTTP/2  server  push.    Server  push  is  only
              supported  by default  mode and  HTTP/2 frontend.   SPDY
              frontend does not support server push.

Mode:
  (default mode)
              Accept  HTTP/2,  SPDY  and HTTP/1.1  over  SSL/TLS.   If
              --frontend-no-tls is  used, accept HTTP/2  and HTTP/1.1.
              The  incoming HTTP/1.1  connection  can  be upgraded  to
              HTTP/2  through  HTTP  Upgrade.   The  protocol  to  the
              backend is HTTP/1.1.
  -s, --http2-proxy
              Like default mode, but enable secure proxy mode.
  --http2-bridge
              Like default  mode, but communicate with  the backend in
              HTTP/2 over SSL/TLS.  Thus  the incoming all connections
              are converted  to HTTP/2  connection and relayed  to the
              backend.  See --backend-http-proxy-uri option if you are
              behind  the proxy  and want  to connect  to the  outside
              HTTP/2 proxy.
  --client    Accept  HTTP/2   and  HTTP/1.1  without   SSL/TLS.   The
              incoming HTTP/1.1  connection can be upgraded  to HTTP/2
              connection through  HTTP Upgrade.   The protocol  to the
              backend is HTTP/2.   To use nghttpx as  a forward proxy,
              use -p option instead.
  -p, --client-proxy
              Like --client  option, but it also  requires the request
              path from frontend must be an absolute URI, suitable for
              use as a forward proxy.

Logging:
  -L, --log-level=<LEVEL>
              Set the severity  level of log output.   <LEVEL> must be
              one of INFO, NOTICE, WARN, ERROR and FATAL.
              Default: NOTICE
  --accesslog-file=<PATH>
              Set path to write access log.  To reopen file, send USR1
              signal to nghttpx.
  --accesslog-syslog
              Send  access log  to syslog.   If this  option is  used,
              --accesslog-file option is ignored.
  --accesslog-format=<FORMAT>
              Specify  format  string  for access  log.   The  default
              format is combined format.   The following variables are
              available:

              * $remote_addr: client IP address.
              * $time_local: local time in Common Log format.
              * $time_iso8601: local time in ISO 8601 format.
              * $request: HTTP request line.
              * $status: HTTP response status code.
              * $body_bytes_sent: the  number of bytes sent  to client
                as response body.
              * $http_<VAR>: value of HTTP  request header <VAR> where
                '_' in <VAR> is replaced with '-'.
              * $remote_port: client  port.
              * $server_port: server port.
              * $request_time: request processing time in seconds with
                milliseconds resolution.
              * $pid: PID of the running process.
              * $alpn: ALPN identifier of the protocol which generates
                the response.   For HTTP/1,  ALPN is  always http/1.1,
                regardless of minor version.
              * $ssl_cipher: cipher used for SSL/TLS connection.
              * $ssl_protocol: protocol for SSL/TLS connection.
              * $ssl_session_id: session ID for SSL/TLS connection.
              * $ssl_session_reused:  "r"   if  SSL/TLS   session  was
                reused.  Otherwise, "."

              The  variable  can  be  enclosed  by  "{"  and  "}"  for
              disambiguation (e.g., ${remote_addr}).

              Default: )" << DEFAULT_ACCESSLOG_FORMAT << R"(
  --errorlog-file=<PATH>
              Set path to write error  log.  To reopen file, send USR1
              signal  to nghttpx.   stderr will  be redirected  to the
              error log file unless --errorlog-syslog is used.
              Default: )" << get_config()->errorlog_file.get() << R"(
  --errorlog-syslog
              Send  error log  to  syslog.  If  this  option is  used,
              --errorlog-file option is ignored.
  --syslog-facility=<FACILITY>
              Set syslog facility to <FACILITY>.
              Default: )" << str_syslog_facility(get_config()->syslog_facility)
      << R"(

HTTP:
  --add-x-forwarded-for
              Append  X-Forwarded-For header  field to  the downstream
              request.
  --strip-incoming-x-forwarded-for
              Strip X-Forwarded-For  header field from  inbound client
              requests.
  --no-via    Don't append to  Via header field.  If  Via header field
              is received, it is left unaltered.
  --no-location-rewrite
              Don't rewrite  location header field  on --http2-bridge,
              --client  and  default   mode.   For  --http2-proxy  and
              --client-proxy mode,  location header field will  not be
              altered regardless of this option.
  --host-rewrite
              Rewrite   host   and   :authority   header   fields   on
              --http2-bridge,   --client   and  default   mode.    For
              --http2-proxy  and  --client-proxy mode,  these  headers
              will not be altered regardless of this option.
  --altsvc=<PROTOID,PORT[,HOST,[ORIGIN]]>
              Specify   protocol  ID,   port,  host   and  origin   of
              alternative service.  <HOST>  and <ORIGIN> are optional.
              They  are advertised  in  alt-svc header  field only  in
              HTTP/1.1  frontend.  This  option can  be used  multiple
              times   to   specify  multiple   alternative   services.
              Example: --altsvc=h2,443
  --add-request-header=<HEADER>
              Specify additional header field to add to request header
              set.  This  option just  appends header field  and won't
              replace anything  already set.  This option  can be used
              several  times   to  specify  multiple   header  fields.
              Example: --add-request-header="foo: bar"
  --add-response-header=<HEADER>
              Specify  additional  header  field to  add  to  response
              header set.   This option just appends  header field and
              won't replace anything already  set.  This option can be
              used several  times to  specify multiple  header fields.
              Example: --add-response-header="foo: bar"
  --header-field-buffer=<SIZE>
              Set maximum  buffer size for incoming  HTTP header field
              list.   This is  the sum  of  header name  and value  in
              bytes.
              Default: )"
      << util::utos_with_unit(get_config()->header_field_buffer) << R"(
  --max-header-fields=<N>
              Set maximum number of incoming HTTP header fields, which
              appear in one request or response header field list.
              Default: )" << get_config()->max_header_fields << R"(

Debug:
  --frontend-http2-dump-request-header=<PATH>
              Dumps request headers received by HTTP/2 frontend to the
              file denoted  in <PATH>.  The  output is done  in HTTP/1
              header field format and each header block is followed by
              an empty line.  This option  is not thread safe and MUST
              NOT be used with option -n<N>, where <N> >= 2.
  --frontend-http2-dump-response-header=<PATH>
              Dumps response headers sent  from HTTP/2 frontend to the
              file denoted  in <PATH>.  The  output is done  in HTTP/1
              header field format and each header block is followed by
              an empty line.  This option  is not thread safe and MUST
              NOT be used with option -n<N>, where <N> >= 2.
  -o, --frontend-frame-debug
              Print HTTP/2 frames in  frontend to stderr.  This option
              is  not thread  safe and  MUST NOT  be used  with option
              -n=N, where N >= 2.

Process:
  -D, --daemon
              Run in a background.  If -D is used, the current working
              directory is changed to '/'.
  --pid-file=<PATH>
              Set path to save PID of this program.
  --user=<USER>
              Run this program as <USER>.   This option is intended to
              be used to drop root privileges.

Misc:
  --conf=<PATH>
              Load configuration from <PATH>.
              Default: )" << get_config()->conf_path.get() << R"(
  --include=<PATH>
              Load additional configurations from <PATH>.  File <PATH>
              is  read  when  configuration  parser  encountered  this
              option.  This option can be used multiple times, or even
              recursively.
  -v, --version
              Print version and exit.
  -h, --help  Print this help and exit.

--

  The <SIZE> argument is an integer and an optional unit (e.g., 10K is
  10 * 1024).  Units are K, M and G (powers of 1024).

  The <DURATION> argument is an integer and an optional unit (e.g., 1s
  is 1 second and 500ms is 500 milliseconds).  Units are h, m, s or ms
  (hours, minutes, seconds and milliseconds, respectively).  If a unit
  is omitted, a second is used as unit.)" << std::endl;
}
} // namespace

int main(int argc, char **argv) {
#ifndef NOTHREADS
  nghttp2::ssl::LibsslGlobalLock lock;
#endif // NOTHREADS
  // Initialize OpenSSL before parsing options because we create
  // SSL_CTX there.
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(nullptr);

  Log::set_severity_level(NOTICE);
  create_config();
  fill_default_config();

  // First open log files with default configuration, so that we can
  // log errors/warnings while reading configuration files.
  reopen_log_files();

  // We have to copy argv, since getopt_long may change its content.
  mod_config()->argc = argc;
  mod_config()->argv = new char *[argc];

  for (int i = 0; i < argc; ++i) {
    mod_config()->argv[i] = strdup(argv[i]);
  }

  mod_config()->cwd = getcwd(nullptr, 0);
  if (mod_config()->cwd == nullptr) {
    auto error = errno;
    LOG(FATAL) << "failed to get current working directory: errno=" << error;
    exit(EXIT_FAILURE);
  }

  std::vector<std::pair<const char *, const char *>> cmdcfgs;
  while (1) {
    static int flag = 0;
    static option long_options[] = {
        {SHRPX_OPT_DAEMON, no_argument, nullptr, 'D'},
        {SHRPX_OPT_LOG_LEVEL, required_argument, nullptr, 'L'},
        {SHRPX_OPT_BACKEND, required_argument, nullptr, 'b'},
        {SHRPX_OPT_HTTP2_MAX_CONCURRENT_STREAMS, required_argument, nullptr,
         'c'},
        {SHRPX_OPT_FRONTEND, required_argument, nullptr, 'f'},
        {"help", no_argument, nullptr, 'h'},
        {SHRPX_OPT_INSECURE, no_argument, nullptr, 'k'},
        {SHRPX_OPT_WORKERS, required_argument, nullptr, 'n'},
        {SHRPX_OPT_CLIENT_PROXY, no_argument, nullptr, 'p'},
        {SHRPX_OPT_HTTP2_PROXY, no_argument, nullptr, 's'},
        {"version", no_argument, nullptr, 'v'},
        {SHRPX_OPT_FRONTEND_FRAME_DEBUG, no_argument, nullptr, 'o'},
        {SHRPX_OPT_ADD_X_FORWARDED_FOR, no_argument, &flag, 1},
        {SHRPX_OPT_FRONTEND_HTTP2_READ_TIMEOUT, required_argument, &flag, 2},
        {SHRPX_OPT_FRONTEND_READ_TIMEOUT, required_argument, &flag, 3},
        {SHRPX_OPT_FRONTEND_WRITE_TIMEOUT, required_argument, &flag, 4},
        {SHRPX_OPT_BACKEND_READ_TIMEOUT, required_argument, &flag, 5},
        {SHRPX_OPT_BACKEND_WRITE_TIMEOUT, required_argument, &flag, 6},
        {SHRPX_OPT_ACCESSLOG_FILE, required_argument, &flag, 7},
        {SHRPX_OPT_BACKEND_KEEP_ALIVE_TIMEOUT, required_argument, &flag, 8},
        {SHRPX_OPT_FRONTEND_HTTP2_WINDOW_BITS, required_argument, &flag, 9},
        {SHRPX_OPT_PID_FILE, required_argument, &flag, 10},
        {SHRPX_OPT_USER, required_argument, &flag, 11},
        {"conf", required_argument, &flag, 12},
        {SHRPX_OPT_SYSLOG_FACILITY, required_argument, &flag, 14},
        {SHRPX_OPT_BACKLOG, required_argument, &flag, 15},
        {SHRPX_OPT_CIPHERS, required_argument, &flag, 16},
        {SHRPX_OPT_CLIENT, no_argument, &flag, 17},
        {SHRPX_OPT_BACKEND_HTTP2_WINDOW_BITS, required_argument, &flag, 18},
        {SHRPX_OPT_CACERT, required_argument, &flag, 19},
        {SHRPX_OPT_BACKEND_IPV4, no_argument, &flag, 20},
        {SHRPX_OPT_BACKEND_IPV6, no_argument, &flag, 21},
        {SHRPX_OPT_PRIVATE_KEY_PASSWD_FILE, required_argument, &flag, 22},
        {SHRPX_OPT_NO_VIA, no_argument, &flag, 23},
        {SHRPX_OPT_SUBCERT, required_argument, &flag, 24},
        {SHRPX_OPT_HTTP2_BRIDGE, no_argument, &flag, 25},
        {SHRPX_OPT_BACKEND_HTTP_PROXY_URI, required_argument, &flag, 26},
        {SHRPX_OPT_BACKEND_NO_TLS, no_argument, &flag, 27},
        {SHRPX_OPT_FRONTEND_NO_TLS, no_argument, &flag, 29},
        {SHRPX_OPT_BACKEND_TLS_SNI_FIELD, required_argument, &flag, 31},
        {SHRPX_OPT_DH_PARAM_FILE, required_argument, &flag, 33},
        {SHRPX_OPT_READ_RATE, required_argument, &flag, 34},
        {SHRPX_OPT_READ_BURST, required_argument, &flag, 35},
        {SHRPX_OPT_WRITE_RATE, required_argument, &flag, 36},
        {SHRPX_OPT_WRITE_BURST, required_argument, &flag, 37},
        {SHRPX_OPT_NPN_LIST, required_argument, &flag, 38},
        {SHRPX_OPT_VERIFY_CLIENT, no_argument, &flag, 39},
        {SHRPX_OPT_VERIFY_CLIENT_CACERT, required_argument, &flag, 40},
        {SHRPX_OPT_CLIENT_PRIVATE_KEY_FILE, required_argument, &flag, 41},
        {SHRPX_OPT_CLIENT_CERT_FILE, required_argument, &flag, 42},
        {SHRPX_OPT_FRONTEND_HTTP2_DUMP_REQUEST_HEADER, required_argument, &flag,
         43},
        {SHRPX_OPT_FRONTEND_HTTP2_DUMP_RESPONSE_HEADER, required_argument,
         &flag, 44},
        {SHRPX_OPT_HTTP2_NO_COOKIE_CRUMBLING, no_argument, &flag, 45},
        {SHRPX_OPT_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS, required_argument,
         &flag, 46},
        {SHRPX_OPT_BACKEND_HTTP2_CONNECTION_WINDOW_BITS, required_argument,
         &flag, 47},
        {SHRPX_OPT_TLS_PROTO_LIST, required_argument, &flag, 48},
        {SHRPX_OPT_PADDING, required_argument, &flag, 49},
        {SHRPX_OPT_WORKER_READ_RATE, required_argument, &flag, 50},
        {SHRPX_OPT_WORKER_READ_BURST, required_argument, &flag, 51},
        {SHRPX_OPT_WORKER_WRITE_RATE, required_argument, &flag, 52},
        {SHRPX_OPT_WORKER_WRITE_BURST, required_argument, &flag, 53},
        {SHRPX_OPT_ALTSVC, required_argument, &flag, 54},
        {SHRPX_OPT_ADD_RESPONSE_HEADER, required_argument, &flag, 55},
        {SHRPX_OPT_WORKER_FRONTEND_CONNECTIONS, required_argument, &flag, 56},
        {SHRPX_OPT_ACCESSLOG_SYSLOG, no_argument, &flag, 57},
        {SHRPX_OPT_ERRORLOG_FILE, required_argument, &flag, 58},
        {SHRPX_OPT_ERRORLOG_SYSLOG, no_argument, &flag, 59},
        {SHRPX_OPT_STREAM_READ_TIMEOUT, required_argument, &flag, 60},
        {SHRPX_OPT_STREAM_WRITE_TIMEOUT, required_argument, &flag, 61},
        {SHRPX_OPT_NO_LOCATION_REWRITE, no_argument, &flag, 62},
        {SHRPX_OPT_BACKEND_HTTP1_CONNECTIONS_PER_HOST, required_argument, &flag,
         63},
        {SHRPX_OPT_LISTENER_DISABLE_TIMEOUT, required_argument, &flag, 64},
        {SHRPX_OPT_STRIP_INCOMING_X_FORWARDED_FOR, no_argument, &flag, 65},
        {SHRPX_OPT_ACCESSLOG_FORMAT, required_argument, &flag, 66},
        {SHRPX_OPT_BACKEND_HTTP1_CONNECTIONS_PER_FRONTEND, required_argument,
         &flag, 67},
        {SHRPX_OPT_TLS_TICKET_KEY_FILE, required_argument, &flag, 68},
        {SHRPX_OPT_RLIMIT_NOFILE, required_argument, &flag, 69},
        {SHRPX_OPT_BACKEND_RESPONSE_BUFFER, required_argument, &flag, 71},
        {SHRPX_OPT_BACKEND_REQUEST_BUFFER, required_argument, &flag, 72},
        {SHRPX_OPT_NO_HOST_REWRITE, no_argument, &flag, 73},
        {SHRPX_OPT_NO_SERVER_PUSH, no_argument, &flag, 74},
        {SHRPX_OPT_BACKEND_HTTP2_CONNECTIONS_PER_WORKER, required_argument,
         &flag, 76},
        {SHRPX_OPT_FETCH_OCSP_RESPONSE_FILE, required_argument, &flag, 77},
        {SHRPX_OPT_OCSP_UPDATE_INTERVAL, required_argument, &flag, 78},
        {SHRPX_OPT_NO_OCSP, no_argument, &flag, 79},
        {SHRPX_OPT_HEADER_FIELD_BUFFER, required_argument, &flag, 80},
        {SHRPX_OPT_MAX_HEADER_FIELDS, required_argument, &flag, 81},
        {SHRPX_OPT_ADD_REQUEST_HEADER, required_argument, &flag, 82},
        {SHRPX_OPT_INCLUDE, required_argument, &flag, 83},
        {SHRPX_OPT_TLS_TICKET_KEY_CIPHER, required_argument, &flag, 84},
        {SHRPX_OPT_HOST_REWRITE, no_argument, &flag, 85},
        {SHRPX_OPT_TLS_SESSION_CACHE_MEMCACHED, required_argument, &flag, 86},
        {SHRPX_OPT_TLS_TICKET_KEY_MEMCACHED, required_argument, &flag, 87},
        {SHRPX_OPT_TLS_TICKET_KEY_MEMCACHED_INTERVAL, required_argument, &flag,
         88},
        {SHRPX_OPT_TLS_TICKET_KEY_MEMCACHED_MAX_RETRY, required_argument, &flag,
         89},
        {SHRPX_OPT_TLS_TICKET_KEY_MEMCACHED_MAX_FAIL, required_argument, &flag,
         90},
        {nullptr, 0, nullptr, 0}};

    int option_index = 0;
    int c = getopt_long(argc, argv, "DL:b:c:f:hkn:opsv", long_options,
                        &option_index);
    if (c == -1) {
      break;
    }
    switch (c) {
    case 'D':
      cmdcfgs.emplace_back(SHRPX_OPT_DAEMON, "yes");
      break;
    case 'L':
      cmdcfgs.emplace_back(SHRPX_OPT_LOG_LEVEL, optarg);
      break;
    case 'b':
      cmdcfgs.emplace_back(SHRPX_OPT_BACKEND, optarg);
      break;
    case 'c':
      cmdcfgs.emplace_back(SHRPX_OPT_HTTP2_MAX_CONCURRENT_STREAMS, optarg);
      break;
    case 'f':
      cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND, optarg);
      break;
    case 'h':
      print_help(std::cout);
      exit(EXIT_SUCCESS);
    case 'k':
      cmdcfgs.emplace_back(SHRPX_OPT_INSECURE, "yes");
      break;
    case 'n':
#ifdef NOTHREADS
      LOG(WARN) << "Threading disabled at build time, no threads created.";
#else
      cmdcfgs.emplace_back(SHRPX_OPT_WORKERS, optarg);
#endif // NOTHREADS
      break;
    case 'o':
      cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_FRAME_DEBUG, "yes");
      break;
    case 'p':
      cmdcfgs.emplace_back(SHRPX_OPT_CLIENT_PROXY, "yes");
      break;
    case 's':
      cmdcfgs.emplace_back(SHRPX_OPT_HTTP2_PROXY, "yes");
      break;
    case 'v':
      print_version(std::cout);
      exit(EXIT_SUCCESS);
    case '?':
      util::show_candidates(argv[optind - 1], long_options);
      exit(EXIT_FAILURE);
    case 0:
      switch (flag) {
      case 1:
        // --add-x-forwarded-for
        cmdcfgs.emplace_back(SHRPX_OPT_ADD_X_FORWARDED_FOR, "yes");
        break;
      case 2:
        // --frontend-http2-read-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_READ_TIMEOUT, optarg);
        break;
      case 3:
        // --frontend-read-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_READ_TIMEOUT, optarg);
        break;
      case 4:
        // --frontend-write-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_WRITE_TIMEOUT, optarg);
        break;
      case 5:
        // --backend-read-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_READ_TIMEOUT, optarg);
        break;
      case 6:
        // --backend-write-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_WRITE_TIMEOUT, optarg);
        break;
      case 7:
        cmdcfgs.emplace_back(SHRPX_OPT_ACCESSLOG_FILE, optarg);
        break;
      case 8:
        // --backend-keep-alive-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_KEEP_ALIVE_TIMEOUT, optarg);
        break;
      case 9:
        // --frontend-http2-window-bits
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_WINDOW_BITS, optarg);
        break;
      case 10:
        cmdcfgs.emplace_back(SHRPX_OPT_PID_FILE, optarg);
        break;
      case 11:
        cmdcfgs.emplace_back(SHRPX_OPT_USER, optarg);
        break;
      case 12:
        // --conf
        mod_config()->conf_path = strcopy(optarg);
        break;
      case 14:
        // --syslog-facility
        cmdcfgs.emplace_back(SHRPX_OPT_SYSLOG_FACILITY, optarg);
        break;
      case 15:
        // --backlog
        cmdcfgs.emplace_back(SHRPX_OPT_BACKLOG, optarg);
        break;
      case 16:
        // --ciphers
        cmdcfgs.emplace_back(SHRPX_OPT_CIPHERS, optarg);
        break;
      case 17:
        // --client
        cmdcfgs.emplace_back(SHRPX_OPT_CLIENT, "yes");
        break;
      case 18:
        // --backend-http2-window-bits
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_HTTP2_WINDOW_BITS, optarg);
        break;
      case 19:
        // --cacert
        cmdcfgs.emplace_back(SHRPX_OPT_CACERT, optarg);
        break;
      case 20:
        // --backend-ipv4
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_IPV4, "yes");
        break;
      case 21:
        // --backend-ipv6
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_IPV6, "yes");
        break;
      case 22:
        // --private-key-passwd-file
        cmdcfgs.emplace_back(SHRPX_OPT_PRIVATE_KEY_PASSWD_FILE, optarg);
        break;
      case 23:
        // --no-via
        cmdcfgs.emplace_back(SHRPX_OPT_NO_VIA, "yes");
        break;
      case 24:
        // --subcert
        cmdcfgs.emplace_back(SHRPX_OPT_SUBCERT, optarg);
        break;
      case 25:
        // --http2-bridge
        cmdcfgs.emplace_back(SHRPX_OPT_HTTP2_BRIDGE, "yes");
        break;
      case 26:
        // --backend-http-proxy-uri
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_HTTP_PROXY_URI, optarg);
        break;
      case 27:
        // --backend-no-tls
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_NO_TLS, "yes");
        break;
      case 29:
        // --frontend-no-tls
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_NO_TLS, "yes");
        break;
      case 31:
        // --backend-tls-sni-field
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_TLS_SNI_FIELD, optarg);
        break;
      case 33:
        // --dh-param-file
        cmdcfgs.emplace_back(SHRPX_OPT_DH_PARAM_FILE, optarg);
        break;
      case 34:
        // --read-rate
        cmdcfgs.emplace_back(SHRPX_OPT_READ_RATE, optarg);
        break;
      case 35:
        // --read-burst
        cmdcfgs.emplace_back(SHRPX_OPT_READ_BURST, optarg);
        break;
      case 36:
        // --write-rate
        cmdcfgs.emplace_back(SHRPX_OPT_WRITE_RATE, optarg);
        break;
      case 37:
        // --write-burst
        cmdcfgs.emplace_back(SHRPX_OPT_WRITE_BURST, optarg);
        break;
      case 38:
        // --npn-list
        cmdcfgs.emplace_back(SHRPX_OPT_NPN_LIST, optarg);
        break;
      case 39:
        // --verify-client
        cmdcfgs.emplace_back(SHRPX_OPT_VERIFY_CLIENT, "yes");
        break;
      case 40:
        // --verify-client-cacert
        cmdcfgs.emplace_back(SHRPX_OPT_VERIFY_CLIENT_CACERT, optarg);
        break;
      case 41:
        // --client-private-key-file
        cmdcfgs.emplace_back(SHRPX_OPT_CLIENT_PRIVATE_KEY_FILE, optarg);
        break;
      case 42:
        // --client-cert-file
        cmdcfgs.emplace_back(SHRPX_OPT_CLIENT_CERT_FILE, optarg);
        break;
      case 43:
        // --frontend-http2-dump-request-header
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_DUMP_REQUEST_HEADER,
                             optarg);
        break;
      case 44:
        // --frontend-http2-dump-response-header
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_DUMP_RESPONSE_HEADER,
                             optarg);
        break;
      case 45:
        // --http2-no-cookie-crumbling
        cmdcfgs.emplace_back(SHRPX_OPT_HTTP2_NO_COOKIE_CRUMBLING, "yes");
        break;
      case 46:
        // --frontend-http2-connection-window-bits
        cmdcfgs.emplace_back(SHRPX_OPT_FRONTEND_HTTP2_CONNECTION_WINDOW_BITS,
                             optarg);
        break;
      case 47:
        // --backend-http2-connection-window-bits
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_HTTP2_CONNECTION_WINDOW_BITS,
                             optarg);
        break;
      case 48:
        // --tls-proto-list
        cmdcfgs.emplace_back(SHRPX_OPT_TLS_PROTO_LIST, optarg);
        break;
      case 49:
        // --padding
        cmdcfgs.emplace_back(SHRPX_OPT_PADDING, optarg);
        break;
      case 50:
        // --worker-read-rate
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_READ_RATE, optarg);
        break;
      case 51:
        // --worker-read-burst
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_READ_BURST, optarg);
        break;
      case 52:
        // --worker-write-rate
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_WRITE_RATE, optarg);
        break;
      case 53:
        // --worker-write-burst
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_WRITE_BURST, optarg);
        break;
      case 54:
        // --altsvc
        cmdcfgs.emplace_back(SHRPX_OPT_ALTSVC, optarg);
        break;
      case 55:
        // --add-response-header
        cmdcfgs.emplace_back(SHRPX_OPT_ADD_RESPONSE_HEADER, optarg);
        break;
      case 56:
        // --worker-frontend-connections
        cmdcfgs.emplace_back(SHRPX_OPT_WORKER_FRONTEND_CONNECTIONS, optarg);
        break;
      case 57:
        // --accesslog-syslog
        cmdcfgs.emplace_back(SHRPX_OPT_ACCESSLOG_SYSLOG, "yes");
        break;
      case 58:
        // --errorlog-file
        cmdcfgs.emplace_back(SHRPX_OPT_ERRORLOG_FILE, optarg);
        break;
      case 59:
        // --errorlog-syslog
        cmdcfgs.emplace_back(SHRPX_OPT_ERRORLOG_SYSLOG, "yes");
        break;
      case 60:
        // --stream-read-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_STREAM_READ_TIMEOUT, optarg);
        break;
      case 61:
        // --stream-write-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_STREAM_WRITE_TIMEOUT, optarg);
        break;
      case 62:
        // --no-location-rewrite
        cmdcfgs.emplace_back(SHRPX_OPT_NO_LOCATION_REWRITE, "yes");
        break;
      case 63:
        // --backend-http1-connections-per-host
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_HTTP1_CONNECTIONS_PER_HOST,
                             optarg);
        break;
      case 64:
        // --listener-disable-timeout
        cmdcfgs.emplace_back(SHRPX_OPT_LISTENER_DISABLE_TIMEOUT, optarg);
        break;
      case 65:
        // --strip-incoming-x-forwarded-for
        cmdcfgs.emplace_back(SHRPX_OPT_STRIP_INCOMING_X_FORWARDED_FOR, "yes");
        break;
      case 66:
        // --accesslog-format
        cmdcfgs.emplace_back(SHRPX_OPT_ACCESSLOG_FORMAT, optarg);
        break;
      case 67:
        // --backend-http1-connections-per-frontend
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_HTTP1_CONNECTIONS_PER_FRONTEND,
                             optarg);
        break;
      case 68:
        // --tls-ticket-key-file
        cmdcfgs.emplace_back(SHRPX_OPT_TLS_TICKET_KEY_FILE, optarg);
        break;
      case 69:
        // --rlimit-nofile
        cmdcfgs.emplace_back(SHRPX_OPT_RLIMIT_NOFILE, optarg);
        break;
      case 71:
        // --backend-response-buffer
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_RESPONSE_BUFFER, optarg);
        break;
      case 72:
        // --backend-request-buffer
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_REQUEST_BUFFER, optarg);
        break;
      case 73:
        // --no-host-rewrite
        cmdcfgs.emplace_back(SHRPX_OPT_NO_HOST_REWRITE, "yes");
        break;
      case 74:
        // --no-server-push
        cmdcfgs.emplace_back(SHRPX_OPT_NO_SERVER_PUSH, "yes");
        break;
      case 76:
        // --backend-http2-connections-per-worker
        cmdcfgs.emplace_back(SHRPX_OPT_BACKEND_HTTP2_CONNECTIONS_PER_WORKER,
                             optarg);
        break;
      case 77:
        // --fetch-ocsp-response-file
        cmdcfgs.emplace_back(SHRPX_OPT_FETCH_OCSP_RESPONSE_FILE, optarg);
        break;
      case 78:
        // --ocsp-update-interval
        cmdcfgs.emplace_back(SHRPX_OPT_OCSP_UPDATE_INTERVAL, optarg);
        break;
      case 79:
        // --no-ocsp
        cmdcfgs.emplace_back(SHRPX_OPT_NO_OCSP, "yes");
        break;
      case 80:
        // --header-field-buffer
        cmdcfgs.emplace_back(SHRPX_OPT_HEADER_FIELD_BUFFER, optarg);
        break;
      case 81:
        // --max-header-fields
        cmdcfgs.emplace_back(SHRPX_OPT_MAX_HEADER_FIELDS, optarg);
        break;
      case 82:
        // --add-request-header
        cmdcfgs.emplace_back(SHRPX_OPT_ADD_REQUEST_HEADER, optarg);
        break;
      case 83:
        // --include
        cmdcfgs.emplace_back(SHRPX_OPT_INCLUDE, optarg);
        break;
      case 84:
        // --tls-ticket-key-cipher
        cmdcfgs.emplace_back(SHRPX_OPT_TLS_TICKET_KEY_CIPHER, optarg);
        break;
      case 85:
        // --host-rewrite
        cmdcfgs.emplace_back(SHRPX_OPT_HOST_REWRITE, "yes");
        break;
      case 86:
        // --tls-session-cache-memcached
        cmdcfgs.emplace_back(SHRPX_OPT_TLS_SESSION_CACHE_MEMCACHED, optarg);
        break;
      case 87:
        // --tls-ticket-key-memcached
        cmdcfgs.emplace_back(SHRPX_OPT_TLS_TICKET_KEY_MEMCACHED, optarg);
        break;
      case 88:
        // --tls-ticket-key-memcached-interval
        cmdcfgs.emplace_back(SHRPX_OPT_TLS_TICKET_KEY_MEMCACHED_INTERVAL,
                             optarg);
        break;
      case 89:
        // --tls-ticket-key-memcached-max-retry
        cmdcfgs.emplace_back(SHRPX_OPT_TLS_TICKET_KEY_MEMCACHED_MAX_RETRY,
                             optarg);
        break;
      case 90:
        // --tls-ticket-key-memcached-max-fail
        cmdcfgs.emplace_back(SHRPX_OPT_TLS_TICKET_KEY_MEMCACHED_MAX_FAIL,
                             optarg);
        break;
      default:
        break;
      }
      break;
    default:
      break;
    }
  }

  if (conf_exists(get_config()->conf_path.get())) {
    std::set<std::string> include_set;
    if (load_config(get_config()->conf_path.get(), include_set) == -1) {
      LOG(FATAL) << "Failed to load configuration from "
                 << get_config()->conf_path.get();
      exit(EXIT_FAILURE);
    }
    assert(include_set.empty());
  }

  if (argc - optind >= 2) {
    cmdcfgs.emplace_back(SHRPX_OPT_PRIVATE_KEY_FILE, argv[optind++]);
    cmdcfgs.emplace_back(SHRPX_OPT_CERTIFICATE_FILE, argv[optind++]);
  }

  // Reopen log files using configurations in file
  reopen_log_files();

  {
    std::set<std::string> include_set;

    for (size_t i = 0, len = cmdcfgs.size(); i < len; ++i) {
      if (parse_config(cmdcfgs[i].first, cmdcfgs[i].second, include_set) ==
          -1) {
        LOG(FATAL) << "Failed to parse command-line argument.";
        exit(EXIT_FAILURE);
      }
    }

    assert(include_set.empty());
  }

  if (get_config()->accesslog_syslog || get_config()->errorlog_syslog) {
    openlog("nghttpx", LOG_NDELAY | LOG_NOWAIT | LOG_PID,
            get_config()->syslog_facility);
  }

  if (reopen_log_files() != 0) {
    LOG(FATAL) << "Failed to open log file";
    exit(EXIT_FAILURE);
  }

  redirect_stderr_to_errorlog();

  if (get_config()->uid != 0) {
    if (log_config()->accesslog_fd != -1 &&
        fchown(log_config()->accesslog_fd, get_config()->uid,
               get_config()->gid) == -1) {
      auto error = errno;
      LOG(WARN) << "Changing owner of access log file failed: "
                << strerror(error);
    }
    if (log_config()->errorlog_fd != -1 &&
        fchown(log_config()->errorlog_fd, get_config()->uid,
               get_config()->gid) == -1) {
      auto error = errno;
      LOG(WARN) << "Changing owner of error log file failed: "
                << strerror(error);
    }
  }

  if (get_config()->http2_upstream_dump_request_header_file) {
    auto path = get_config()->http2_upstream_dump_request_header_file.get();
    auto f = open_file_for_write(path);

    if (f == nullptr) {
      LOG(FATAL) << "Failed to open http2 upstream request header file: "
                 << path;
      exit(EXIT_FAILURE);
    }

    mod_config()->http2_upstream_dump_request_header = f;

    if (get_config()->uid != 0) {
      if (chown(path, get_config()->uid, get_config()->gid) == -1) {
        auto error = errno;
        LOG(WARN) << "Changing owner of http2 upstream request header file "
                  << path << " failed: " << strerror(error);
      }
    }
  }

  if (get_config()->http2_upstream_dump_response_header_file) {
    auto path = get_config()->http2_upstream_dump_response_header_file.get();
    auto f = open_file_for_write(path);

    if (f == nullptr) {
      LOG(FATAL) << "Failed to open http2 upstream response header file: "
                 << path;
      exit(EXIT_FAILURE);
    }

    mod_config()->http2_upstream_dump_response_header = f;

    if (get_config()->uid != 0) {
      if (chown(path, get_config()->uid, get_config()->gid) == -1) {
        auto error = errno;
        LOG(WARN) << "Changing owner of http2 upstream response header file"
                  << " " << path << " failed: " << strerror(error);
      }
    }
  }

  if (get_config()->npn_list.empty()) {
    mod_config()->npn_list = parse_config_str_list(DEFAULT_NPN_LIST);
  }
  if (get_config()->tls_proto_list.empty()) {
    mod_config()->tls_proto_list =
        parse_config_str_list(DEFAULT_TLS_PROTO_LIST);
  }

  mod_config()->tls_proto_mask =
      ssl::create_tls_proto_mask(get_config()->tls_proto_list);

  mod_config()->alpn_prefs = ssl::set_alpn_prefs(get_config()->npn_list);

  if (get_config()->backend_ipv4 && get_config()->backend_ipv6) {
    LOG(FATAL) << "--backend-ipv4 and --backend-ipv6 cannot be used at the "
               << "same time.";
    exit(EXIT_FAILURE);
  }

  if (get_config()->worker_frontend_connections == 0) {
    mod_config()->worker_frontend_connections =
        std::numeric_limits<size_t>::max();
  }

  if (get_config()->http2_proxy + get_config()->http2_bridge +
          get_config()->client_proxy + get_config()->client >
      1) {
    LOG(FATAL) << "--http2-proxy, --http2-bridge, --client-proxy and --client "
               << "cannot be used at the same time.";
    exit(EXIT_FAILURE);
  }

  if (get_config()->client || get_config()->client_proxy) {
    mod_config()->client_mode = true;
    mod_config()->upstream_no_tls = true;
  }

  if (get_config()->client_mode || get_config()->http2_bridge) {
    mod_config()->downstream_proto = PROTO_HTTP2;
  } else {
    mod_config()->downstream_proto = PROTO_HTTP;
  }

  if (!get_config()->upstream_no_tls &&
      (!get_config()->private_key_file || !get_config()->cert_file)) {
    print_usage(std::cerr);
    LOG(FATAL) << "Too few arguments";
    exit(EXIT_FAILURE);
  }

  if (!get_config()->upstream_no_tls && !get_config()->no_ocsp) {
    struct stat buf;
    if (stat(get_config()->fetch_ocsp_response_file.get(), &buf) != 0) {
      mod_config()->no_ocsp = true;
      LOG(WARN) << "--fetch-ocsp-response-file: "
                << get_config()->fetch_ocsp_response_file.get()
                << " not found.  OCSP stapling has been disabled.";
    }
  }

  if (get_config()->downstream_addr_groups.empty()) {
    DownstreamAddr addr;
    addr.host = strcopy(DEFAULT_DOWNSTREAM_HOST);
    addr.port = DEFAULT_DOWNSTREAM_PORT;

    DownstreamAddrGroup g("/");
    g.addrs.push_back(std::move(addr));
    mod_config()->downstream_addr_groups.push_back(std::move(g));
  } else if (get_config()->http2_proxy || get_config()->client_proxy) {
    // We don't support host mapping in these cases.  Move all
    // non-catch-all patterns to catch-all pattern.
    DownstreamAddrGroup catch_all("/");
    for (auto &g : mod_config()->downstream_addr_groups) {
      std::move(std::begin(g.addrs), std::end(g.addrs),
                std::back_inserter(catch_all.addrs));
    }
    std::vector<DownstreamAddrGroup>().swap(
        mod_config()->downstream_addr_groups);
    mod_config()->downstream_addr_groups.push_back(std::move(catch_all));
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Resolving backend address";
  }

  ssize_t catch_all_group = -1;
  for (size_t i = 0; i < mod_config()->downstream_addr_groups.size(); ++i) {
    auto &g = mod_config()->downstream_addr_groups[i];
    if (g.pattern == "/") {
      catch_all_group = i;
    }
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Host-path pattern: group " << i << ": '" << g.pattern
                << "'";
      for (auto &addr : g.addrs) {
        LOG(INFO) << "group " << i << " -> " << addr.host.get()
                  << (addr.host_unix ? "" : ":" + util::utos(addr.port));
      }
    }
  }

  if (catch_all_group == -1) {
    LOG(FATAL) << "-b: No catch-all backend address is configured";
    exit(EXIT_FAILURE);
  }
  mod_config()->downstream_addr_group_catch_all = catch_all_group;

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "Catch-all pattern is group " << catch_all_group;
  }

  for (auto &g : mod_config()->downstream_addr_groups) {
    for (auto &addr : g.addrs) {

      if (addr.host_unix) {
        // for AF_UNIX socket, we use "localhost" as host for backend
        // hostport.  This is used as Host header field to backend and
        // not going to be passed to any syscalls.
        addr.hostport =
            strcopy(util::make_hostport("localhost", get_config()->port));

        auto path = addr.host.get();
        auto pathlen = strlen(path);

        if (pathlen + 1 > sizeof(addr.addr.su.un.sun_path)) {
          LOG(FATAL) << "UNIX domain socket path " << path << " is too long > "
                     << sizeof(addr.addr.su.un.sun_path);
          exit(EXIT_FAILURE);
        }

        LOG(INFO) << "Use UNIX domain socket path " << path
                  << " for backend connection";

        addr.addr.su.un.sun_family = AF_UNIX;
        // copy path including terminal NULL
        std::copy_n(path, pathlen + 1, addr.addr.su.un.sun_path);
        addr.addr.len = sizeof(addr.addr.su.un);

        continue;
      }

      addr.hostport = strcopy(util::make_hostport(addr.host.get(), addr.port));

      if (resolve_hostname(
              &addr.addr, addr.host.get(), addr.port,
              get_config()->backend_ipv4 ? AF_INET : (get_config()->backend_ipv6
                                                          ? AF_INET6
                                                          : AF_UNSPEC)) == -1) {
        exit(EXIT_FAILURE);
      }
    }
  }

  if (get_config()->downstream_http_proxy_host) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "Resolving backend http proxy address";
    }
    if (resolve_hostname(&mod_config()->downstream_http_proxy_addr,
                         get_config()->downstream_http_proxy_host.get(),
                         get_config()->downstream_http_proxy_port,
                         AF_UNSPEC) == -1) {
      exit(EXIT_FAILURE);
    }
  }

  if (get_config()->session_cache_memcached_host) {
    if (resolve_hostname(&mod_config()->session_cache_memcached_addr,
                         get_config()->session_cache_memcached_host.get(),
                         get_config()->session_cache_memcached_port,
                         AF_UNSPEC) == -1) {
      exit(EXIT_FAILURE);
    }
  }

  if (get_config()->tls_ticket_key_memcached_host) {
    if (resolve_hostname(&mod_config()->tls_ticket_key_memcached_addr,
                         get_config()->tls_ticket_key_memcached_host.get(),
                         get_config()->tls_ticket_key_memcached_port,
                         AF_UNSPEC) == -1) {
      exit(EXIT_FAILURE);
    }
  }

  if (get_config()->rlimit_nofile) {
    struct rlimit lim = {static_cast<rlim_t>(get_config()->rlimit_nofile),
                         static_cast<rlim_t>(get_config()->rlimit_nofile)};
    if (setrlimit(RLIMIT_NOFILE, &lim) != 0) {
      auto error = errno;
      LOG(WARN) << "Setting rlimit-nofile failed: " << strerror(error);
    }
  }

  if (get_config()->upstream_frame_debug) {
    // To make it sync to logging
    set_output(stderr);
    if (isatty(fileno(stdout))) {
      set_color_output(true);
    }
    reset_timer();
  }

  struct sigaction act {};
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, nullptr);

  event_loop();

  LOG(NOTICE) << "Shutdown momentarily";

  return 0;
}

} // namespace shrpx

int main(int argc, char **argv) { return shrpx::main(argc, argv); }
