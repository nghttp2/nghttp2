/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2021 Tatsuhiro Tsujikawa
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
#include "shrpx_quic.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/udp.h>

#include <array>
#include <chrono>

#include <ngtcp2/ngtcp2_crypto.h>

#include <nghttp3/nghttp3.h>

#include <openssl/rand.h>

#include "shrpx_config.h"
#include "shrpx_log.h"
#include "util.h"
#include "xsi_strerror.h"

using namespace nghttp2;

namespace shrpx {

ngtcp2_tstamp quic_timestamp() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

int create_quic_server_socket(UpstreamAddr &faddr) {
  std::array<char, STRERROR_BUFSIZE> errbuf;
  int fd = -1;
  int rv;

  auto service = util::utos(faddr.port);
  addrinfo hints{};
  hints.ai_family = faddr.family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif // AI_ADDRCONFIG

  auto node =
      faddr.host == StringRef::from_lit("*") ? nullptr : faddr.host.c_str();

  addrinfo *res, *rp;
  rv = getaddrinfo(node, service.c_str(), &hints, &res);
#ifdef AI_ADDRCONFIG
  if (rv != 0) {
    // Retry without AI_ADDRCONFIG
    hints.ai_flags &= ~AI_ADDRCONFIG;
    rv = getaddrinfo(node, service.c_str(), &hints, &res);
  }
#endif // AI_ADDRCONFIG
  if (rv != 0) {
    LOG(FATAL) << "Unable to get IPv" << (faddr.family == AF_INET ? "4" : "6")
               << " address for " << faddr.host << ", port " << faddr.port
               << ": " << gai_strerror(rv);
    return -1;
  }

  auto res_d = defer(freeaddrinfo, res);

  std::array<char, NI_MAXHOST> host;

  for (rp = res; rp; rp = rp->ai_next) {
    rv = getnameinfo(rp->ai_addr, rp->ai_addrlen, host.data(), host.size(),
                     nullptr, 0, NI_NUMERICHOST);
    if (rv != 0) {
      LOG(WARN) << "getnameinfo() failed: " << gai_strerror(rv);
      continue;
    }

#ifdef SOCK_NONBLOCK
    fd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
                rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      LOG(WARN) << "socket() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      continue;
    }
#else  // !SOCK_NONBLOCK
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      auto error = errno;
      LOG(WARN) << "socket() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      continue;
    }
    util::make_socket_nonblocking(fd);
    util::make_socket_closeonexec(fd);
#endif // !SOCK_NONBLOCK

    int val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      LOG(WARN) << "Failed to set SO_REUSEADDR option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val,
                   static_cast<socklen_t>(sizeof(val))) == -1) {
      auto error = errno;
      LOG(WARN) << "Failed to set SO_REUSEPORT option to listener socket: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    if (faddr.family == AF_INET6) {
#ifdef IPV6_V6ONLY
      if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        LOG(WARN) << "Failed to set IPV6_V6ONLY option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
#endif // IPV6_V6ONLY

      if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        LOG(WARN)
            << "Failed to set IPV6_RECVPKTINFO option to listener socket: "
            << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
    } else {
      if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val,
                     static_cast<socklen_t>(sizeof(val))) == -1) {
        auto error = errno;
        LOG(WARN) << "Failed to set IP_PKTINFO option to listener socket: "
                  << xsi_strerror(error, errbuf.data(), errbuf.size());
        close(fd);
        continue;
      }
    }

    // TODO Enable ECN

    if (bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
      auto error = errno;
      LOG(WARN) << "bind() syscall failed: "
                << xsi_strerror(error, errbuf.data(), errbuf.size());
      close(fd);
      continue;
    }

    break;
  }

  if (!rp) {
    LOG(FATAL) << "Listening " << (faddr.family == AF_INET ? "IPv4" : "IPv6")
               << " socket failed";

    return -1;
  }

  faddr.fd = fd;
  faddr.hostport = util::make_http_hostport(mod_config()->balloc,
                                            StringRef{host.data()}, faddr.port);

  LOG(NOTICE) << "Listening on " << faddr.hostport << ", quic";

  return 0;
}

int quic_send_packet(const UpstreamAddr *faddr, const sockaddr *remote_sa,
                     size_t remote_salen, const sockaddr *local_sa,
                     size_t local_salen, const uint8_t *data, size_t datalen,
                     size_t gso_size) {
  iovec msg_iov = {const_cast<uint8_t *>(data), datalen};
  msghdr msg{};
  msg.msg_name = const_cast<sockaddr *>(remote_sa);
  msg.msg_namelen = remote_salen;
  msg.msg_iov = &msg_iov;
  msg.msg_iovlen = 1;

  uint8_t
      msg_ctrl[CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(sizeof(in6_pktinfo))];

  memset(msg_ctrl, 0, sizeof(msg_ctrl));

  msg.msg_control = msg_ctrl;
  msg.msg_controllen = sizeof(msg_ctrl);

  size_t controllen = 0;

  auto cm = CMSG_FIRSTHDR(&msg);

  switch (local_sa->sa_family) {
  case AF_INET: {
    controllen += CMSG_SPACE(sizeof(in_pktinfo));
    cm->cmsg_level = IPPROTO_IP;
    cm->cmsg_type = IP_PKTINFO;
    cm->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
    auto pktinfo = reinterpret_cast<in_pktinfo *>(CMSG_DATA(cm));
    memset(pktinfo, 0, sizeof(in_pktinfo));
    auto addrin =
        reinterpret_cast<sockaddr_in *>(const_cast<sockaddr *>(local_sa));
    pktinfo->ipi_spec_dst = addrin->sin_addr;
    break;
  }
  case AF_INET6: {
    controllen += CMSG_SPACE(sizeof(in6_pktinfo));
    cm->cmsg_level = IPPROTO_IPV6;
    cm->cmsg_type = IPV6_PKTINFO;
    cm->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
    auto pktinfo = reinterpret_cast<in6_pktinfo *>(CMSG_DATA(cm));
    memset(pktinfo, 0, sizeof(in6_pktinfo));
    auto addrin =
        reinterpret_cast<sockaddr_in6 *>(const_cast<sockaddr *>(local_sa));
    pktinfo->ipi6_addr = addrin->sin6_addr;
    break;
  }
  default:
    assert(0);
  }

  if (gso_size && datalen > gso_size) {
    controllen += CMSG_SPACE(sizeof(uint16_t));
    cm = CMSG_NXTHDR(&msg, cm);
    cm->cmsg_level = SOL_UDP;
    cm->cmsg_type = UDP_SEGMENT;
    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
    *(reinterpret_cast<uint16_t *>(CMSG_DATA(cm))) = gso_size;
  }

  msg.msg_controllen = controllen;

  ssize_t nwrite;

  do {
    nwrite = sendmsg(faddr->fd, &msg, 0);
  } while (nwrite == -1 && errno == EINTR);

  if (nwrite == -1) {
    return -1;
  }

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "QUIC sent packet: local="
              << util::to_numeric_addr(local_sa, local_salen)
              << " remote=" << util::to_numeric_addr(remote_sa, remote_salen)
              << " " << nwrite << " bytes";
  }

  return 0;
}

int generate_quic_connection_id(ngtcp2_cid *cid, size_t cidlen) {
  if (RAND_bytes(cid->data, cidlen) != 1) {
    return -1;
  }

  cid->datalen = cidlen;

  return 0;
}

int generate_quic_stateless_reset_token(uint8_t *token, const ngtcp2_cid *cid,
                                        const uint8_t *secret,
                                        size_t secretlen) {
  ngtcp2_crypto_md md;
  ngtcp2_crypto_md_init(&md, const_cast<EVP_MD *>(EVP_sha256()));

  if (ngtcp2_crypto_generate_stateless_reset_token(token, &md, secret,
                                                   secretlen, cid) != 0) {
    return -1;
  }

  return 0;
}

} // namespace shrpx
