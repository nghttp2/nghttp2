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
#include "shrpx_quic_listener.h"
#include "shrpx_worker.h"
#include "shrpx_config.h"
#include "shrpx_log.h"

namespace shrpx {

namespace {
void readcb(struct ev_loop *loop, ev_io *w, int revent) {
  auto l = static_cast<QUICListener *>(w->data);
  l->on_read();
}
} // namespace

QUICListener::QUICListener(const UpstreamAddr *faddr, Worker *worker)
  : faddr_{faddr}, worker_{worker} {
  ev_io_init(&rev_, readcb, faddr_->fd, EV_READ);
  rev_.data = this;
  ev_io_start(worker_->get_loop(), &rev_);
}

QUICListener::~QUICListener() {
  ev_io_stop(worker_->get_loop(), &rev_);
  close(faddr_->fd);
}

void QUICListener::on_read() {
  Address remote_addr;
  std::array<uint8_t, 64_k> buf;
  size_t pktcnt = 0;
  iovec msg_iov{
    .iov_base = buf.data(),
    .iov_len = buf.size(),
  };

  uint8_t msg_ctrl[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(in6_pktinfo)) +
                   CMSG_SPACE(sizeof(int))];

  msghdr msg{
    .msg_name = &remote_addr.su,
    .msg_iov = &msg_iov,
    .msg_iovlen = 1,
    .msg_control = msg_ctrl,
  };

  auto quic_conn_handler = worker_->get_quic_connection_handler();
  auto config = get_config();
  auto &quicconf = config->quic;
  auto bbr_cc = quicconf.upstream.congestion_controller == NGTCP2_CC_ALGO_BBR;
  auto start = quic_timestamp();

  for (; pktcnt < 64;) {
    if (recv_pkt_time_threshold_exceeded(bbr_cc, pktcnt, start,
                                         quic_timestamp())) {
      return;
    }

    msg.msg_namelen = sizeof(remote_addr.su);
    msg.msg_controllen = sizeof(msg_ctrl);

    auto nread = recvmsg(faddr_->fd, &msg, 0);
    if (nread == -1) {
      return;
    }

    // Packets less than 21 bytes never be a valid QUIC packet.
    if (nread < 21) {
      ++pktcnt;

      continue;
    }

    if (util::quic_prohibited_port(util::get_port(&remote_addr.su))) {
      ++pktcnt;

      continue;
    }

    Address local_addr{};
    if (util::msghdr_get_local_addr(local_addr, &msg,
                                    remote_addr.su.storage.ss_family) != 0) {
      ++pktcnt;

      continue;
    }

    util::set_port(local_addr, faddr_->port);

    ngtcp2_pkt_info pi{
      .ecn = util::msghdr_get_ecn(&msg, remote_addr.su.storage.ss_family),
    };

    auto gso_size = util::msghdr_get_udp_gro(&msg);
    if (gso_size == 0) {
      gso_size = static_cast<size_t>(nread);
    }

    auto data = std::span{buf}.first(as_unsigned(nread));

    for (;;) {
      auto datalen = std::min(data.size(), gso_size);

      ++pktcnt;

      remote_addr.len = msg.msg_namelen;

      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "QUIC received packet: local="
                  << util::to_numeric_addr(&local_addr)
                  << " remote=" << util::to_numeric_addr(&remote_addr)
                  << " ecn=" << log::hex << pi.ecn << log::dec << " " << datalen
                  << " bytes";
      }

      // Packets less than 21 bytes never be a valid QUIC packet.
      if (datalen < 21) {
        break;
      }

      quic_conn_handler->handle_packet(faddr_, remote_addr, local_addr, pi,
                                       data.first(datalen));

      data = data.subspan(datalen);
      if (data.empty()) {
        break;
      }
    }
  }
}

} // namespace shrpx
