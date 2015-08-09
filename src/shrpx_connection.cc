/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2015 Tatsuhiro Tsujikawa
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
#include "shrpx_connection.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif // HAVE_UNISTD_H

#include <limits>

#include <openssl/err.h>

#include "shrpx_ssl.h"
#include "shrpx_memcached_request.h"
#include "memchunk.h"

using namespace nghttp2;

namespace shrpx {
Connection::Connection(struct ev_loop *loop, int fd, SSL *ssl,
                       ev_tstamp write_timeout, ev_tstamp read_timeout,
                       size_t write_rate, size_t write_burst, size_t read_rate,
                       size_t read_burst, IOCb writecb, IOCb readcb,
                       TimerCb timeoutcb, void *data)
    : tls{}, wlimit(loop, &wev, write_rate, write_burst),
      rlimit(loop, &rev, read_rate, read_burst, ssl), writecb(writecb),
      readcb(readcb), timeoutcb(timeoutcb), loop(loop), data(data), fd(fd) {

  ev_io_init(&wev, writecb, fd, EV_WRITE);
  ev_io_init(&rev, readcb, fd, EV_READ);

  wev.data = this;
  rev.data = this;

  ev_timer_init(&wt, timeoutcb, 0., write_timeout);
  ev_timer_init(&rt, timeoutcb, 0., read_timeout);

  wt.data = this;
  rt.data = this;

  // set 0. to double field explicitly just in case
  tls.last_write_idle = 0.;

  if (ssl) {
    set_ssl(ssl);
  }
}

Connection::~Connection() {
  disconnect();

  if (tls.ssl) {
    SSL_free(tls.ssl);
  }
}

void Connection::disconnect() {
  ev_timer_stop(loop, &rt);
  ev_timer_stop(loop, &wt);

  rlimit.stopw();
  wlimit.stopw();

  if (tls.ssl) {
    SSL_set_shutdown(tls.ssl, SSL_RECEIVED_SHUTDOWN);
    ERR_clear_error();

    if (tls.cached_session) {
      SSL_SESSION_free(tls.cached_session);
    }

    if (tls.cached_session_lookup_req) {
      tls.cached_session_lookup_req->canceled = true;
    }

    // To reuse SSL/TLS session, we have to shutdown, and don't free
    // tls.ssl.
    if (SSL_shutdown(tls.ssl) != 1) {
      SSL_free(tls.ssl);
      tls.ssl = nullptr;
    }

    tls = {tls.ssl};
  }

  if (fd != -1) {
    shutdown(fd, SHUT_WR);
    close(fd);
    fd = -1;
  }
}

namespace {
void allocate_buffer(Connection *conn) {
  conn->tls.rb = make_unique<Buffer<16_k>>();
  conn->tls.wb = make_unique<Buffer<16_k>>();
}
} // namespace

void Connection::prepare_client_handshake() {
  SSL_set_connect_state(tls.ssl);
  allocate_buffer(this);
}

void Connection::prepare_server_handshake() {
  SSL_set_accept_state(tls.ssl);
  allocate_buffer(this);
}

// BIO implementation is inspired by openldap implementation:
// http://www.openldap.org/devel/cvsweb.cgi/~checkout~/libraries/libldap/tls_o.c
namespace {
int shrpx_bio_write(BIO *b, const char *buf, int len) {
  if (buf == nullptr || len <= 0) {
    return 0;
  }

  auto conn = static_cast<Connection *>(b->ptr);
  auto &wb = conn->tls.wb;

  BIO_clear_retry_flags(b);

  if (conn->tls.initial_handshake_done) {
    // After handshake finished, send |buf| of length |len| to the
    // socket directly.
    if (wb && wb->rleft()) {
      auto nwrite = conn->write_clear(wb->pos, wb->rleft());
      if (nwrite < 0) {
        return -1;
      }

      wb->drain(nwrite);
      if (wb->rleft()) {
        BIO_set_retry_write(b);
        return -1;
      }

      // Here delete TLS write buffer
      wb.reset();
    }
    auto nwrite = conn->write_clear(buf, len);
    if (nwrite < 0) {
      return -1;
    }

    if (nwrite == 0) {
      BIO_set_retry_write(b);
      return -1;
    }

    return nwrite;
  }

  auto nwrite = std::min(static_cast<size_t>(len), wb->wleft());

  if (nwrite == 0) {
    BIO_set_retry_write(b);
    return -1;
  }

  wb->write(buf, nwrite);

  return nwrite;
}
} // namespace

namespace {
int shrpx_bio_read(BIO *b, char *buf, int len) {
  if (buf == nullptr || len <= 0) {
    return 0;
  }

  auto conn = static_cast<Connection *>(b->ptr);
  auto &rb = conn->tls.rb;

  BIO_clear_retry_flags(b);

  if (conn->tls.initial_handshake_done && !rb) {
    auto nread = conn->read_clear(buf, len);
    if (nread < 0) {
      return -1;
    }
    if (nread == 0) {
      BIO_set_retry_read(b);
      return -1;
    }
    return nread;
  }

  auto nread = std::min(static_cast<size_t>(len), rb->rleft());

  if (nread == 0) {
    if (conn->tls.initial_handshake_done) {
      rb.reset();
    }

    BIO_set_retry_read(b);
    return -1;
  }

  std::copy_n(rb->pos, nread, buf);

  rb->drain(nread);

  return nread;
}
} // namespace

namespace {
int shrpx_bio_puts(BIO *b, const char *str) {
  return shrpx_bio_write(b, str, strlen(str));
}
} // namespace

namespace {
int shrpx_bio_gets(BIO *b, char *buf, int len) { return -1; }
} // namespace

namespace {
long shrpx_bio_ctrl(BIO *b, int cmd, long num, void *ptr) {
  switch (cmd) {
  case BIO_CTRL_FLUSH:
    return 1;
  }

  return 0;
}
} // namespace

namespace {
int shrpx_bio_create(BIO *b) {
  b->init = 1;
  b->num = 0;
  b->ptr = nullptr;
  b->flags = 0;
  return 1;
}
} // namespace

namespace {
int shrpx_bio_destroy(BIO *b) {
  if (b == nullptr) {
    return 0;
  }

  b->ptr = nullptr;
  b->init = 0;
  b->flags = 0;

  return 1;
}
} // namespace

namespace {
BIO_METHOD shrpx_bio_method = {
    BIO_TYPE_FD,    "nghttpx-bio",    shrpx_bio_write,
    shrpx_bio_read, shrpx_bio_puts,   shrpx_bio_gets,
    shrpx_bio_ctrl, shrpx_bio_create, shrpx_bio_destroy,
};
} // namespace

void Connection::set_ssl(SSL *ssl) {
  tls.ssl = ssl;
  auto bio = BIO_new(&shrpx_bio_method);
  bio->ptr = this;
  SSL_set_bio(tls.ssl, bio, bio);
  SSL_set_app_data(tls.ssl, this);
  rlimit.set_ssl(tls.ssl);
}

int Connection::tls_handshake() {
  wlimit.stopw();
  ev_timer_stop(loop, &wt);

  auto nread = read_clear(tls.rb->last, tls.rb->wleft());
  if (nread < 0) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "tls: handshake read error";
    }
    return -1;
  }
  tls.rb->write(nread);

  // We have limited space for read buffer, so stop reading if it
  // filled up.
  if (tls.rb->wleft() == 0) {
    if (tls.handshake_state != TLS_CONN_WRITE_STARTED) {
      // Reading 16KiB before writing server hello is unlikely for
      // ordinary client.
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "tls: client hello is too large";
      }
      return -1;
    }

    rlimit.stopw();
    ev_timer_stop(loop, &rt);
  }

  switch (tls.handshake_state) {
  case TLS_CONN_WAIT_FOR_SESSION_CACHE:
    if (nread > 0) {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "tls: client sent addtional data after client hello";
      }
      return -1;
    }
    return SHRPX_ERR_INPROGRESS;
  case TLS_CONN_GOT_SESSION_CACHE: {
    // Use the same trick invented by @kazuho in h2o project
    tls.wb->reset();
    tls.rb->pos = tls.rb->begin();

    auto ssl_ctx = SSL_get_SSL_CTX(tls.ssl);
    auto ssl_opts = SSL_get_options(tls.ssl);
    SSL_free(tls.ssl);

    auto ssl = ssl::create_ssl(ssl_ctx);
    if (!ssl) {
      return -1;
    }
    if (ssl_opts & SSL_OP_NO_TICKET) {
      SSL_set_options(ssl, SSL_OP_NO_TICKET);
    }

    set_ssl(ssl);

    SSL_set_accept_state(tls.ssl);

    tls.handshake_state = TLS_CONN_NORMAL;
    break;
  }
  case TLS_CONN_CANCEL_SESSION_CACHE:
    tls.handshake_state = TLS_CONN_NORMAL;
    break;
  }

  auto rv = SSL_do_handshake(tls.ssl);

  if (rv <= 0) {
    auto err = SSL_get_error(tls.ssl, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      break;
    default:
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "tls: handshake libssl error " << err;
      }
      return SHRPX_ERR_NETWORK;
    }
  }

  if (tls.handshake_state == TLS_CONN_WAIT_FOR_SESSION_CACHE) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "tls: handshake is still in progress";
    }
    return SHRPX_ERR_INPROGRESS;
  }

  if (tls.wb->rleft()) {
    // First write indicates that resumption stuff has done.
    tls.handshake_state = TLS_CONN_WRITE_STARTED;
    auto nwrite = write_clear(tls.wb->pos, tls.wb->rleft());
    if (nwrite < 0) {
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "tls: handshake write error";
      }
      return -1;
    }
    tls.wb->drain(nwrite);
  }

  if (tls.wb->rleft()) {
    wlimit.startw();
    ev_timer_again(loop, &wt);
  } else {
    tls.wb->reset();
  }

  if (tls.handshake_state == TLS_CONN_WRITE_STARTED && tls.rb->rleft() == 0) {
    tls.rb->reset();

    // We may have stopped reading
    rlimit.startw();
    ev_timer_again(loop, &rt);
  }

  if (rv != 1) {
    if (LOG_ENABLED(INFO)) {
      LOG(INFO) << "tls: handshake is still in progress";
    }
    return SHRPX_ERR_INPROGRESS;
  }

  tls.initial_handshake_done = true;

  if (LOG_ENABLED(INFO)) {
    LOG(INFO) << "SSL/TLS handshake completed";
    if (SSL_session_reused(tls.ssl)) {
      LOG(INFO) << "SSL/TLS session reused";
    }
  }

  return 0;
}

namespace {
const size_t SHRPX_SMALL_WRITE_LIMIT = 1300;
const size_t SHRPX_WARMUP_THRESHOLD = 1 << 20;
} // namespace

size_t Connection::get_tls_write_limit() {
  auto t = ev_now(loop);

  if (tls.last_write_idle >= 0. && t - tls.last_write_idle > 1.) {
    // Time out, use small record size
    tls.warmup_writelen = 0;
    return SHRPX_SMALL_WRITE_LIMIT;
  }

  if (tls.warmup_writelen >= SHRPX_WARMUP_THRESHOLD) {
    return std::numeric_limits<ssize_t>::max();
  }

  return SHRPX_SMALL_WRITE_LIMIT;
}

void Connection::update_tls_warmup_writelen(size_t n) {
  if (tls.warmup_writelen < SHRPX_WARMUP_THRESHOLD) {
    tls.warmup_writelen += n;
  }
}

void Connection::start_tls_write_idle() {
  if (tls.last_write_idle < 0.) {
    tls.last_write_idle = ev_now(loop);
  }
}

ssize_t Connection::write_tls(const void *data, size_t len) {
  // SSL_write requires the same arguments (buf pointer and its
  // length) on SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
  // get_write_limit() may return smaller length than previously
  // passed to SSL_write, which violates OpenSSL assumption.  To avoid
  // this, we keep last legnth passed to SSL_write to
  // tls.last_writelen if SSL_write indicated I/O blocking.
  if (tls.last_writelen == 0) {
    len = std::min(len, wlimit.avail());
    len = std::min(len, get_tls_write_limit());
    if (len == 0) {
      return 0;
    }
  } else {
    len = tls.last_writelen;
    tls.last_writelen = 0;
  }

  tls.last_write_idle = -1.;

  auto rv = SSL_write(tls.ssl, data, len);

  if (rv == 0) {
    return SHRPX_ERR_NETWORK;
  }

  if (rv < 0) {
    auto err = SSL_get_error(tls.ssl, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Close connection due to TLS renegotiation";
      }
      return SHRPX_ERR_NETWORK;
    case SSL_ERROR_WANT_WRITE:
      tls.last_writelen = len;
      wlimit.startw();
      ev_timer_again(loop, &wt);
      return 0;
    default:
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "SSL_write: SSL_get_error returned " << err;
      }
      return SHRPX_ERR_NETWORK;
    }
  }

  wlimit.drain(rv);

  update_tls_warmup_writelen(rv);

  return rv;
}

ssize_t Connection::read_tls(void *data, size_t len) {
  // SSL_read requires the same arguments (buf pointer and its
  // length) on SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.
  // rlimit_.avail() or rlimit_.avail() may return different length
  // than the length previously passed to SSL_read, which violates
  // OpenSSL assumption.  To avoid this, we keep last legnth passed
  // to SSL_read to tls_last_readlen_ if SSL_read indicated I/O
  // blocking.
  if (tls.last_readlen == 0) {
    len = std::min(len, rlimit.avail());
    if (len == 0) {
      return 0;
    }
  } else {
    len = tls.last_readlen;
    tls.last_readlen = 0;
  }

  auto rv = SSL_read(tls.ssl, data, len);

  if (rv <= 0) {
    auto err = SSL_get_error(tls.ssl, rv);
    switch (err) {
    case SSL_ERROR_WANT_READ:
      tls.last_readlen = len;
      return 0;
    case SSL_ERROR_WANT_WRITE:
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "Close connection due to TLS renegotiation";
      }
      return SHRPX_ERR_NETWORK;
    case SSL_ERROR_ZERO_RETURN:
      return SHRPX_ERR_EOF;
    default:
      if (LOG_ENABLED(INFO)) {
        LOG(INFO) << "SSL_read: SSL_get_error returned " << err;
      }
      return SHRPX_ERR_NETWORK;
    }
  }

  rlimit.drain(rv);

  return rv;
}

ssize_t Connection::write_clear(const void *data, size_t len) {
  len = std::min(len, wlimit.avail());
  if (len == 0) {
    return 0;
  }

  ssize_t nwrite;
  while ((nwrite = write(fd, data, len)) == -1 && errno == EINTR)
    ;
  if (nwrite == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      wlimit.startw();
      ev_timer_again(loop, &wt);
      return 0;
    }
    return SHRPX_ERR_NETWORK;
  }

  wlimit.drain(nwrite);

  return nwrite;
}

ssize_t Connection::writev_clear(struct iovec *iov, int iovcnt) {
  iovcnt = limit_iovec(iov, iovcnt, wlimit.avail());
  if (iovcnt == 0) {
    return 0;
  }

  ssize_t nwrite;
  while ((nwrite = writev(fd, iov, iovcnt)) == -1 && errno == EINTR)
    ;
  if (nwrite == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      wlimit.startw();
      ev_timer_again(loop, &wt);
      return 0;
    }
    return SHRPX_ERR_NETWORK;
  }

  wlimit.drain(nwrite);

  return nwrite;
}

ssize_t Connection::read_clear(void *data, size_t len) {
  len = std::min(len, rlimit.avail());
  if (len == 0) {
    return 0;
  }

  ssize_t nread;
  while ((nread = read(fd, data, len)) == -1 && errno == EINTR)
    ;
  if (nread == -1) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return 0;
    }
    return SHRPX_ERR_NETWORK;
  }

  if (nread == 0) {
    return SHRPX_ERR_EOF;
  }

  rlimit.drain(nread);

  return nread;
}

void Connection::handle_tls_pending_read() {
  if (!ev_is_active(&rev)) {
    return;
  }
  rlimit.handle_tls_pending_read();
}

} // namespace shrpx
