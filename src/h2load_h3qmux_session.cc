/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#include "h2load_h3qmux_session.h"

#include <print>

#include <dwnx/dwnx.h>

#include "ssl_compat.h"

#ifdef NGHTTP2_OPENSSL_IS_WOLFSSL
#  include <wolfssl/options.h>
#  include <wolfssl/openssl/rand.h>
#else // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)
#  include <openssl/rand.h>
#endif // !defined(NGHTTP2_OPENSSL_IS_WOLFSSL)

#include "h2load.h"

namespace h2load {

namespace {
dwnx_tstamp quic_timestamp() {
  return static_cast<dwnx_tstamp>(
    std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch())
      .count());
}
} // namespace

H3QMuxSession::H3QMuxSession(Client *client) : client_(client) {
  dwnx_ccerr_default(&last_error_);
}

H3QMuxSession::~H3QMuxSession() {
  nghttp3_conn_del(conn_);
  dwnx_conn_del(qconn_);
}

void H3QMuxSession::on_connect() { (void)init_qconn(); }

std::expected<void, Error> H3QMuxSession::submit_request() {
  if (npending_request_) {
    ++npending_request_;
    return {};
  }

  auto config = client_->worker->config;
  reqidx_ = client_->reqidx;

  if (++client_->reqidx == config->nva.size()) {
    client_->reqidx = 0;
  }

  auto rv = submit_request_internal();
  if (!rv) {
    if (rv.error() == Error::STREAM_ID_BLOCKED) {
      ++npending_request_;
      return {};
    }
    return std::unexpected{rv.error()};
  }

  return {};
}

namespace {
nghttp3_ssize read_data(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec,
                        size_t veccnt, uint32_t *pflags, void *user_data,
                        void *stream_user_data) {
  auto s = static_cast<H3QMuxSession *>(user_data);

  s->read_data(vec, veccnt, pflags);

  return 1;
}
} // namespace

void H3QMuxSession::read_data(nghttp3_vec *vec, size_t veccnt,
                              uint32_t *pflags) {
  assert(veccnt > 0);

  auto config = client_->worker->config;

  vec[0].base = config->data;
  vec[0].len = static_cast<size_t>(config->data_length);
  *pflags |= NGHTTP3_DATA_FLAG_EOF;
}

std::expected<void, Error> H3QMuxSession::submit_request_internal() {
  int rv;
  int64_t stream_id;

  auto config = client_->worker->config;
  auto &nva = config->nva[reqidx_];

  rv = dwnx_conn_open_bidi_stream(qconn_, &stream_id, nullptr);
  if (rv != 0) {
    if (rv == DWNX_ERR_STREAM_ID_BLOCKED) {
      return std::unexpected{Error::STREAM_ID_BLOCKED};
    }

    return std::unexpected{Error::QUIC};
  }

  nghttp3_data_reader dr{
    .read_data = h2load::read_data,
  };

  rv = nghttp3_conn_submit_request(
    conn_, stream_id, reinterpret_cast<nghttp3_nv *>(nva.data()), nva.size(),
    config->data_fd == -1 ? nullptr : &dr, nullptr);
  if (rv != 0) {
    return std::unexpected{Error::HTTP3};
  }

  client_->on_request(stream_id);
  auto req_stat = client_->get_req_stat(stream_id);
  assert(req_stat);
  client_->record_request_time(req_stat);

  return {};
}

void H3QMuxSession::terminate() { should_close_ = true; }

size_t H3QMuxSession::max_concurrent_streams() {
  return client_->worker->config->max_concurrent_streams;
}

namespace {
int stream_close(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
                 void *user_data, void *stream_user_data) {
  auto s = static_cast<H3QMuxSession *>(user_data);
  s->stream_close(stream_id, app_error_code);

  return 0;
}
} // namespace

void H3QMuxSession::stream_close(int64_t stream_id, uint64_t app_error_code) {
  if (dwnx_is_bidi_stream(stream_id)) {
    client_->on_stream_close(stream_id, app_error_code == NGHTTP3_H3_NO_ERROR);

    return;
  }

  if (!dwnx_conn_is_local_stream(qconn_, stream_id)) {
    dwnx_conn_extend_max_streams_uni(qconn_, 1);
  }
}

namespace {
int end_stream(nghttp3_conn *conn, int64_t stream_id, void *user_data,
               void *stream_user_data) {
  auto s = static_cast<H3QMuxSession *>(user_data);
  s->end_stream(stream_id);

  return 0;
}
} // namespace

void H3QMuxSession::end_stream(int64_t stream_id) { client_->record_ttfb(); }

namespace {
int recv_data(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data,
              size_t datalen, void *user_data, void *stream_user_data) {
  auto s = static_cast<H3QMuxSession *>(user_data);
  s->recv_data(stream_id, {data, datalen});
  return 0;
}
} // namespace

void H3QMuxSession::recv_data(int64_t stream_id,
                              std::span<const uint8_t> data) {
  client_->record_ttfb();
  client_->worker->stats.bytes_body += data.size();
  consume(stream_id, data.size());
}

namespace {
int deferred_consume(nghttp3_conn *conn, int64_t stream_id, size_t nconsumed,
                     void *user_data, void *stream_user_data) {
  auto s = static_cast<H3QMuxSession *>(user_data);
  s->consume(stream_id, nconsumed);
  return 0;
}
} // namespace

void H3QMuxSession::consume(int64_t stream_id, size_t nconsumed) {
  dwnx_conn_extend_max_stream_offset(qconn_, stream_id, nconsumed);
  dwnx_conn_extend_max_offset(qconn_, nconsumed);
}

namespace {
int begin_headers(nghttp3_conn *conn, int64_t stream_id, void *user_data,
                  void *stream_user_data) {
  auto s = static_cast<H3QMuxSession *>(user_data);
  s->begin_headers(stream_id);
  return 0;
}
} // namespace

void H3QMuxSession::begin_headers(int64_t stream_id) {
  auto payloadlen = nghttp3_conn_get_frame_payload_left2(conn_, stream_id);
  assert(payloadlen > 0);

  client_->worker->stats.bytes_head += payloadlen;
}

namespace {
int recv_header(nghttp3_conn *conn, int64_t stream_id, int32_t token,
                nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags,
                void *user_data, void *stream_user_data) {
  auto s = static_cast<H3QMuxSession *>(user_data);
  auto k = nghttp3_rcbuf_get_buf(name);
  auto v = nghttp3_rcbuf_get_buf(value);
  s->recv_header(stream_id, {k.base, k.len}, {v.base, v.len});
  return 0;
}
} // namespace

void H3QMuxSession::recv_header(int64_t stream_id,
                                std::span<const uint8_t> name,
                                std::span<const uint8_t> value) {
  client_->on_header(stream_id, name, value);
  client_->worker->stats.bytes_head_decomp += name.size() + value.size();
}

namespace {
int stop_sending(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
                 void *user_data, void *stream_user_data) {
  auto s = static_cast<H3QMuxSession *>(user_data);
  if (!s->stop_sending(stream_id, app_error_code)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

std::expected<void, Error>
H3QMuxSession::stop_sending(int64_t stream_id, uint64_t app_error_code) {
  auto rv =
    dwnx_conn_shutdown_stream_read(qconn_, 0, stream_id, app_error_code);
  if (rv != 0) {
    std::println(stderr, "dwnx_conn_shutdown_stream_read: {}",
                 dwnx_strerror(rv));
    return std::unexpected{Error::QUIC};
  }
  return {};
}

namespace {
int reset_stream(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code,
                 void *user_data, void *stream_user_data) {
  auto s = static_cast<H3QMuxSession *>(user_data);
  if (!s->reset_stream(stream_id, app_error_code)) {
    return NGHTTP3_ERR_CALLBACK_FAILURE;
  }
  return 0;
}
} // namespace

std::expected<void, Error>
H3QMuxSession::reset_stream(int64_t stream_id, uint64_t app_error_code) {
  auto rv =
    dwnx_conn_shutdown_stream_write(qconn_, 0, stream_id, app_error_code);
  if (rv != 0) {
    std::println(stderr, "dwnx_conn_shutdown_stream_write: {}",
                 dwnx_strerror(rv));
    return std::unexpected{Error::QUIC};
  }
  return {};
}

std::expected<void, Error>
H3QMuxSession::close_stream(int64_t stream_id,
                            std::optional<uint64_t> rx_app_error_code,
                            std::optional<uint64_t> tx_app_error_code) {
  uint32_t flags = NGHTTP3_STREAM_CLOSE_FLAG_NONE;

  if (rx_app_error_code.has_value()) {
    flags |= NGHTTP3_STREAM_CLOSE_FLAG_RX_APP_ERROR_CODE_SET;
  }

  if (tx_app_error_code.has_value()) {
    flags |= NGHTTP3_STREAM_CLOSE_FLAG_TX_APP_ERROR_CODE_SET;
  }

  auto rv = nghttp3_conn_close_stream2(conn_, flags, stream_id,
                                       rx_app_error_code.value_or(0),
                                       tx_app_error_code.value_or(0));
  if (rv != 0) {
    if (rv == NGHTTP3_ERR_STREAM_NOT_FOUND) {
      if (!dwnx_is_bidi_stream(stream_id)) {
        assert(!dwnx_conn_is_local_stream(qconn_, stream_id));
        dwnx_conn_extend_max_streams_uni(qconn_, 1);
      }

      return {};
    }

    return std::unexpected{Error::HTTP3};
  }

  return {};
}

std::expected<void, Error>
H3QMuxSession::shutdown_stream_read(int64_t stream_id) {
  auto rv = nghttp3_conn_shutdown_stream_read(conn_, stream_id);
  if (rv != 0) {
    return std::unexpected{Error::HTTP3};
  }
  return {};
}

std::expected<void, Error> H3QMuxSession::extend_max_local_streams() {
  auto config = client_->worker->config;

  for (; npending_request_; --npending_request_) {
    auto rv = submit_request_internal();
    if (!rv) {
      if (rv.error() == Error::STREAM_ID_BLOCKED) {
        return {};
      }
      return rv;
    }

    if (++reqidx_ == config->nva.size()) {
      reqidx_ = 0;
    }
  }

  return {};
}

namespace {
void rand(uint8_t *dest, size_t destlen) {
  auto rv =
    RAND_bytes(dest, static_cast<nghttp2_ssl_rand_length_type>(destlen));
  if (rv != 1) {
    assert(0);
    abort();
  }
}
} // namespace

std::expected<void, Error> H3QMuxSession::init_conn() {
  int rv;

  assert(conn_ == nullptr);

  if (dwnx_conn_get_streams_uni_left(qconn_) < 3) {
    return std::unexpected{Error::INTERNAL};
  }

  static constexpr auto callbacks = nghttp3_callbacks{
    .stream_close = h2load::stream_close,
    .recv_data = h2load::recv_data,
    .deferred_consume = h2load::deferred_consume,
    .begin_headers = h2load::begin_headers,
    .recv_header = h2load::recv_header,
    .recv_trailer = h2load::recv_header,
    .stop_sending = h2load::stop_sending,
    .end_stream = h2load::end_stream,
    .reset_stream = h2load::reset_stream,
    .rand = h2load::rand,
  };

  auto config = client_->worker->config;

  nghttp3_settings settings;
  nghttp3_settings_default(&settings);
  settings.qpack_max_dtable_capacity = config->header_table_size;
  settings.qpack_blocked_streams = 100;

  auto mem = nghttp3_mem_default();

  rv = nghttp3_conn_client_new(&conn_, &callbacks, &settings, mem, this);
  if (rv != 0) {
    std::println(stderr, "nghttp3_conn_client_new: {}", nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  int64_t ctrl_stream_id;

  rv = dwnx_conn_open_uni_stream(qconn_, &ctrl_stream_id, nullptr);
  if (rv != 0) {
    std::println(stderr, "dwnx_conn_open_uni_stream: {}", dwnx_strerror(rv));
    return std::unexpected{Error::QUIC};
  }

  rv = nghttp3_conn_bind_control_stream(conn_, ctrl_stream_id);
  if (rv != 0) {
    std::println(stderr, "nghttp3_conn_bind_control_stream: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  int64_t qpack_enc_stream_id, qpack_dec_stream_id;

  rv = dwnx_conn_open_uni_stream(qconn_, &qpack_enc_stream_id, nullptr);
  if (rv != 0) {
    std::println(stderr, "dwnx_conn_open_uni_stream: {}", dwnx_strerror(rv));
    return std::unexpected{Error::QUIC};
  }

  rv = dwnx_conn_open_uni_stream(qconn_, &qpack_dec_stream_id, nullptr);
  if (rv != 0) {
    std::println(stderr, "dwnx_conn_open_uni_stream: {}", dwnx_strerror(rv));
    return std::unexpected{Error::QUIC};
  }

  rv = nghttp3_conn_bind_qpack_streams(conn_, qpack_enc_stream_id,
                                       qpack_dec_stream_id);
  if (rv != 0) {
    std::println(stderr, "nghttp3_conn_bind_qpack_streams: {}",
                 nghttp3_strerror(rv));
    return std::unexpected{Error::HTTP3};
  }

  return {};
}

std::expected<size_t, Error>
H3QMuxSession::read_stream(uint32_t flags, int64_t stream_id,
                           std::span<const uint8_t> data) {
  auto nconsumed = nghttp3_conn_read_stream2(
    conn_, stream_id, data.data(), data.size(),
    flags & DWNX_STREAM_DATA_FLAG_FIN, dwnx_conn_get_timestamp(qconn_));
  if (nconsumed < 0) {
    std::println(stderr, "nghttp3_conn_read_stream2: {}",
                 nghttp3_strerror(static_cast<int>(nconsumed)));
    dwnx_ccerr_set_application_error(
      &last_error_,
      nghttp3_err_infer_quic_app_error_code(static_cast<int>(nconsumed)),
      nullptr, 0);
    return std::unexpected{Error::HTTP3};
  }
  return as_unsigned(nconsumed);
}

std::expected<H3QMuxSession::WriteResult, Error>
H3QMuxSession::write_stream(std::span<nghttp3_vec> dest) {
  int64_t stream_id;
  int fin;

  auto sveccnt = nghttp3_conn_writev_stream(conn_, &stream_id, &fin,
                                            dest.data(), dest.size());
  if (sveccnt < 0) {
    dwnx_ccerr_set_application_error(
      &last_error_,
      nghttp3_err_infer_quic_app_error_code(static_cast<int>(sveccnt)), nullptr,
      0);
    return std::unexpected{Error::HTTP3};
  }

  return WriteResult{
    .stream_id = stream_id,
    .data = dest.first(as_unsigned(sveccnt)),
    .fin = fin,
  };
}

void H3QMuxSession::block_stream(int64_t stream_id) {
  nghttp3_conn_block_stream(conn_, stream_id);
}

std::expected<void, Error> H3QMuxSession::unblock_stream(int64_t stream_id) {
  if (nghttp3_conn_unblock_stream(conn_, stream_id) != 0) {
    return std::unexpected{Error::HTTP3};
  }

  return {};
}

void H3QMuxSession::shutdown_stream_write(int64_t stream_id) {
  nghttp3_conn_shutdown_stream_write(conn_, stream_id);
}

std::expected<void, Error> H3QMuxSession::add_write_offset(int64_t stream_id,
                                                           size_t ndatalen) {
  auto rv = nghttp3_conn_add_write_offset(conn_, stream_id, ndatalen);
  if (rv != 0) {
    dwnx_ccerr_set_application_error(
      &last_error_, nghttp3_err_infer_quic_app_error_code(rv), nullptr, 0);

    return std::unexpected{Error::HTTP3};
  }

  return {};
}

std::expected<void, Error> H3QMuxSession::add_ack_offset(int64_t stream_id,
                                                         size_t datalen) {
  auto rv = nghttp3_conn_add_ack_offset(conn_, stream_id, datalen);
  if (rv != 0) {
    dwnx_ccerr_set_application_error(
      &last_error_, nghttp3_err_infer_quic_app_error_code(rv), nullptr, 0);

    return std::unexpected{Error::HTTP3};
  }

  return {};
}

namespace {
int qconn_recv_transport_params(dwnx_conn *conn,
                                const dwnx_transport_params *params,
                                void *user_data) {
  auto c = static_cast<Client *>(user_data);
  auto session = static_cast<H3QMuxSession *>(c->session.get());

  if (!session->qconn_recv_transport_params(params)) {
    return DWNX_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

std::expected<void, Error> H3QMuxSession::qconn_recv_transport_params(
  const dwnx_transport_params *params) {
  return init_conn();
}

namespace {
int qconn_recv_stream_data(dwnx_conn *conn, uint32_t flags, int64_t stream_id,
                           uint64_t offset, const uint8_t *data, size_t datalen,
                           void *user_data, void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  auto session = static_cast<H3QMuxSession *>(c->session.get());

  if (!session->qconn_recv_stream_data(flags, stream_id, {data, datalen})) {
    // TODO Better to do this gracefully rather than
    // DWNX_ERR_CALLBACK_FAILURE.
    return DWNX_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

std::expected<void, Error>
H3QMuxSession::qconn_recv_stream_data(uint32_t flags, int64_t stream_id,
                                      std::span<const uint8_t> data) {
  auto maybe_consumed = read_stream(flags, stream_id, data);
  if (!maybe_consumed) {
    return std::unexpected{maybe_consumed.error()};
  }

  auto nconsumed = *maybe_consumed;

  dwnx_conn_extend_max_stream_offset(qconn_, stream_id, nconsumed);
  dwnx_conn_extend_max_offset(qconn_, nconsumed);

  return {};
}

namespace {
int qconn_stream_close(dwnx_conn *conn, uint32_t flags, int64_t stream_id,
                       uint64_t rx_app_error_code, uint64_t tx_app_error_code,
                       void *user_data, void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  auto session = static_cast<H3QMuxSession *>(c->session.get());

  if (!session->close_stream(
        stream_id,
        (flags & DWNX_STREAM_CLOSE_FLAG_RX_APP_ERROR_CODE_SET)
          ? std::make_optional(rx_app_error_code)
          : std::nullopt,
        (flags & DWNX_STREAM_CLOSE_FLAG_TX_APP_ERROR_CODE_SET)
          ? std::make_optional(tx_app_error_code)
          : std::nullopt)) {
    return DWNX_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int qconn_extend_max_local_streams_bidi(dwnx_conn *conn, uint64_t max_streams,
                                        void *user_data) {
  auto c = static_cast<Client *>(user_data);
  auto session = static_cast<H3QMuxSession *>(c->session.get());

  if (!session->extend_max_local_streams()) {
    return DWNX_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int qconn_stream_reset(dwnx_conn *conn, int64_t stream_id, uint64_t final_size,
                       uint64_t app_error_code, void *user_data,
                       void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  auto session = static_cast<H3QMuxSession *>(c->session.get());

  if (!session->shutdown_stream_read(stream_id)) {
    return DWNX_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int qconn_stream_stop_sending(dwnx_conn *conn, int64_t stream_id,
                              uint64_t app_error_code, void *user_data,
                              void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  auto session = static_cast<H3QMuxSession *>(c->session.get());

  if (!session->shutdown_stream_read(stream_id)) {
    return DWNX_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
int qconn_extend_max_stream_data(dwnx_conn *conn, int64_t stream_id,
                                 uint64_t max_data, void *user_data,
                                 void *stream_user_data) {
  auto c = static_cast<Client *>(user_data);
  auto session = static_cast<H3QMuxSession *>(c->session.get());

  if (!session->unblock_stream(stream_id)) {
    return DWNX_ERR_CALLBACK_FAILURE;
  }

  return 0;
}
} // namespace

namespace {
void debug_log_write(void *user_data, char *msg, size_t len) {
  msg[len] = '\n';

  while (write(fileno(stderr), msg, len + 1) == -1 && errno == EINTR)
    ;
}
} // namespace

std::expected<void, Error> H3QMuxSession::init_qconn() {
  auto config = client_->worker->config;

  static constexpr auto callbacks = dwnx_callbacks{
    .rand = h2load::rand,
    .recv_transport_params = h2load::qconn_recv_transport_params,
    .recv_stream_data = h2load::qconn_recv_stream_data,
    .stream_close = h2load::qconn_stream_close,
    .stream_reset = h2load::qconn_stream_reset,
    .stream_stop_sending = h2load::qconn_stream_stop_sending,
    .extend_max_stream_data = h2load::qconn_extend_max_stream_data,
    .extend_max_local_streams_bidi =
      h2load::qconn_extend_max_local_streams_bidi,
  };

  dwnx_settings settings;
  dwnx_settings_default(&settings);

  if (config->verbose) {
    settings.log_write = debug_log_write;
  }

  settings.initial_ts = quic_timestamp();
  util::secure_random(reinterpret_cast<uint8_t *>(&settings.conn_id),
                      sizeof(settings.conn_id));

  dwnx_transport_params params;
  dwnx_transport_params_default(&params);
  auto max_stream_data = static_cast<uint64_t>(
    std::min((1 << 26) - 1, (1 << config->window_bits) - 1));
  params.initial_max_stream_data_bidi_local = max_stream_data;
  params.initial_max_stream_data_uni = max_stream_data;
  params.initial_max_data = (1 << config->connection_window_bits) - 1;
  params.initial_max_streams_bidi = 0;
  params.initial_max_streams_uni = 100;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;

  if (auto rv = dwnx_conn_client_new(&qconn_, &callbacks, &settings, &params,
                                     nullptr, client_);
      rv != 0) {
    return std::unexpected{Error::QUIC};
  }

  return {};
}

std::expected<void, Error>
H3QMuxSession::on_read(std::span<const uint8_t> data) {
  auto rv = dwnx_conn_read(qconn_, data.data(), data.size(), quic_timestamp());
  if (rv != 0) {
    std::println(stderr, "dwnx_conn_read: {}", dwnx_strerror(rv));
    return std::unexpected{Error::QUIC};
  }

  return {};
}

std::expected<void, Error> H3QMuxSession::on_write() {
  if (client_->wb.rleft()) {
    return {};
  }

  if (should_close_) {
    return std::unexpected{Error::DONE};
  }

  return client_->wb.append_or_error(
    16_k, std::bind_front(&H3QMuxSession::write_record, this));
}

std::expected<size_t, Error>
H3QMuxSession::write_record(std::span<uint8_t> dest) {
  std::array<nghttp3_vec, 16> vec;
  auto ts = quic_timestamp();

  for (;;) {
    WriteResult wres;

    if (conn_ && dwnx_conn_get_max_data_left(qconn_)) {
      auto maybe_result = write_stream(vec);
      if (!maybe_result) {
        return std::unexpected{maybe_result.error()};
      }

      wres = *maybe_result;
    }

    dwnx_ssize ndatalen;

    uint32_t flags = DWNX_WRITE_STREAM_FLAG_NONE;
    if (wres.fin) {
      flags |= DWNX_WRITE_STREAM_FLAG_FIN;
    }

    auto nwrite = dwnx_conn_writev_stream(
      qconn_, dest.data(), dest.size(), &ndatalen, flags, wres.stream_id,
      reinterpret_cast<const dwnx_vec *>(wres.data.data()), wres.data.size(),
      ts);
    if (nwrite < 0) {
      switch (nwrite) {
      case DWNX_ERR_STREAM_DATA_BLOCKED:
        assert(ndatalen == -1);
        block_stream(wres.stream_id);
        continue;
      case DWNX_ERR_STREAM_SHUT_WR:
        assert(ndatalen == -1);
        block_stream(wres.stream_id);
        shutdown_stream_write(wres.stream_id);
        continue;
      case DWNX_ERR_WRITE_MORE:
        assert(ndatalen >= 0);

        if (auto rv = add_write_offset(wres.stream_id, as_unsigned(ndatalen));
            !rv) {
          return std::unexpected{rv.error()};
        }

        if (auto rv = add_ack_offset(wres.stream_id, as_unsigned(ndatalen));
            !rv) {
          return std::unexpected{rv.error()};
        }

        continue;
      }

      assert(ndatalen == -1);

      dwnx_ccerr_set_liberr(&last_error_, static_cast<int>(nwrite), nullptr, 0);

      return std::unexpected{Error::HTTP3};
    }

    if (ndatalen >= 0) {
      if (auto rv = add_write_offset(wres.stream_id, as_unsigned(ndatalen));
          !rv) {
        return std::unexpected{rv.error()};
      }

      if (auto rv = add_ack_offset(wres.stream_id, as_unsigned(ndatalen));
          !rv) {
        return std::unexpected{rv.error()};
      }
    }

    return as_unsigned(nwrite);
  }
}

} // namespace h2load
