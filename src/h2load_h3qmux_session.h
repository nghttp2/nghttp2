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
#ifndef H2LOAD_H3QMUX_SESSION_H
#define H2LOAD_H3QMUX_SESSION_H

#include "h2load_session.h"

#include <dwnx/dwnx.h>
#include <nghttp3/nghttp3.h>

namespace h2load {

struct Client;

class H3QMuxSession : public Session {
public:
  H3QMuxSession(Client *client);
  ~H3QMuxSession() override;
  void on_connect() override;
  std::expected<void, Error> submit_request() override;
  std::expected<void, Error> on_read(std::span<const uint8_t> data) override;
  std::expected<void, Error> on_write() override;
  void terminate() override;
  size_t max_concurrent_streams() override;

  std::expected<void, Error> init_conn();
  void stream_close(int64_t stream_id, uint64_t app_error_code);
  void end_stream(int64_t stream_id);
  void recv_data(int64_t stream_id, std::span<const uint8_t> data);
  void consume(int64_t stream_id, size_t nconsumed);
  void begin_headers(int64_t stream_id);
  void recv_header(int64_t stream_id, std::span<const uint8_t> name,
                   std::span<const uint8_t> value);
  std::expected<void, Error> stop_sending(int64_t stream_id,
                                          uint64_t app_error_code);
  std::expected<void, Error> reset_stream(int64_t stream_id,
                                          uint64_t app_error_code);

  std::expected<void, Error>
  close_stream(int64_t stream_id, std::optional<uint64_t> rx_app_error_code,
               std::optional<uint64_t> tx_app_error_code);
  std::expected<void, Error> shutdown_stream_read(int64_t stream_id);
  std::expected<void, Error> extend_max_local_streams();
  std::expected<void, Error> submit_request_internal();

  std::expected<size_t, Error> read_stream(uint32_t flags, int64_t stream_id,
                                           std::span<const uint8_t> data);

  struct WriteResult {
    int64_t stream_id{-1};
    std::span<nghttp3_vec> data;
    int fin{};
  };

  std::expected<WriteResult, Error> write_stream(std::span<nghttp3_vec> vec);
  std::expected<size_t, Error> write_record(std::span<uint8_t> dest);
  void block_stream(int64_t stream_id);
  std::expected<void, Error> unblock_stream(int64_t stream_id);
  void shutdown_stream_write(int64_t stream_id);
  std::expected<void, Error> add_write_offset(int64_t stream_id,
                                              size_t ndatalen);
  std::expected<void, Error> add_ack_offset(int64_t stream_id, size_t datalen);

  void read_data(nghttp3_vec *vec, size_t veccnt, uint32_t *pflags);

  std::expected<void, Error> init_qconn();
  std::expected<void, Error>
  qconn_recv_transport_params(const dwnx_transport_params *params);
  std::expected<void, Error>
  qconn_recv_stream_data(uint32_t flags, int64_t stream_id,
                         std::span<const uint8_t> data);

private:
  Client *client_;
  dwnx_conn *qconn_{};
  dwnx_ccerr last_error_{};
  nghttp3_conn *conn_{};
  size_t npending_request_{};
  size_t reqidx_{};
  bool should_close_{};
};

} // namespace h2load

#endif // H2LOAD_H3QMUX_SESSION_H
