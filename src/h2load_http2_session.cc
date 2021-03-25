/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2014 Tatsuhiro Tsujikawa
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
#include "h2load_http2_session.h"

#include <cassert>
#include <cerrno>
#include <iostream>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <regex>

#include "h2load.h"
#include "util.h"
#include "template.h"

using namespace nghttp2;

namespace h2load {

Http2Session::Http2Session(Client *client)
    : client_(client), session_(nullptr) {}

Http2Session::~Http2Session() { nghttp2_session_del(session_); }

namespace {
int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame,
                       const uint8_t *name, size_t namelen,
                       const uint8_t *value, size_t valuelen, uint8_t flags,
                       void *user_data) {
  auto client = static_cast<Client *>(user_data);
  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
    return 0;
  }
  client->on_header(frame->hd.stream_id, name, namelen, value, valuelen);
  client->worker->stats.bytes_head_decomp += namelen + valuelen;

  if (client->worker->config->verbose) {
    std::cout << "[stream_id=" << frame->hd.stream_id << "] ";
    std::cout.write(reinterpret_cast<const char *>(name), namelen);
    std::cout << ": ";
    std::cout.write(reinterpret_cast<const char *>(value), valuelen);
    std::cout << "\n";
  }

  return 0;
}
} // namespace

namespace {
int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame,
                           void *user_data) {
  auto client = static_cast<Client *>(user_data);
  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
    return 0;
  }
  client->worker->stats.bytes_head +=
      frame->hd.length - frame->headers.padlen -
      ((frame->hd.flags & NGHTTP2_FLAG_PRIORITY) ? 5 : 0);
  if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    client->record_ttfb();
  }
  return 0;
}
} // namespace

namespace {
int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                int32_t stream_id, const uint8_t *data,
                                size_t len, void *user_data) {
  auto client = static_cast<Client *>(user_data);
  client->record_ttfb();
  client->worker->stats.bytes_body += len;
  return 0;
}
} // namespace

namespace {
int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                             uint32_t error_code, void *user_data) {
  auto client = static_cast<Client *>(user_data);
  client->on_stream_close(stream_id, error_code == NGHTTP2_NO_ERROR);
  return 0;
}
} // namespace

namespace {
int before_frame_send_callback(nghttp2_session *session,
                               const nghttp2_frame *frame, void *user_data) {
  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  auto client = static_cast<Client *>(user_data);
  auto req_stat = client->get_req_stat(frame->hd.stream_id);
  assert(req_stat);
  client->record_request_time(req_stat);

  return 0;
}
} // namespace

namespace {
ssize_t file_read_callback(nghttp2_session *session, int32_t stream_id,
                           uint8_t *buf, size_t length, uint32_t *data_flags,
                           nghttp2_data_source *source, void *user_data) {
  auto client = static_cast<Client *>(user_data);
  auto config = client->worker->config;
  auto req_stat = client->get_req_stat(stream_id);
  assert(req_stat);
  ssize_t nread;
  while ((nread = pread(config->data_fd, buf, length, req_stat->data_offset)) ==
             -1 &&
         errno == EINTR)
    ;

  if (nread == -1) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  req_stat->data_offset += nread;

  if (req_stat->data_offset == config->data_length) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return nread;
  }

  if (req_stat->data_offset > config->data_length || nread == 0) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  return nread;
}

ssize_t buffer_read_callback(nghttp2_session *session, int32_t stream_id,
                           uint8_t *buf, size_t length, uint32_t *data_flags,
                           nghttp2_data_source *source, void *user_data) {
  auto client = static_cast<Client *>(user_data);
  auto config = client->worker->config;
  auto req_stat = client->get_req_stat(stream_id);
  uint64_t variable_value = client->streams_CRUD_data[stream_id].user_id;
  std::string& stream_buffer = client->streams_CRUD_data[stream_id].data_buffer;
  assert(req_stat);

  if (stream_buffer.empty()) {
    stream_buffer = (client->streams_waiting_for_update_response.find(stream_id) !=
                     client->streams_waiting_for_update_response.end() ?
                     config->crud_update_data_template_buf : config->data_buffer);
    if (!config->req_variable_name.empty() &&
        stream_buffer.find(config->req_variable_name) != std::string::npos) {
      size_t full_var_length = std::to_string(config->req_variable_end).size();
      std::string curr_var_value = std::to_string(variable_value);
      curr_var_value.reserve(full_var_length);
      std::string padding;
      padding.reserve(full_var_length - curr_var_value.size());
      for (size_t i = 0; i < full_var_length - curr_var_value.size(); i++) {
        padding.append("0");
      }
      curr_var_value.insert(0, padding);
      stream_buffer =
        std::regex_replace(stream_buffer, std::regex(config->req_variable_name), curr_var_value);
    }
  }
  if (length >= stream_buffer.size()) {
    memcpy(buf, stream_buffer.c_str(), stream_buffer.size());
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    size_t buf_size = stream_buffer.size();
    stream_buffer.clear();
    return buf_size;
  }
  else {
    memcpy(buf, stream_buffer.c_str(), length);
    stream_buffer = stream_buffer.substr(length, std::string::npos);
    return length;
  }
}

} // namespace

namespace {
ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                      size_t length, int flags, void *user_data) {
  auto client = static_cast<Client *>(user_data);
  auto &wb = client->wb;

  if (wb.rleft() >= BACKOFF_WRITE_BUFFER_THRES) {
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  return wb.append(data, length);
}
} // namespace

void Http2Session::on_connect() {
  int rv;

  // This is required with --disable-assert.
  (void)rv;

  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new(&callbacks);

  auto callbacks_deleter = defer(nghttp2_session_callbacks_del, callbacks);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);

  nghttp2_session_callbacks_set_before_frame_send_callback(
      callbacks, before_frame_send_callback);

  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

  nghttp2_option *opt;

  rv = nghttp2_option_new(&opt);
  assert(rv == 0);

  auto config = client_->worker->config;

  if (config->encoder_header_table_size != NGHTTP2_DEFAULT_HEADER_TABLE_SIZE) {
    nghttp2_option_set_max_deflate_dynamic_table_size(
        opt, config->encoder_header_table_size);
  }

  nghttp2_session_client_new2(&session_, callbacks, client_, opt);

  nghttp2_option_del(opt);

  std::array<nghttp2_settings_entry, 3> iv;
  size_t niv = 2;
  iv[0].settings_id = NGHTTP2_SETTINGS_ENABLE_PUSH;
  iv[0].value = 0;
  iv[1].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
  iv[1].value = (1 << config->window_bits) - 1;

  if (config->header_table_size != NGHTTP2_DEFAULT_HEADER_TABLE_SIZE) {
    iv[niv].settings_id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE;
    iv[niv].value = config->header_table_size;
    ++niv;
  }

  rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv.data(), niv);

  assert(rv == 0);

  auto connection_window = (1 << config->connection_window_bits) - 1;
  nghttp2_session_set_local_window_size(session_, NGHTTP2_FLAG_NONE, 0,
                                        connection_window);
  if (config->nclients > 1)
  {
    std::random_device                  rand_dev;
    std::mt19937                        generator(rand_dev());
    std::uniform_int_distribution<uint64_t>  distr(config->req_variable_start, config->req_variable_end);
    client_->worker->curr_req_variable_value = distr(generator);
  }
  else {
    client_->worker->curr_req_variable_value = config->req_variable_start;
  }

  client_->signal_write();
}

int Http2Session::submit_request() {
  if (nghttp2_session_check_request_allowed(session_) == 0) {
    return -1;
  }

  auto config = client_->worker->config;
  thread_local static auto nvas = config->nva;
  thread_local static auto read_nva = config->read_nva;
  thread_local static auto update_nva = config->update_nva;
  thread_local static auto delete_nva = config->delete_nva;
  int32_t stream_id = -1;

  // tear down the client which is approaching max stream, and reconnect again
  if ((config->nclients > 1 && config->rps > 0 &&
       INT32_MAX - client_->curr_stream_id < config->nclients * config->nclients * config->rps &&
       rand() % config->nclients == 0 )||
      (client_->curr_stream_id >= INT32_MAX - 1)) {
    return MAX_STREAM_TO_BE_EXHAUSTED;
  }

  if (config->crud_read_method.empty()) {
    client_->resource_uris_to_update.insert(client_->resource_uris_to_update.begin(),
        client_->resource_uris_to_read.begin(), client_->resource_uris_to_read.end());
    client_->resource_uris_to_read.clear();
  }

  if (config->crud_update_method.empty()) {
    client_->resource_uris_to_delete.insert(client_->resource_uris_to_delete.begin(),
        client_->resource_uris_to_update.begin(), client_->resource_uris_to_update.end());
    client_->resource_uris_to_update.clear();
  }

  if (config->crud_delete_method.empty()) {
    client_->resource_uris_to_delete.clear();
  }

  nghttp2_data_provider prd{{0}, file_read_callback};

  const std::string path_header_name = ":path";
  const std::string path_header_value_stub = "/";

  if (!client_->resource_uris_to_read.empty()) {
    auto uri_with_user_id = client_->resource_uris_to_read.front();
    client_->resource_uris_to_read.pop_front();
    replace_header_in_nva(read_nva, path_header_name, uri_with_user_id.resource_uri);
    stream_id =
        nghttp2_submit_request(session_, nullptr, read_nva.data(),  read_nva.size(),
                               nullptr, nullptr);
    replace_header_in_nva(read_nva, path_header_name, path_header_value_stub);
    if (stream_id > 0) {
      client_->streams_waiting_for_get_response[stream_id] = uri_with_user_id;
    }
    else {
        client_->resource_uris_to_update.push_back(uri_with_user_id);
    }
  }
  else if (!client_->resource_uris_to_update.empty()) {
    auto uri_with_user_id = client_->resource_uris_to_update.front();
    client_->resource_uris_to_update.pop_front();
    replace_header_in_nva(update_nva, path_header_name, uri_with_user_id.resource_uri);
    prd.read_callback = buffer_read_callback;
    stream_id =
        nghttp2_submit_request(session_, nullptr, update_nva.data(),  update_nva.size(),
                               config->crud_update_data_template_buf.empty() ? nullptr : &prd, nullptr);
    replace_header_in_nva(update_nva, path_header_name, path_header_value_stub);
    if (stream_id > 0) {
      client_->streams_waiting_for_update_response[stream_id] = uri_with_user_id;
      client_->streams_CRUD_data[stream_id].user_id = uri_with_user_id.user_id;
    }
    else {
      client_->resource_uris_to_delete.push_back(uri_with_user_id);
    }
  }
  else if (!client_->resource_uris_to_delete.empty()) {
    auto uri_with_user_id = client_->resource_uris_to_delete.front();
    client_->resource_uris_to_delete.pop_front();
    replace_header_in_nva(delete_nva, path_header_name, uri_with_user_id.resource_uri);
    stream_id =
        nghttp2_submit_request(session_, nullptr, delete_nva.data(),  delete_nva.size(),
                               nullptr, nullptr);
    replace_header_in_nva(delete_nva, path_header_name, path_header_value_stub);
  }
  else { // regular request or CRUD create request (first request)

    auto &nva = nvas[client_->reqidx++];

    if (client_->reqidx == nvas.size()) {
      client_->reqidx = 0;
    }
    nghttp2_nv path_nv_with_variable;
    int64_t path_nv_index = -1;
    uint64_t curr_stream_var_value = client_->worker->curr_req_variable_value;

    std::string new_path;
    if (!config->req_variable_name.empty() && config->req_variable_end) {
      for (size_t i = 0; i < nva.size(); i++) {
        std::string header_name((const char*)nva[i].name, nva[i].namelen);
        if (header_name == ":path") {
          path_nv_with_variable = nva[i];
          std::string path_value((const char*)nva[i].value, nva[i].valuelen);
          if (path_value.find(config->req_variable_name) != std::string::npos) {
            new_path = path_value;
            size_t full_length = std::to_string(config->req_variable_end).size();
            std::string curr_var_value = std::to_string(client_->worker->curr_req_variable_value);
            std::string padding;
            padding.reserve(full_length - curr_var_value.size());
            for (size_t i = 0; i < full_length - curr_var_value.size(); i++) {
              padding.append("0");
            }
            curr_var_value.insert(0, padding);
            new_path = std::regex_replace(new_path, std::regex(config->req_variable_name), curr_var_value);
            nva[i].value = (uint8_t*)new_path.c_str();
            nva[i].valuelen = new_path.size();
            path_nv_index = i;
          }
          if (client_->reqidx == nvas.size() -1 ) {
            // all uris in uri list are looped for this variable value, use next value for next loop
            client_->worker->curr_req_variable_value++;
            if (client_->worker->curr_req_variable_value > config->req_variable_end) {
              client_->worker->curr_req_variable_value = config->req_variable_start;
            }
          }
          break;
        }
      }
      prd.read_callback = buffer_read_callback;
    }
    stream_id =
        nghttp2_submit_request(session_, nullptr, nva.data(), nva.size(),
                               config->data_fd == -1 ? nullptr : &prd, nullptr);

    if (stream_id > 0 && !config->crud_resource_header_name.empty() && (-1 != path_nv_index)) {
        client_->streams_waiting_for_create_response[stream_id] = curr_stream_var_value;
    }

    if (stream_id > 0 && !config->data_buffer.empty()) {
        client_->streams_CRUD_data[stream_id].user_id = curr_stream_var_value;
    }

    if (-1 != path_nv_index) {
      nva[path_nv_index] = path_nv_with_variable; // restore path nv for next request
    }
  }

  if (stream_id < 0) {
    return -1;
  }

  client_->on_request(stream_id);
  client_->curr_stream_id = stream_id;

  return 0;
}

int Http2Session::on_read(const uint8_t *data, size_t len) {
  auto rv = nghttp2_session_mem_recv(session_, data, len);
  if (rv < 0) {
    return -1;
  }

  assert(static_cast<size_t>(rv) == len);

  if (nghttp2_session_want_read(session_) == 0 &&
      nghttp2_session_want_write(session_) == 0 && client_->wb.rleft() == 0) {
    return -1;
  }

  client_->signal_write();

  return 0;
}

int Http2Session::on_write() {
  auto rv = nghttp2_session_send(session_);
  if (rv != 0) {
    return -1;
  }

  if (nghttp2_session_want_read(session_) == 0 &&
      nghttp2_session_want_write(session_) == 0 && client_->wb.rleft() == 0) {
    return -1;
  }

  return 0;
}

void Http2Session::terminate() {
  nghttp2_session_terminate_session(session_, NGHTTP2_NO_ERROR);
}

size_t Http2Session::max_concurrent_streams() {
  return (size_t)client_->worker->config->max_concurrent_streams;
}

void Http2Session::submit_rst_stream(int32_t stream_id) {
  nghttp2_submit_rst_stream(session_, NGHTTP2_FLAG_END_STREAM, stream_id, NGHTTP2_STREAM_CLOSED);
}

} // namespace h2load
