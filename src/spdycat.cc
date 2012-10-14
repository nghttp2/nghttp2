/*
 * Spdylay - SPDY Library
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
#include "spdylay_config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <getopt.h>
#include <poll.h>

#include <cassert>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <string>
#include <set>
#include <iomanip>
#include <fstream>
#include <map>
#include <vector>
#include <sstream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <spdylay/spdylay.h>

#include "spdylay_ssl.h"
#include "uri.h"
#include "HtmlParser.h"
#include "util.h"

namespace spdylay {

struct Config {
  bool null_out;
  bool remote_name;
  bool verbose;
  bool get_assets;
  bool stat;
  int spdy_version;
  // milliseconds
  int timeout;
  std::string certfile;
  std::string keyfile;
  int window_bits;
  std::map<std::string,std::string> headers;
  Config():null_out(false), remote_name(false), verbose(false),
           get_assets(false), stat(false),
           spdy_version(-1), timeout(-1), window_bits(-1)
  {}
};

struct RequestStat {
  timeval on_syn_stream_time;
  timeval on_syn_reply_time;
  timeval on_complete_time;
  RequestStat()
  {
    on_syn_stream_time.tv_sec = -1;
    on_syn_stream_time.tv_usec = -1;
    on_syn_reply_time.tv_sec = -1;
    on_syn_reply_time.tv_usec = -1;
    on_complete_time.tv_sec = -1;
    on_complete_time.tv_usec = -1;
  }
};

void record_time(timeval *tv)
{
  gettimeofday(tv, 0);
}

struct Request {
  uri::UriStruct us;
  spdylay_gzip *inflater;
  HtmlParser *html_parser;
  // Recursion level: 0: first entity, 1: entity linked from first entity
  int level;
  RequestStat stat;
  std::string status;
  Request(const uri::UriStruct& us, int level = 0)
    : us(us), inflater(0), html_parser(0), level(level)
  {}

  ~Request()
  {
    spdylay_gzip_inflate_del(inflater);
    delete html_parser;
  }

  void init_inflater()
  {
    int rv;
    rv = spdylay_gzip_inflate_new(&inflater);
    assert(rv == 0);
  }

  void init_html_parser()
  {
    html_parser = new HtmlParser(uri::construct(us));
  }

  int update_html_parser(const uint8_t *data, size_t len, int fin)
  {
    if(!html_parser) {
      return 0;
    }
    int rv;
    rv = html_parser->parse_chunk(reinterpret_cast<const char*>(data), len,
                                  fin);
    return rv;
  }

  void record_syn_stream_time()
  {
    record_time(&stat.on_syn_stream_time);
  }

  void record_syn_reply_time()
  {
    record_time(&stat.on_syn_reply_time);
  }

  void record_complete_time()
  {
    record_time(&stat.on_complete_time);
  }
};

struct SessionStat {
  timeval on_handshake_time;
  SessionStat()
  {
    on_handshake_time.tv_sec = -1;
    on_handshake_time.tv_usec = -1;
  }
};

struct SpdySession {
  std::vector<Request*> reqvec;
  // Map from stream ID to Request object.
  std::map<int32_t, Request*> streams;
  // Insert path already added in reqvec to prevent multiple request
  // for 1 resource.
  std::set<std::string> path_cache;
  // The number of completed requests, including failed ones.
  size_t complete;
  std::string hostport;
  Spdylay *sc;
  SessionStat stat;
  SpdySession():complete(0) {}
  ~SpdySession()
  {
    for(size_t i = 0; i < reqvec.size(); ++i) {
      delete reqvec[i];
    }
  }
  bool all_requests_processed() const
  {
    return complete == reqvec.size();
  }
  void update_hostport()
  {
    if(reqvec.empty()) {
      return;
    }
    std::stringstream ss;
    if(reqvec[0]->us.ipv6LiteralAddress) {
      ss << "[" << reqvec[0]->us.host << "]";
    } else {
      ss << reqvec[0]->us.host;
    }
    if(reqvec[0]->us.port != 443) {
      ss << ":" << reqvec[0]->us.port;
    }
    hostport = ss.str();
  }
  bool add_request(const uri::UriStruct& us, int level = 0)
  {
    std::string key = us.dir+us.file+us.query;
    if(path_cache.count(key)) {
      return false;
    } else {
      path_cache.insert(key);
      reqvec.push_back(new Request(us, level));
      return true;
    }
  }
  void record_handshake_time()
  {
    record_time(&stat.on_handshake_time);
  }
};

Config config;
extern bool ssl_debug;

void submit_request(Spdylay& sc, const std::string& hostport,
                    const std::map<std::string,std::string> &headers,
                    Request* req)
{
  uri::UriStruct& us = req->us;
  std::string path = us.dir+us.file+us.query;
  int r = sc.submit_request(hostport, path, headers, 3, req);
  assert(r == 0);
}

void update_html_parser(SpdySession *spdySession, Request *req,
                        const uint8_t *data, size_t len, int fin)
{
  if(!req->html_parser) {
    return;
  }
  req->update_html_parser(data, len, fin);

  for(size_t i = 0; i < req->html_parser->get_links().size(); ++i) {
    const std::string& uri = req->html_parser->get_links()[i];
    uri::UriStruct us;
    if(uri::parse(us, uri) &&
       req->us.protocol == us.protocol && req->us.host == us.host &&
       req->us.port == us.port) {
      spdySession->add_request(us, req->level+1);
      submit_request(*spdySession->sc, spdySession->hostport, config.headers,
                     spdySession->reqvec.back());
    }
  }
  req->html_parser->clear_links();
}

SpdySession* get_session(void *user_data)
{
  return reinterpret_cast<SpdySession*>
    (reinterpret_cast<Spdylay*>(user_data)->user_data());
}

void on_data_chunk_recv_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data)
{
  SpdySession *spdySession = get_session(user_data);
  std::map<int32_t, Request*>::iterator itr =
    spdySession->streams.find(stream_id);
  if(itr != spdySession->streams.end()) {
    Request *req = (*itr).second;
    if(req->inflater) {
      while(len > 0) {
        const size_t MAX_OUTLEN = 4096;
        uint8_t out[MAX_OUTLEN];
        size_t outlen = MAX_OUTLEN;
        size_t tlen = len;
        int rv = spdylay_gzip_inflate(req->inflater, out, &outlen, data, &tlen);
        if(rv == -1) {
          spdylay_submit_rst_stream(session, stream_id, SPDYLAY_INTERNAL_ERROR);
          break;
        }
        if(!config.null_out) {
          std::cout.write(reinterpret_cast<const char*>(out), outlen);
        }
        update_html_parser(spdySession, req, out, outlen, 0);
        data += tlen;
        len -= tlen;
      }
    } else {
      if(!config.null_out) {
        std::cout.write(reinterpret_cast<const char*>(data), len);
      }
      update_html_parser(spdySession, req, data, len, 0);
    }
  }
}

void check_stream_id(spdylay_session *session,
                     spdylay_frame_type type, spdylay_frame *frame,
                     void *user_data)
{
  SpdySession *spdySession = get_session(user_data);
  int32_t stream_id = frame->syn_stream.stream_id;
  Request *req = (Request*)spdylay_session_get_stream_user_data(session,
                                                                stream_id);
  spdySession->streams[stream_id] = req;
  req->record_syn_stream_time();
}

void on_ctrl_send_callback2
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  if(type == SPDYLAY_SYN_STREAM) {
    check_stream_id(session, type, frame, user_data);
  }
  if(config.verbose) {
    on_ctrl_send_callback(session, type, frame, user_data);
  }
}

void check_response_header
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  char **nv;
  int32_t stream_id;
  if(type == SPDYLAY_SYN_REPLY) {
    nv = frame->syn_reply.nv;
    stream_id = frame->syn_reply.stream_id;
  } else if(type == SPDYLAY_HEADERS) {
    nv = frame->headers.nv;
    stream_id = frame->headers.stream_id;
  } else {
    return;
  }
  Request *req = (Request*)spdylay_session_get_stream_user_data(session,
                                                                stream_id);
  if(!req) {
    // Server-pushed stream does not have stream user data
    return;
  }
  bool gzip = false;
  for(size_t i = 0; nv[i]; i += 2) {
    if(strcmp("content-encoding", nv[i]) == 0) {
      gzip = util::strieq("gzip", nv[i+1]) || util::strieq("deflate", nv[i+1]);
    } else if(strcmp(":status", nv[i]) == 0) {
      req->status = nv[i+1];
    }
  }
  if(gzip) {
    if(!req->inflater) {
      req->init_inflater();
    }
  }
  if(config.get_assets && req->level == 0) {
    if(!req->html_parser) {
      req->init_html_parser();
    }
  }
}

void on_ctrl_recv_callback2
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  if(type == SPDYLAY_SYN_REPLY) {
    Request *req = (Request*)spdylay_session_get_stream_user_data
      (session, frame->syn_reply.stream_id);
    assert(req);
    req->record_syn_reply_time();
  }
  check_response_header(session, type, frame, user_data);
  if(config.verbose) {
    on_ctrl_recv_callback(session, type, frame, user_data);
  }
}

void on_stream_close_callback
(spdylay_session *session, int32_t stream_id, spdylay_status_code status_code,
 void *user_data)
{
  SpdySession *spdySession = get_session(user_data);
  std::map<int32_t, Request*>::iterator itr =
    spdySession->streams.find(stream_id);
  if(itr != spdySession->streams.end()) {
    update_html_parser(spdySession, (*itr).second, 0, 0, 1);
    (*itr).second->record_complete_time();
    ++spdySession->complete;
    if(spdySession->all_requests_processed()) {
      spdylay_submit_goaway(session, SPDYLAY_GOAWAY_OK);
    }
  }
}

void print_stats(const SpdySession& spdySession)
{
  std::cout << "***** Statistics *****" << std::endl;
  for(size_t i = 0; i < spdySession.reqvec.size(); ++i) {
    const Request *req = spdySession.reqvec[i];
    std::cout << "#" << i+1 << ": " << uri::construct(req->us) << std::endl;
    std::cout << "    Status: " << req->status << std::endl;
    std::cout << "    Delta (ms) from SSL/TLS handshake(SYN_STREAM):"
              << std::endl;
    if(req->stat.on_syn_reply_time.tv_sec >= 0) {
      std::cout << "        SYN_REPLY: "
                << time_delta(req->stat.on_syn_reply_time,
                              spdySession.stat.on_handshake_time)
                << "("
                << time_delta(req->stat.on_syn_reply_time,
                              req->stat.on_syn_stream_time)
                << ")"
                << std::endl;
    }
    if(req->stat.on_complete_time.tv_sec >= 0) {
      std::cout << "        Completed: "
                << time_delta(req->stat.on_complete_time,
                              spdySession.stat.on_handshake_time)
                << "("
                << time_delta(req->stat.on_complete_time,
                              req->stat.on_syn_stream_time)
                << ")"
                << std::endl;
    }
    std::cout << std::endl;
  }
}

int communicate(const std::string& host, uint16_t port,
                SpdySession& spdySession,
                const spdylay_session_callbacks *callbacks)
{
  int rv;
  int timeout = config.timeout;
  int fd = nonblock_connect_to(host, port, timeout);
  if(fd == -1) {
    std::cerr << "Could not connect to the host" << std::endl;
    return -1;
  } else if(fd == -2) {
    std::cerr << "Request to " << spdySession.hostport << " timed out "
              << "during establishing connection."
              << std::endl;
    return -1;
  }
  set_tcp_nodelay(fd);
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(TLSv1_client_method());
  if(!ssl_ctx) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  std::string next_proto;
  switch(config.spdy_version) {
  case SPDYLAY_PROTO_SPDY2:
    next_proto = "spdy/2";
    break;
  case SPDYLAY_PROTO_SPDY3:
    next_proto = "spdy/3";
    break;
  }
  setup_ssl_ctx(ssl_ctx, &next_proto);
  if(!config.keyfile.empty()) {
    if(SSL_CTX_use_PrivateKey_file(ssl_ctx, config.keyfile.c_str(),
                                   SSL_FILETYPE_PEM) != 1) {
      std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
      return -1;
    }
  }
  if(!config.certfile.empty()) {
    if(SSL_CTX_use_certificate_chain_file(ssl_ctx,
                                          config.certfile.c_str()) != 1) {
      std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
      return -1;
    }
  }
  SSL *ssl = SSL_new(ssl_ctx);
  if(!ssl) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  if (!SSL_set_tlsext_host_name(ssl, host.c_str())) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  rv = ssl_nonblock_handshake(ssl, fd, timeout);
  if(rv == -1) {
    return -1;
  } else if(rv == -2) {
    std::cerr << "Request to " << spdySession.hostport
              << " timed out in SSL/TLS handshake."
              << std::endl;
    return -1;
  }

  spdySession.record_handshake_time();
  int spdy_version = spdylay_npn_get_version(
      reinterpret_cast<const unsigned char*>(next_proto.c_str()),
      next_proto.size());
  if (spdy_version <= 0) {
    return -1;
  }
  Spdylay sc(fd, ssl, spdy_version, callbacks, &spdySession);
  spdySession.sc = &sc;

  nfds_t npollfds = 1;
  pollfd pollfds[1];

  if(spdy_version >= SPDYLAY_PROTO_SPDY3 && config.window_bits != -1) {
    spdylay_settings_entry iv[1];
    iv[0].settings_id = SPDYLAY_SETTINGS_INITIAL_WINDOW_SIZE;
    iv[0].flags = SPDYLAY_ID_FLAG_SETTINGS_NONE;
    iv[0].value = 1 << config.window_bits;
    int rv = sc.submit_settings(SPDYLAY_FLAG_SETTINGS_NONE, iv, 1);
    assert(rv == 0);
  }
  for(int i = 0, n = spdySession.reqvec.size(); i < n; ++i) {
    submit_request(sc, spdySession.hostport, config.headers,
                   spdySession.reqvec[i]);
  }
  pollfds[0].fd = fd;
  ctl_poll(pollfds, &sc);

  bool ok = true;
  timeval tv1, tv2;
  while(!sc.finish()) {
    if(config.timeout != -1) {
      gettimeofday(&tv1, 0);
    }
    int nfds = poll(pollfds, npollfds, timeout);
    if(nfds == -1) {
      perror("poll");
      return -1;
    }
    if(pollfds[0].revents & (POLLIN | POLLOUT)) {
      int rv;
      if((rv = sc.recv()) != 0 || (rv = sc.send()) != 0) {
        if(rv != SPDYLAY_ERR_EOF || !spdySession.all_requests_processed()) {
          std::cout << "Fatal: " << spdylay_strerror(rv) << std::endl;
          std::cout << "reqnum=" << spdySession.reqvec.size()
                    << ", completed=" << spdySession.complete << std::endl;
        }
        ok = false;
        break;
      }
    }
    if((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
      std::cout << "HUP" << std::endl;
      ok = false;
      break;
    }
    if(config.timeout != -1) {
      gettimeofday(&tv2, 0);
      timeout -= time_delta(tv2, tv1);
      if (timeout <= 0) {
        std::cerr << "Requests to " << spdySession.hostport << " timed out."
                  << std::endl;
        ok = false;
        break;
      }
    }
    assert(ok);
    ctl_poll(pollfds, &sc);
  }
  if(!spdySession.all_requests_processed()) {
    std::cout << "Some requests were not processed. total="
              << spdySession.reqvec.size()
              << ", processed=" << spdySession.complete << std::endl;
  }
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  shutdown(fd, SHUT_WR);
  close(fd);
  if(config.stat) {
    print_stats(spdySession);
  }
  return ok ? 0 : -1;
}

int run(char **uris, int n)
{
  spdylay_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = send_callback;
  callbacks.recv_callback = recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;
  callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback2;
  callbacks.on_ctrl_send_callback = on_ctrl_send_callback2;
  if(config.verbose) {
    callbacks.on_data_recv_callback = on_data_recv_callback;
    callbacks.on_invalid_ctrl_recv_callback = on_invalid_ctrl_recv_callback;
    callbacks.on_ctrl_recv_parse_error_callback =
      on_ctrl_recv_parse_error_callback;
    callbacks.on_unknown_ctrl_recv_callback = on_unknown_ctrl_recv_callback;
  }
  callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  ssl_debug = config.verbose;
  std::string prev_host;
  uint16_t prev_port = 0;
  int failures = 0;
  SpdySession spdySession;
  for(int i = 0; i < n; ++i) {
    uri::UriStruct us;
    if(uri::parse(us, uris[i])) {
      if(prev_host != us.host || prev_port != us.port) {
        if(!spdySession.reqvec.empty()) {
          spdySession.update_hostport();
          if (communicate(prev_host, prev_port, spdySession, &callbacks) != 0) {
            ++failures;
          }
          spdySession = SpdySession();
        }
        prev_host = us.host;
        prev_port = us.port;
      }
      spdySession.add_request(us);
    }
  }
  if(!spdySession.reqvec.empty()) {
    spdySession.update_hostport();
    if (communicate(prev_host, prev_port, spdySession, &callbacks) != 0) {
      ++failures;
    }
  }
  return failures;
}

void print_usage(std::ostream& out)
{
  out << "Usage: spdycat [-Oansv23] [-t <SECONDS>] [-w <WINDOW_BITS>] [--cert=<CERT>]\n"
      << "               [--key=<KEY>] <URI>..."
      << std::endl;
}

void print_help(std::ostream& out)
{
  print_usage(out);
  out << "\n"
      << "OPTIONS:\n"
      << "    -v, --verbose      Print debug information such as reception/\n"
      << "                       transmission of frames and name/value pairs.\n"
      << "    -n, --null-out     Discard downloaded data.\n"
      << "    -O, --remote-name  Save download data in the current directory.\n"
      << "                       The filename is dereived from URI. If URI\n"
      << "                       ends with '/', 'index.html' is used as a\n"
      << "                       filename. Not implemented yet.\n"
      << "    -2, --spdy2        Only use SPDY/2.\n"
      << "    -3, --spdy3        Only use SPDY/3.\n"
      << "    -t, --timeout=<N>  Timeout each request after <N> seconds.\n"
      << "    -w, --window-bits=<N>\n"
      << "                       Sets the initial window size to 2**<N>.\n"
      << "    -a, --get-assets   Download assets such as stylesheets, images\n"
      << "                       and script files linked from the downloaded\n"
      << "                       resource. Only links whose origins are the\n"
      << "                       same with the linking resource will be\n"
      << "                       downloaded.\n"
      << "    -s, --stat         Print statistics.\n"
      << "    -H, --header       Add a header to the requests.\n"
      << "    --cert=<CERT>      Use the specified client certificate file.\n"
      << "                       The file must be in PEM format.\n"
      << "    --key=<KEY>        Use the client private key file. The file\n"
      << "                       must be in PEM format.\n"
      << std::endl;
}

int main(int argc, char **argv)
{
  while(1) {
    int flag;
    static option long_options[] = {
      {"verbose", no_argument, 0, 'v' },
      {"null-out", no_argument, 0, 'n' },
      {"remote-name", no_argument, 0, 'O' },
      {"spdy2", no_argument, 0, '2' },
      {"spdy3", no_argument, 0, '3' },
      {"timeout", required_argument, 0, 't' },
      {"window-bits", required_argument, 0, 'w' },
      {"get-assets", no_argument, 0, 'a' },
      {"stat", no_argument, 0, 's' },
      {"cert", required_argument, &flag, 1 },
      {"key", required_argument, &flag, 2 },
      {"help", no_argument, 0, 'h' },
      {"header", required_argument, 0, 'H' },
      {0, 0, 0, 0 }
    };
    int option_index = 0;
    int c = getopt_long(argc, argv, "OanhH:v23st:w:", long_options,
                        &option_index);
    if(c == -1) {
      break;
    }
    switch(c) {
    case 'O':
      config.remote_name = true;
      break;
    case 'h':
      print_help(std::cout);
      exit(EXIT_SUCCESS);
    case 'n':
      config.null_out = true;
      break;
    case 'v':
      config.verbose = true;
      break;
    case '2':
      config.spdy_version = SPDYLAY_PROTO_SPDY2;
      break;
    case '3':
      config.spdy_version = SPDYLAY_PROTO_SPDY3;
      break;
    case 't':
      config.timeout = atoi(optarg) * 1000;
      break;
    case 'w': {
      errno = 0;
      unsigned long int n = strtoul(optarg, 0, 10);
      if(errno == 0 && n < 31) {
        config.window_bits = n;
      } else {
        std::cerr << "-w: specify the integer in the range [0, 30], inclusive"
                  << std::endl;
        exit(EXIT_FAILURE);
      }
      break;
    }
    case 'H': {
      char *header = optarg;
      char *value = strchr( optarg, ':' );
      if ( ! value || header == value) {
        std::cerr << "-H: invalid header: " << optarg
                  << std::endl;
        exit(EXIT_FAILURE);
      }
      *value = 0;
      value++;
      while( isspace( *value ) ) { value++; }
      if ( *value == 0 ) {
        // This could also be a valid case for suppressing a header
        // similar to curl
        std::cerr << "-H: invalid header - value missing: " << optarg
                  << std::endl;
        exit(EXIT_FAILURE);
      }
      // Note that there is no processing currently to handle multiple
      // message-header fields with the same field name
      config.headers.insert(std::pair<std::string,std::string>(header, value));
      break;
    }
    case 'a':
#ifdef HAVE_LIBXML2
      config.get_assets = true;
#else // !HAVE_LIBXML2
      std::cerr << "Warning: -a, --get-assets option cannot be used because\n"
                << "the binary was not compiled with libxml2."
                << std::endl;
#endif // !HAVE_LIBXML2
      break;
    case 's':
      config.stat = true;
      break;
    case '?':
      exit(EXIT_FAILURE);
    case 0:
      switch(flag) {
      case 1:
        // cert option
        config.certfile = optarg;
        break;
      case 2:
        // key option
        config.keyfile = optarg;
        break;
      }
      break;
    default:
      break;
    }
  }
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);
  SSL_load_error_strings();
  SSL_library_init();
  reset_timer();
  return run(argv+optind, argc-optind);
}

} // namespace spdylay

int main(int argc, char **argv)
{
  return spdylay::main(argc, argv);
}
