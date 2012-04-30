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
#include <zlib.h>

#include "spdylay_ssl.h"
#include "uri.h"

namespace spdylay {

struct Config {
  bool null_out;
  bool remote_name;
  bool verbose;
  bool spdy3_only;
  int timeout;
  std::string certfile;
  std::string keyfile;
  Config():null_out(false), remote_name(false), verbose(false),
           spdy3_only(false), timeout(-1) {}
};

struct Request {
  uri::UriStruct us;
  z_stream *inflater;
  Request(const uri::UriStruct& us):us(us), inflater(0) {}
  ~Request()
  {
    spdylay_free_inflate_stream(inflater);
  }

  void init_inflater()
  {
    inflater = spdylay_new_inflate_stream();
    assert(inflater != NULL);
  }
};

std::map<int32_t, Request*> stream2req;
size_t numreq, complete;

Config config;
extern bool ssl_debug;

void on_data_chunk_recv_callback
(spdylay_session *session, uint8_t flags, int32_t stream_id,
 const uint8_t *data, size_t len, void *user_data)
{
  std::map<int32_t, Request*>::iterator itr = stream2req.find(stream_id);
  if(itr != stream2req.end()) {
    Request *req = (*itr).second;
    if(req->inflater) {
      while(len > 0) {
        const size_t MAX_OUTLEN = 4096;
        uint8_t out[MAX_OUTLEN];
        size_t outlen = MAX_OUTLEN;
        size_t tlen = len;
        int rv = spdylay_inflate_data(req->inflater, out, &outlen, data, &tlen);
        if(rv == -1) {
          spdylay_submit_rst_stream(session, stream_id, SPDYLAY_INTERNAL_ERROR);
          break;
        }
        std::cout.write(reinterpret_cast<const char*>(out), outlen);
        data += tlen;
        len -= tlen;
      }
    } else {
      std::cout.write(reinterpret_cast<const char*>(data), len);
    }
  }
}

void check_stream_id(spdylay_session *session,
                     spdylay_frame_type type, spdylay_frame *frame)
{
  int32_t stream_id = frame->syn_stream.stream_id;
  Request *req = (Request*)spdylay_session_get_stream_user_data(session,
                                                                stream_id);
  stream2req[stream_id] = req;
}

void on_ctrl_send_callback2
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  if(type == SPDYLAY_SYN_STREAM) {
    check_stream_id(session, type, frame);
  }
}

void on_ctrl_send_callback3
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  if(type == SPDYLAY_SYN_STREAM) {
    check_stream_id(session, type, frame);
  }
  on_ctrl_send_callback(session, type, frame, user_data);
}

void check_gzip
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
  bool gzip = false;
  for(size_t i = 0; nv[i]; i += 2) {
    if(strcmp("content-encoding", nv[i]) == 0) {
      gzip = strcmp("gzip", nv[i+1]) == 0;
      break;
    }
  }
  if(gzip) {
    Request *req = (Request*)spdylay_session_get_stream_user_data(session,
                                                                  stream_id);
    assert(req);
    if(req->inflater) {
      return;
    }
    req->init_inflater();
  }
}

void on_ctrl_recv_callback2
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  check_gzip(session, type, frame, user_data);
}

void on_ctrl_recv_callback3
(spdylay_session *session, spdylay_frame_type type, spdylay_frame *frame,
 void *user_data)
{
  check_gzip(session, type, frame, user_data);
  on_ctrl_recv_callback(session, type, frame, user_data);
}

void on_stream_close_callback
(spdylay_session *session, int32_t stream_id, spdylay_status_code status_code,
 void *user_data)
{
  std::map<int32_t, Request*>::iterator itr = stream2req.find(stream_id);
  if(itr != stream2req.end()) {
    ++complete;
    if(complete == numreq) {
      spdylay_submit_goaway(session, SPDYLAY_GOAWAY_OK);
    }
    stream2req.erase(itr);
  }
}

int communicate(const std::string& host, uint16_t port,
                std::vector<Request>& reqvec,
                const spdylay_session_callbacks *callbacks)
{
  numreq = reqvec.size();
  complete = 0;
  stream2req.clear();
  int fd = connect_to(host, port);
  if(fd == -1) {
    std::cerr << "Could not connect to the host" << std::endl;
    return -1;
  }
  SSL_CTX *ssl_ctx;
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if(!ssl_ctx) {
    std::cerr << ERR_error_string(ERR_get_error(), 0) << std::endl;
    return -1;
  }
  std::string next_proto;
  if(config.spdy3_only) {
    next_proto = "spdy/3";
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
  if(ssl_handshake(ssl, fd) == -1) {
    return -1;
  }
  make_non_block(fd);
  set_tcp_nodelay(fd);
  int spdy_version = spdylay_npn_get_version(
      reinterpret_cast<const unsigned char*>(next_proto.c_str()),
      next_proto.size());
  if (spdy_version <= 0) {
    return -1;
  }
  Spdylay sc(fd, ssl, spdy_version, callbacks);

  nfds_t npollfds = 1;
  pollfd pollfds[1];

  std::stringstream ss;
  if(reqvec[0].us.ipv6LiteralAddress) {
    ss << "[";
  }
  ss << host;
  if(reqvec[0].us.ipv6LiteralAddress) {
    ss << "]";
  }
  if(port != 443) {
    ss << ":" << port;
  }
  std::string hostport = ss.str();

  for(int i = 0, n = reqvec.size(); i < n; ++i) {
    uri::UriStruct& us = reqvec[i].us;
    std::string path = us.dir+us.file+us.query;
    int r = sc.submit_request(hostport, path, 3, &reqvec[i]);
    assert(r == 0);
  }
  pollfds[0].fd = fd;
  ctl_poll(pollfds, &sc);
  int end_time = time(NULL) + config.timeout;
  int timeout = config.timeout;

  bool ok = true;
  while(!sc.finish()) {
    int nfds = poll(pollfds, npollfds, timeout);
    if(nfds == -1) {
      perror("poll");
      return -1;
    }
    if(pollfds[0].revents & (POLLIN | POLLOUT)) {
      if(sc.recv() != 0 || sc.send() != 0) {
        std::cout << "Fatal" << std::endl;
        ok = false;
        break;
      }
    }
    if((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
      std::cout << "HUP" << std::endl;
      ok = false;
      break;
    }
    timeout = timeout == -1 ? timeout : end_time - time(NULL);
    if (config.timeout != -1 && timeout <= 0) {
      std::cout << "Requests to " << hostport << "timed out.";
      ok = false;
      break;
    }
    assert(ok);
    ctl_poll(pollfds, &sc);
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  shutdown(fd, SHUT_WR);
  close(fd);
  return ok ? 0 : -1;
}

int run(char **uris, int n)
{
  spdylay_session_callbacks callbacks;
  memset(&callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks.send_callback = send_callback;
  callbacks.recv_callback = recv_callback;
  callbacks.on_stream_close_callback = on_stream_close_callback;
  if(config.verbose) {
    callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback3;
    callbacks.on_data_recv_callback = on_data_recv_callback;
    callbacks.on_ctrl_send_callback = on_ctrl_send_callback3;
  } else {
    callbacks.on_ctrl_recv_callback = on_ctrl_recv_callback2;
    callbacks.on_ctrl_send_callback = on_ctrl_send_callback2;
  }
  if(!config.null_out) {
    callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
  }
  ssl_debug = config.verbose;
  std::vector<Request> reqvec;
  std::string prev_host;
  uint16_t prev_port = 0;
  int failures = 0;
  for(int i = 0; i < n; ++i) {
    uri::UriStruct us;
    if(uri::parse(us, uris[i])) {
      if(prev_host != us.host || prev_port != us.port) {
        if(!reqvec.empty()) {
          if (communicate(prev_host, prev_port, reqvec, &callbacks) != 0) {
            ++failures;
          }
          reqvec.clear();
        }
        prev_host = us.host;
        prev_port = us.port;
      }
      reqvec.push_back(Request(us));
    }
  }
  if(!reqvec.empty()) {
    if (communicate(prev_host, prev_port, reqvec, &callbacks) != 0) {
      ++failures;
    }
  }
  return failures;
}

void print_usage(std::ostream& out)
{
  out << "Usage: spdycat [-Onv3] [-t=seconds] [--cert=CERT] [--key=KEY] [URI...]" << std::endl;
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
      << "    -3, --spdy3        Only use SPDY/3.\n"
      << "    -t, --timeout=N    Timeout each request after N seconds.\n"
      << "    --cert=CERT        Use the specified client certificate file.\n"
      << "                       The file must be in PEM format.\n"
      << "    --key=KEY          Use the client private key file. The file\n"
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
      {"spdy3", no_argument, 0, '3' },
      {"timeout", required_argument, 0, 't' },
      {"cert", required_argument, &flag, 1 },
      {"key", required_argument, &flag, 2 },
      {"help", no_argument, 0, 'h' },
      {0, 0, 0, 0 }
    };
    int option_index = 0;
    int c = getopt_long(argc, argv, "Onhv3t", long_options, &option_index);
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
    case '3':
      config.spdy3_only = true;
      break;
    case 't':
      config.timeout = atoi(optarg);
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
