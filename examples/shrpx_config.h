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
#ifndef SHRPX_CONFIG_H
#define SHRPX_CONFIG_H

#include "shrpx.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string>

namespace shrpx {

union sockaddr_union {
  sockaddr sa;
  sockaddr_storage storage;
  sockaddr_in6 in6;
  sockaddr_in in;
};

struct Config {
  bool verbose;
  bool daemon;
  const char *host;
  uint16_t port;
  const char *private_key_file;
  const char *cert_file;
  bool verify_client;
  const char *server_name;
  const char *downstream_host;
  uint16_t downstream_port;
  const char *downstream_hostport;
  sockaddr_union downstream_addr;
  size_t downstream_addrlen;
  timeval spdy_upstream_read_timeout;
  timeval upstream_read_timeout;
  timeval upstream_write_timeout;
  timeval downstream_read_timeout;
  timeval downstream_write_timeout;
  timeval downstream_idle_read_timeout;
  size_t num_worker;
  size_t spdy_max_concurrent_streams;
  bool spdy_proxy;
  bool add_x_forwarded_for;
  Config();
};

const Config* get_config();
Config* mod_config();
void create_config();

} // namespace shrpx

#endif // SHRPX_CONFIG_H
