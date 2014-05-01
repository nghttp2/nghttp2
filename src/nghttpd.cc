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
#include "nghttp2_config.h"

#include <unistd.h>
#include <signal.h>
#include <getopt.h>

#include <cstdlib>
#include <cstring>
#include <cassert>
#include <string>
#include <iostream>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nghttp2/nghttp2.h>

#include "app_helper.h"
#include "HttpServer.h"
#include "util.h"
#include "ssl.h"

namespace nghttp2 {

namespace {
int parse_push_config(Config& config, const char *optarg)
{
  const char *eq = strchr(optarg, '=');
  if(eq == NULL) {
    return -1;
  }
  auto paths = std::vector<std::string>();
  auto optarg_end = optarg + strlen(optarg);
  const char *i = eq + 1;
  for(;;) {
    const char *j = strchr(i, ',');
    if(j == NULL) {
      j = optarg_end;
    }
    paths.emplace_back(i, j);
    if(j == optarg_end) {
      break;
    }
    i = j;
    ++i;
  }
  config.push[std::string(optarg, eq)] = std::move(paths);
  return 0;
}
} // namespace

namespace {
void print_version(std::ostream& out)
{
  out << "nghttpd nghttp2/" NGHTTP2_VERSION << std::endl;
}
} // namespace

namespace {
void print_usage(std::ostream& out)
{
  out << "Usage: nghttpd [OPTION]... <PORT> <PRIVATE_KEY> <CERT>\n"
      << "  or:  nghttpd --no-tls [OPTION]... <PORT>\n"
      << "HTTP/2 experimental server" << std::endl;
}
} // namespace

namespace {
void print_help(std::ostream& out)
{
  print_usage(out);
  out << R"(
  <PORT>             Specify listening port number.
  <PRIVATE_KEY>      Set  path  to  server's  private  key.   Required
                     unless --no-tls is specified.
  <CERT>             Set  path  to   server's  certificate.   Required
                     unless --no-tls is specified.
Options:
  -D, --daemon       Run in a background.  If  -D is used, the current
                     working directory  is changed to  '/'.  Therefore
                     if  this  option  is  used,  -d  option  must  be
                     specified.
  -V, --verify-client
                     The  server sends  a client  certificate request.
                     If the  client did not return  a certificate, the
                     handshake is terminated.   Currently, this option
                     just requests  a client certificate and  does not
                     verify it.
  -d, --htdocs=<PATH>
                     Specify  document root.   If this  option is  not
                     specified,  the  document  root  is  the  current
                     working directory.
  -v, --verbose      Print  debug   information  such   as  reception/
                     transmission of frames and name/value pairs.
  --no-tls           Disable SSL/TLS.
  -c, --header-table-size=<N>
                     Specify decoder header table size.
  --color            Force colored log output.
  -p, --push=<PATH>=<PUSH_PATH,...>
                     Push  resources   <PUSH_PATH>s  when   <PATH>  is
                     requested.  This option can be used repeatedly to
                     specify multiple push configurations.  <PATH> and
                     <PUSH_PATH>s are relative  to document root.  See
                     --htdocs    option.      Example:    -p/=/foo.png
                     -p/doc=/bar.css
  -b, --padding=<N>  Add  at most  <N>  bytes to  a  frame payload  as
                     padding.  Specify 0 to disable padding.
  -n, --workers=<CORE>
                     Set the number of worker threads.
                     Default: 1
  -e, --error-gzip   Make error response gzipped.
  --version          Display version information and exit.
  -h, --help         Display this help and exit.)"
      << std::endl;
}
} // namespace

int main(int argc, char **argv)
{
  Config config;
  bool color = false;
  while(1) {
    static int flag = 0;
    static option long_options[] = {
      {"daemon", no_argument, nullptr, 'D'},
      {"htdocs", required_argument, nullptr, 'd'},
      {"help", no_argument, nullptr, 'h'},
      {"verbose", no_argument, nullptr, 'v'},
      {"verify-client", no_argument, nullptr, 'V'},
      {"header-table-size", required_argument, nullptr, 'c'},
      {"push", required_argument, nullptr, 'p'},
      {"padding", required_argument, nullptr, 'b'},
      {"workers", required_argument, nullptr, 'n'},
      {"error-gzip", no_argument, nullptr, 'e'},
      {"no-tls", no_argument, &flag, 1},
      {"color", no_argument, &flag, 2},
      {"version", no_argument, &flag, 3},
      {nullptr, 0, nullptr, 0}
    };
    int option_index = 0;
    int c = getopt_long(argc, argv, "DVb:c:d:ehn:p:v", long_options,
                        &option_index);
    char *end;
    if(c == -1) {
      break;
    }
    switch(c) {
    case 'D':
      config.daemon = true;
      break;
    case 'V':
      config.verify_client = true;
      break;
    case 'b':
      config.padding = strtol(optarg, nullptr, 10);
      break;
    case 'd':
      config.htdocs = optarg;
      break;
    case 'e':
      config.error_gzip = true;
      break;
    case 'n':
#ifdef NOTHREADS
	  std::cerr << "-n: WARNING: Threading disabled at build time, " <<
		  "no threads created." << std::endl;
#else
      errno = 0;
      config.num_worker = strtoul(optarg, &end, 10);
      if(errno == ERANGE || *end != '\0' || config.num_worker == 0) {
        std::cerr << "-n: Bad option value: " << optarg << std::endl;
        exit(EXIT_FAILURE);
      }
#endif /* NOTHREADS */
      break;
    case 'h':
      print_help(std::cout);
      exit(EXIT_SUCCESS);
    case 'v':
      config.verbose = true;
      break;
    case 'c':
      errno = 0;
      config.header_table_size = strtol(optarg, &end, 10);
      if(errno == ERANGE || *end != '\0') {
        std::cerr << "-c: Bad option value: " << optarg << std::endl;
        exit(EXIT_FAILURE);
      }
      break;
    case 'p':
      if(parse_push_config(config, optarg) != 0) {
        std::cerr << "-p: Bad option value: " << optarg << std::endl;
      }
      break;
    case '?':
      util::show_candidates(argv[optind - 1], long_options);
      exit(EXIT_FAILURE);
    case 0:
      switch(flag) {
      case 1:
        // no-tls option
        config.no_tls = true;
        break;
      case 2:
        // color option
        color = true;
        break;
      case 3:
        // version
        print_version(std::cout);
        exit(EXIT_SUCCESS);
      }
      break;
    default:
      break;
    }
  }
  if(argc - optind < (config.no_tls ? 1 : 3)) {
    print_usage(std::cerr);
    std::cerr << "Too few arguments" << std::endl;
    exit(EXIT_FAILURE);
  }

  config.port = strtol(argv[optind++], nullptr, 10);

  if(!config.no_tls) {
    config.private_key_file = argv[optind++];
    config.cert_file = argv[optind++];
  }

  if(config.daemon) {
    if(config.htdocs.empty()) {
      print_usage(std::cerr);
      std::cerr << "-d option must be specified when -D is used." << std::endl;
      exit(EXIT_FAILURE);
    }
    if(daemon(0, 0) == -1) {
      perror("daemon");
      exit(EXIT_FAILURE);
    }
  }
  if(config.htdocs.empty()) {
    config.htdocs = "./";
  }

  set_color_output(color || isatty(fileno(stdout)));

  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, nullptr);
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  SSL_library_init();
#ifndef NOTHREADS
  ssl::LibsslGlobalLock();
#endif /* NOTHREADS */

  reset_timer();

  HttpServer server(&config);
  server.run();
  return 0;
}

} // namespace nghttp2

int main(int argc, char **argv)
{
  return nghttp2::main(argc, argv);
}
