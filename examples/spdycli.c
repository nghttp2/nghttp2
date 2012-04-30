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
/*
 * This program is written to show how to use Spdylay API in C and
 * intentionally made simple.
 */
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>

#include <spdylay/spdylay.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <zlib.h>

enum {
  IO_NONE,
  WANT_READ,
  WANT_WRITE
};

struct Connection {
  SSL *ssl;
  spdylay_session *session;
  /* WANT_READ if SSL connection needs more input; or WANT_WRITE if it
     needs more output; or IO_NONE. This is necessary because SSL/TLS
     re-negotiation is possible at any time. Spdylay API offers
     similar functions like spdylay_session_want_read() and
     spdylay_session_want_write() but they do not take into account
     SSL connection. */
  int want_io;
};

struct Request {
  char *host;
  uint16_t port;
  /* In this program, path contains query component as well. */
  char *path;
  /* This is the concatenation of host and port with ":" in
     between. */
  char *hostport;
  /* Stream ID for this request. */
  int32_t stream_id;
  /* zlib context for gzip response */
  z_stream *inflater;
};

struct URI {
  const char *host;
  size_t hostlen;
  uint16_t port;
  /* In this program, path contains query component as well. */
  const char *path;
  size_t pathlen;
  const char *hostport;
  size_t hostportlen;
};

/*
 * Returns copy of string |s| with the length |len|. The returned
 * string is NULL-terminated.
 */
static char* strcopy(const char *s, size_t len)
{
  char *dst;
  dst = malloc(len+1);
  memcpy(dst, s, len);
  dst[len] = '\0';
  return dst;
}

/*
 * Prints error message |msg| and exit.
 */
static void die(const char *msg)
{
  fprintf(stderr, "FATAL: %s\n", msg);
  exit(EXIT_FAILURE);
}

/*
 * Prints error containing the function name |func| and message |msg|
 * and exit.
 */
static void dief(const char *func, const char *msg)
{
  fprintf(stderr, "FATAL: %s: %s\n", func, msg);
  exit(EXIT_FAILURE);
}

/*
 * Prints error containing the function name |func| and error code
 * |error_code| and exit.
 */
static void diec(const char *func, int error_code)
{
  fprintf(stderr, "FATAL: %s: error_code=%d\n", func, error_code);
  exit(EXIT_FAILURE);
}

/*
 * Check response is content-encoding: gzip. We need this because SPDY
 * client is required to support gzip.
 */
static void check_gzip(struct Request *req, char **nv)
{
  int gzip = 0;
  size_t i;
  for(i = 0; nv[i]; i += 2) {
    if(strcmp("content-encoding", nv[i]) == 0) {
      gzip = strcmp("gzip", nv[i+1]) == 0;
      break;
    }
  }
  if(gzip) {
    if(req->inflater) {
      return;
    }
    req->inflater = spdylay_new_inflate_stream();
    if (req->inflater == NULL) {
      die("Can't allocate inflate stream.");
    }
  }
}

/*
 * The implementation of spdylay_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * spdylay_send_callback for the details.
 */
static ssize_t send_callback(spdylay_session *session,
                             const uint8_t *data, size_t length, int flags,
                             void *user_data)
{
  struct Connection *connection;
  ssize_t rv;
  connection = (struct Connection*)user_data;
  connection->want_io = IO_NONE;
  rv = SSL_write(connection->ssl, data, length);
  if(rv < 0) {
    int err = SSL_get_error(connection->ssl, rv);
    if(err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      connection->want_io = (err == SSL_ERROR_WANT_READ ?
                             WANT_READ : WANT_WRITE);
      rv = SPDYLAY_ERR_WOULDBLOCK;
    } else {
      rv = SPDYLAY_ERR_CALLBACK_FAILURE;
    }
  }
  return rv;
}

/*
 * The implementation of spdylay_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of spdylay_recv_callback for the details.
 */
static ssize_t recv_callback(spdylay_session *session,
                             uint8_t *buf, size_t length, int flags,
                             void *user_data)
{
  struct Connection *connection;
  ssize_t rv;
  connection = (struct Connection*)user_data;
  connection->want_io = IO_NONE;
  rv = SSL_read(connection->ssl, buf, length);
  if(rv < 0) {
    int err = SSL_get_error(connection->ssl, rv);
    if(err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      connection->want_io = (err == SSL_ERROR_WANT_READ ?
                             WANT_READ : WANT_WRITE);
      rv = SPDYLAY_ERR_WOULDBLOCK;
    } else {
      rv = SPDYLAY_ERR_CALLBACK_FAILURE;
    }
  }
  return rv;
}

/*
 * The implementation of spdylay_before_ctrl_send_callback type.  We
 * use this function to get stream ID of the request. This is because
 * stream ID is not known when we submit the request
 * (spdylay_submit_request).
 */
static void before_ctrl_send_callback(spdylay_session *session,
                                      spdylay_frame_type type,
                                      spdylay_frame *frame,
                                      void *user_data)
{
  if(type == SPDYLAY_SYN_STREAM) {
    struct Request *req;
    int stream_id = frame->syn_stream.stream_id;
    req = spdylay_session_get_stream_user_data(session, stream_id);
    if(req && req->stream_id == -1) {
      req->stream_id = stream_id;
      printf("[INFO] Stream ID = %d\n", stream_id);
    }
  }
}

static void on_ctrl_send_callback(spdylay_session *session,
                                  spdylay_frame_type type,
                                  spdylay_frame *frame, void *user_data)
{
  char **nv;
  const char *name = NULL;
  int32_t stream_id;
  size_t i;
  switch(type) {
  case SPDYLAY_SYN_STREAM:
    nv = frame->syn_stream.nv;
    name = "SYN_STREAM";
    stream_id = frame->syn_stream.stream_id;
    break;
  default:
    break;
  }
  if(name && spdylay_session_get_stream_user_data(session, stream_id)) {
    printf("[INFO] C ----------------------------> S (%s)\n", name);
    for(i = 0; nv[i]; i += 2) {
      printf("       %s: %s\n", nv[i], nv[i+1]);
    }
  }
}

static void on_ctrl_recv_callback(spdylay_session *session,
                                  spdylay_frame_type type,
                                  spdylay_frame *frame, void *user_data)
{
  struct Request *req;
  char **nv;
  const char *name = NULL;
  int32_t stream_id;
  size_t i;
  switch(type) {
  case SPDYLAY_SYN_REPLY:
    nv = frame->syn_reply.nv;
    name = "SYN_REPLY";
    stream_id = frame->syn_reply.stream_id;
    break;
  case SPDYLAY_HEADERS:
    nv = frame->headers.nv;
    name = "HEADERS";
    stream_id = frame->headers.stream_id;
    break;
  default:
    break;
  }
  if(!name) {
    return;
  }
  req = spdylay_session_get_stream_user_data(session, stream_id);
  if(req) {
    check_gzip(req, nv);
    printf("[INFO] C <---------------------------- S (%s)\n", name);
    for(i = 0; nv[i]; i += 2) {
      printf("       %s: %s\n", nv[i], nv[i+1]);
    }
  }
}

/*
 * The implementation of spdylay_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static void on_stream_close_callback(spdylay_session *session,
                                     int32_t stream_id,
                                     spdylay_status_code status_code,
                                     void *user_data)
{
  struct Request *req;
  req = spdylay_session_get_stream_user_data(session, stream_id);
  if(req) {
    int rv;
    rv = spdylay_submit_goaway(session, SPDYLAY_GOAWAY_OK);
    if(rv != 0) {
      diec("spdylay_submit_goaway", rv);
    }
  }
}

#define MAX_OUTLEN 4096

/*
 * The implementation of spdylay_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
static void on_data_chunk_recv_callback(spdylay_session *session, uint8_t flags,
                                        int32_t stream_id,
                                        const uint8_t *data, size_t len,
                                        void *user_data)
{
  struct Request *req;
  req = spdylay_session_get_stream_user_data(session, stream_id);
  if(req) {
    printf("[INFO] C <---------------------------- S (DATA)\n");
    printf("       %lu bytes\n", (unsigned long int)len);
    if(req->inflater) {
      while(len > 0) {
        uint8_t out[MAX_OUTLEN];
        size_t outlen = MAX_OUTLEN;
        size_t tlen = len;
        int rv;
        rv = spdylay_inflate_data(req->inflater, out, &outlen, data, &tlen);
        if(rv == -1) {
          spdylay_submit_rst_stream(session, stream_id, SPDYLAY_INTERNAL_ERROR);
          break;
        }
        fwrite(out, 1, outlen, stdout);
        data += tlen;
        len -= tlen;
      }
    } else {
      /* TODO add support gzip */
      fwrite(data, 1, len, stdout);
    }
    printf("\n");
  }
}

/*
 * Setup callback functions. Spdylay API offers many callback
 * functions, but most of them are optional. The send_callback is
 * always required. Since we use spdylay_session_recv(), the
 * recv_callback is also required.
 */
static void setup_spdylay_callbacks(spdylay_session_callbacks *callbacks)
{
  memset(callbacks, 0, sizeof(spdylay_session_callbacks));
  callbacks->send_callback = send_callback;
  callbacks->recv_callback = recv_callback;
  callbacks->before_ctrl_send_callback = before_ctrl_send_callback;
  callbacks->on_ctrl_send_callback = on_ctrl_send_callback;
  callbacks->on_ctrl_recv_callback = on_ctrl_recv_callback;
  callbacks->on_stream_close_callback = on_stream_close_callback;
  callbacks->on_data_chunk_recv_callback = on_data_chunk_recv_callback;
}

/*
 * Callback function for SSL/TLS NPN. Since this program only supports
 * SPDY protocol, if server does not offer SPDY protocol the Spdylay
 * library supports, we terminate program.
 */
static int select_next_proto_cb(SSL* ssl,
                                unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen,
                                void *arg)
{
  int rv;
  uint16_t *spdy_proto_version;
  /* spdylay_select_next_protocol() selects SPDY protocol version the
     Spdylay library supports. */
  rv = spdylay_select_next_protocol(out, outlen, in, inlen);
  if(rv <= 0) {
    die("Server did not advertise spdy/2 or spdy/3 protocol.");
  }
  spdy_proto_version = (uint16_t*)arg;
  *spdy_proto_version = rv;
  return SSL_TLSEXT_ERR_OK;
}

/*
 * Setup SSL context. We pass |spdy_proto_version| to get negotiated
 * SPDY protocol version in NPN callback.
 */
static void init_ssl_ctx(SSL_CTX *ssl_ctx, uint16_t *spdy_proto_version)
{
  /* Disable SSLv2 and enable all workarounds for buggy servers */
  SSL_CTX_set_options(ssl_ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
  /* Set NPN callback */
  SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb,
                                   spdy_proto_version);
}

static void ssl_handshake(SSL *ssl, int fd)
{
  int rv;
  if(SSL_set_fd(ssl, fd) == 0) {
    dief("SSL_set_fd", ERR_error_string(ERR_get_error(), NULL));
  }
  rv = SSL_connect(ssl);
  if(rv <= 0) {
    dief("SSL_connect", ERR_error_string(ERR_get_error(), NULL));
  }
}

/*
 * Connects to the host |host| and port |port|.  This function returns
 * the file descriptor of the client socket.
 */
static int connect_to(const char *host, uint16_t port)
{
  struct addrinfo hints;
  int fd = -1;
  int rv;
  char service[NI_MAXSERV];
  struct addrinfo *res, *rp;
  snprintf(service, sizeof(service), "%u", port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  rv = getaddrinfo(host, service, &hints, &res);
  if(rv != 0) {
    dief("getaddrinfo", gai_strerror(rv));
  }
  for(rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if(fd == -1) {
      continue;
    }
    while((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 &&
          errno == EINTR);
    if(rv == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

static void make_non_block(int fd)
{
  int flags, rv;
  while((flags = fcntl(fd, F_GETFL, 0)) == -1 && errno == EINTR);
  if(flags == -1) {
    dief("fcntl", strerror(errno));
  }
  while((rv = fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1 && errno == EINTR);
  if(rv == -1) {
    dief("fcntl", strerror(errno));
  }
}

/*
 * Setting TCP_NODELAY is not mandatory for the SPDY protocol.
 */
static void set_tcp_nodelay(int fd)
{
  int val = 1;
  int rv;
  rv = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, (socklen_t)sizeof(val));
  if(rv == -1) {
    dief("setsockopt", strerror(errno));
  }
}

/*
 * Update |pollfd| based on the state of |connection|.
 */
static void ctl_poll(struct pollfd *pollfd, struct Connection *connection)
{
  pollfd->events = 0;
  if(spdylay_session_want_read(connection->session) ||
     connection->want_io == WANT_READ) {
    pollfd->events |= POLLIN;
  }
  if(spdylay_session_want_write(connection->session) ||
     connection->want_io == WANT_WRITE) {
    pollfd->events |= POLLOUT;
  }
}

/*
 * Submits the request |req| to the connection |connection|.  This
 * function does not send packets; just append the request to the
 * internal queue in |connection->session|.
 */
static void submit_request(struct Connection *connection, struct Request *req)
{
  int pri = 0;
  int rv;
  const char *nv[15];
  /* We always use SPDY/3 style header even if the negotiated protocol
     version is SPDY/2. The library translates the header name as
     necessary. Make sure that the last item is NULL! */
  nv[0] = ":method";     nv[1] = "GET";
  nv[2] = ":path";       nv[3] = req->path;
  nv[4] = ":version";    nv[5] = "HTTP/1.1";
  nv[6] = ":scheme";     nv[7] = "https";
  nv[8] = ":host";       nv[9] = req->hostport;
  nv[10] = "accept";     nv[11] = "*/*";
  nv[12] = "user-agent"; nv[13] = "spdylay/"SPDYLAY_VERSION;
  nv[14] = NULL;
  rv = spdylay_submit_request(connection->session, pri, nv, NULL, req);
  if(rv != 0) {
    diec("spdylay_submit_request", rv);
  }
}

/*
 * Performs the network I/O.
 */
static void exec_io(struct Connection *connection)
{
  int rv;
  rv = spdylay_session_recv(connection->session);
  if(rv != 0) {
    diec("spdylay_session_recv", rv);
  }
  rv = spdylay_session_send(connection->session);
  if(rv != 0) {
    diec("spdylay_session_send", rv);
  }
}

static void request_init(struct Request *req, const struct URI *uri)
{
  req->host = strcopy(uri->host, uri->hostlen);
  req->port = uri->port;
  req->path = strcopy(uri->path, uri->pathlen);
  req->hostport = strcopy(uri->hostport, uri->hostportlen);
  req->stream_id = -1;
  req->inflater = NULL;
}

static void request_free(struct Request *req)
{
  free(req->host);
  free(req->path);
  free(req->hostport);
  spdylay_free_inflate_stream(req->inflater);
}

/*
 * Fetches the resource denoted by |uri|.
 */
static void fetch_uri(const struct URI *uri)
{
  spdylay_session_callbacks callbacks;
  int fd;
  SSL_CTX *ssl_ctx;  
  SSL *ssl;
  struct Request req;
  struct Connection connection;
  int rv;
  nfds_t npollfds = 1;
  struct pollfd pollfds[1];
  uint16_t spdy_proto_version;

  request_init(&req, uri);

  setup_spdylay_callbacks(&callbacks);

  /* Establish connection and setup SSL */
  fd = connect_to(req.host, req.port);
  ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  if(ssl_ctx == NULL) {
    dief("SSL_CTX_new", ERR_error_string(ERR_get_error(), NULL));
  }
  init_ssl_ctx(ssl_ctx, &spdy_proto_version);
  ssl = SSL_new(ssl_ctx);
  if(ssl == NULL) {
    dief("SSL_new", ERR_error_string(ERR_get_error(), NULL));
  }
  /* To simplify the program, we perform SSL/TLS handshake in blocking
     I/O. */
  ssl_handshake(ssl, fd);

  connection.ssl = ssl;
  connection.want_io = IO_NONE;

  /* Here make file descriptor non-block */
  make_non_block(fd);
  set_tcp_nodelay(fd);
  
  printf("[INFO] SPDY protocol version = %d\n", spdy_proto_version);
  rv = spdylay_session_client_new(&connection.session, spdy_proto_version,
                                  &callbacks, &connection);
  if(rv != 0) {
    diec("spdylay_session_client_new", rv);
  }
  
  /* Submit the HTTP request to the outbound queue. */
  submit_request(&connection, &req);

  pollfds[0].fd = fd;
  ctl_poll(pollfds, &connection);

  /* Event loop */
  while(spdylay_session_want_read(connection.session) ||
        spdylay_session_want_write(connection.session)) {
    int nfds = poll(pollfds, npollfds, -1);
    if(nfds == -1) {
      dief("poll", strerror(errno));
    }
    if(pollfds[0].revents & (POLLIN | POLLOUT)) {
      exec_io(&connection);
    }
    if((pollfds[0].revents & POLLHUP) || (pollfds[0].revents & POLLERR)) {
      die("Connection error");
    }
    ctl_poll(pollfds, &connection);
  }

  /* Resource cleanup */
  spdylay_session_del(connection.session);
  SSL_shutdown(ssl);
  SSL_free(ssl);
  SSL_CTX_free(ssl_ctx);
  shutdown(fd, SHUT_WR);
  close(fd);
  request_free(&req);
}

static int parse_uri(struct URI *res, const char *uri)
{
  /* We only interested in https */
  size_t len, i, offset;
  memset(res, 0, sizeof(struct URI));
  len = strlen(uri);
  if(len < 9 || memcmp("https://", uri, 8) != 0) {
    return -1;
  }
  offset = 8;
  res->host = res->hostport = &uri[offset];
  res->hostlen = 0;
  if(uri[offset] == '[') {
    /* IPv6 literal address */
    ++offset;
    ++res->host;
    for(i = offset; i < len; ++i) {
      if(uri[i] == ']') {
        res->hostlen = i-offset;
        offset = i+1;
        break;
      }
    }
  } else {
    const char delims[] = ":/?#";
    for(i = offset; i < len; ++i) {
      if(strchr(delims, uri[i]) != NULL) {
        break;
      }
    }
    res->hostlen = i-offset;
    offset = i;
  }
  if(res->hostlen == 0) {
    return -1;
  }
  /* Assuming https */
  res->port = 443;
  if(offset < len) {
    if(uri[offset] == ':') {
      /* port */
      const char delims[] = "/?#";
      int port = 0;
      ++offset;
      for(i = offset; i < len; ++i) {
        if(strchr(delims, uri[i]) != NULL) {
          break;
        }
        if('0' <= uri[i] && uri[i] <= '9') {
          port *= 10;
          port += uri[i]-'0';
          if(port > 65535) {
            return -1;
          }
        } else {
          return -1;
        }
      }
      if(port == 0) {
        return -1;
      }
      offset = i;
      res->port = port;
    }
  }
  res->hostportlen = uri+offset-res->host;
  for(i = offset; i < len; ++i) {
    if(uri[i] == '#') {
      break;
    }
  }
  if(i-offset == 0) {
    res->path = "/";
    res->pathlen = 1;
  } else {
    res->path = &uri[offset];
    res->pathlen = i-offset;
  }
  return 0;
}

int main(int argc, char **argv)
{
  struct URI uri;
  struct sigaction act;
  int rv;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, 0);

  SSL_load_error_strings();
  SSL_library_init();

  rv = parse_uri(&uri, argv[1]);
  if(rv != 0) {
    die("parse_uri failed");
  }
  fetch_uri(&uri);
  return EXIT_SUCCESS;
}
