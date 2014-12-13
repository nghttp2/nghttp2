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
/*
 * This program is intended to measure library performance, avoiding
 * overhead of underlying I/O library (e.g., libevent, Boost ASIO).
 */
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* !HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include <nghttp2/nghttp2.h>

#define SERVER_NAME "tiny-nghttpd nghttp2/" NGHTTP2_VERSION

#define MAKE_NV(name, value)                                                   \
  {                                                                            \
    (uint8_t *)(name), (uint8_t *)(value), sizeof((name)) - 1,                 \
        sizeof((value)) - 1, NGHTTP2_NV_FLAG_NONE                              \
  }

#define MAKE_NV2(name, value, valuelen)                                        \
  {                                                                            \
    (uint8_t *)(name), (uint8_t *)(value), sizeof((name)) - 1, (valuelen),     \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define array_size(a) (sizeof((a)) / sizeof((a)[0]))

/* Returns the length of remaning data in buffer */
#define io_buf_len(iobuf) ((iobuf)->last - (iobuf)->pos)
/* Returns the space buffer can still accept */
#define io_buf_left(iobuf) ((iobuf)->end - (iobuf)->last)

typedef struct {
  /* beginning of buffer */
  uint8_t *begin;
  /* one byte beyond the end of buffer */
  uint8_t *end;
  /* next read/write position of buffer */
  uint8_t *pos;
  /* one byte beyond last data of buffer */
  uint8_t *last;
} io_buf;

typedef struct {
  /* epoll fd */
  int epfd;
} io_loop;

typedef struct stream {
  struct stream *prev, *next;
  /* mandatory header fields */
  char *method;
  char *scheme;
  char *authority;
  char *path;
  char *host;
  /* region of response body in rawscrbuf */
  uint8_t *res_begin, *res_end;
  /* io_buf wrapping rawscrbuf */
  io_buf scrbuf;
  int64_t fileleft;
  /* length of mandatory header fields */
  size_t methodlen;
  size_t schemelen;
  size_t authoritylen;
  size_t pathlen;
  size_t hostlen;
  /* stream ID of this stream */
  int32_t stream_id;
  /* fd for reading file */
  int filefd;
  /* scratch buffer for this stream */
  uint8_t rawscrbuf[4096];
} stream;

typedef struct { int (*handler)(io_loop *, uint32_t, void *); } evhandle;

typedef struct {
  evhandle evhn;
  nghttp2_session *session;
  /* list of stream */
  stream strm_head;
  /* pending library output */
  const uint8_t *cache;
  /* io_buf wrapping rawoutbuf */
  io_buf buf;
  /* length of cache */
  size_t cachelen;
  /* client fd */
  int fd;
  /* output buffer */
  uint8_t rawoutbuf[65536];
} connection;

typedef struct {
  evhandle evhn;
  /* listening fd */
  int fd;
} server;

typedef struct {
  evhandle evhn;
  /* timerfd */
  int fd;
} timer;

/* document root */
const char *docroot;
/* length of docroot */
size_t docrootlen;

nghttp2_session_callbacks *shared_callbacks;
nghttp2_option *shared_option;

static int handle_accept(io_loop *loop, uint32_t events, void *ptr);
static int handle_connection(io_loop *loop, uint32_t events, void *ptr);
static int handle_timer(io_loop *loop, uint32_t events, void *ptr);

static void io_buf_init(io_buf *buf, uint8_t *underlying, size_t len) {
  buf->begin = buf->pos = buf->last = underlying;
  buf->end = underlying + len;
}

static void io_buf_add(io_buf *buf, const void *src, size_t len) {
  memcpy(buf->last, src, len);
  buf->last += len;
}

static char *io_buf_add_str(io_buf *buf, const void *src, size_t len) {
  uint8_t *start = buf->last;

  memcpy(buf->last, src, len);
  buf->last += len;
  *buf->last++ = '\0';

  return (char *)start;
}

static int memseq(const uint8_t *a, size_t alen, const char *b) {
  const uint8_t *last = a + alen;

  for (; a != last && *b && *a == *b; ++a, ++b)
    ;

  return a == last && *b == 0;
}

static char *cpydig(char *buf, int n, size_t len) {
  char *p;

  p = buf + len - 1;
  do {
    *p-- = (n % 10) + '0';
    n /= 10;
  } while (p >= buf);

  return buf + len;
}

static const char *MONTH[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
static const char *DAY_OF_WEEK[] = {"Sun", "Mon", "Tue", "Wed",
                                    "Thu", "Fri", "Sat"};

static size_t http_date(char *buf, time_t t) {
  struct tm tms;
  char *p = buf;

  if (gmtime_r(&t, &tms) == NULL) {
    return 0;
  }

  /* Sat, 27 Sep 2014 06:31:15 GMT */

  memcpy(p, DAY_OF_WEEK[tms.tm_wday], 3);
  p += 3;
  *p++ = ',';
  *p++ = ' ';
  p = cpydig(p, tms.tm_mday, 2);
  *p++ = ' ';
  memcpy(p, MONTH[tms.tm_mon], 3);
  p += 3;
  *p++ = ' ';
  p = cpydig(p, tms.tm_year + 1900, 4);
  *p++ = ' ';
  p = cpydig(p, tms.tm_hour, 2);
  *p++ = ':';
  p = cpydig(p, tms.tm_min, 2);
  *p++ = ':';
  p = cpydig(p, tms.tm_sec, 2);
  memcpy(p, " GMT", 4);
  p += 4;

  return p - buf;
}

static char date[29];
static char datelen;

static void update_date() { datelen = http_date(date, time(NULL)); }

static size_t utos(char *buf, size_t len, uint64_t n) {
  size_t nwrite = 0;
  uint64_t t = n;

  if (len == 0) {
    return 0;
  }

  if (n == 0) {
    buf[0] = '0';
    return 1;
  }

  for (; t; t /= 10, ++nwrite)
    ;

  if (nwrite > len) {
    return 0;
  }

  buf += nwrite - 1;
  do {
    *buf-- = (n % 10) + '0';
    n /= 10;
  } while (n);

  return nwrite;
}

static void print_errno(const char *prefix, int errnum) {
  char buf[1024];
  char *errmsg;

  errmsg = strerror_r(errnum, buf, sizeof(buf));

  fprintf(stderr, "%s: %s\n", prefix, errmsg);
}

#define list_insert(head, elem)                                                \
  do {                                                                         \
    (elem)->prev = (head);                                                     \
    (elem)->next = (head)->next;                                               \
                                                                               \
    if ((head)->next) {                                                        \
      (head)->next->prev = (elem);                                             \
    }                                                                          \
    (head)->next = (elem);                                                     \
  } while (0)

#define list_remove(elem)                                                      \
  do {                                                                         \
    (elem)->prev->next = (elem)->next;                                         \
    if ((elem)->next) {                                                        \
      (elem)->next->prev = (elem)->prev;                                       \
    }                                                                          \
  } while (0)

static stream *stream_new(int32_t stream_id, connection *conn) {
  stream *strm;

  strm = malloc(sizeof(stream));

  strm->prev = strm->next = NULL;
  strm->method = NULL;
  strm->scheme = NULL;
  strm->authority = NULL;
  strm->path = NULL;
  strm->host = NULL;
  strm->res_begin = NULL;
  strm->res_end = NULL;
  strm->methodlen = 0;
  strm->schemelen = 0;
  strm->authoritylen = 0;
  strm->pathlen = 0;
  strm->hostlen = 0;
  strm->stream_id = stream_id;
  strm->filefd = -1;
  strm->fileleft = 0;

  list_insert(&conn->strm_head, strm);

  io_buf_init(&strm->scrbuf, strm->rawscrbuf, sizeof(strm->rawscrbuf));

  return strm;
}

static void stream_del(stream *strm) {
  list_remove(strm);

  if (strm->filefd != -1) {
    close(strm->filefd);
  }

  free(strm);
}

static connection *connection_new(int fd) {
  connection *conn;
  int rv;

  conn = malloc(sizeof(connection));

  rv = nghttp2_session_server_new2(&conn->session, shared_callbacks, conn,
                                   shared_option);

  if (rv != 0) {
    goto cleanup;
  }

  conn->fd = fd;
  conn->cache = NULL;
  conn->cachelen = 0;
  io_buf_init(&conn->buf, conn->rawoutbuf, sizeof(conn->rawoutbuf));
  conn->evhn.handler = handle_connection;
  conn->strm_head.next = NULL;

  return conn;

cleanup:
  free(conn);
  return NULL;
}

static void connection_del(connection *conn) {
  stream *strm;

  nghttp2_session_del(conn->session);
  shutdown(conn->fd, SHUT_WR);
  close(conn->fd);

  strm = conn->strm_head.next;
  while (strm) {
    stream *next_strm = strm->next;

    stream_del(strm);
    strm = next_strm;
  }

  free(conn);
}

static int connection_start(connection *conn) {
  nghttp2_settings_entry iv = {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100};
  int rv;

  rv = nghttp2_submit_settings(conn->session, NGHTTP2_FLAG_NONE, &iv, 1);

  if (rv != 0) {
    return -1;
  }

  return 0;
}

static int server_init(server *serv, const char *node, const char *service) {
  int rv;
  struct addrinfo hints;
  struct addrinfo *res, *rp;
  int fd;
  int on = 1;
  socklen_t optlen = sizeof(on);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

  rv = getaddrinfo(node, service, &hints, &res);

  if (rv != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return -1;
  }

  for (rp = res; rp; rp = rp->ai_next) {
    fd =
        socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);

    if (fd == -1) {
      continue;
    }

    rv = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, optlen);

    if (rv == -1) {
      print_errno("setsockopt", errno);
    }

    if (bind(fd, rp->ai_addr, rp->ai_addrlen) != 0) {
      close(fd);
      continue;
    }

    if (listen(fd, 65536) != 0) {
      close(fd);
      continue;
    }

    break;
  }

  freeaddrinfo(res);

  if (!rp) {
    fprintf(stderr, "No address to bind\n");
    return -1;
  }

  serv->fd = fd;
  serv->evhn.handler = handle_accept;

  return 0;
}

static int timer_init(timer *tmr) {
  int fd;
  struct itimerspec timerval = {{1, 0}, {1, 0}};

  fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (fd == -1) {
    print_errno("timerfd_create", errno);
    return -1;
  }

  if (timerfd_settime(fd, 0, &timerval, NULL) != 0) {
    print_errno("timerfd_settime", errno);
    return -1;
  }

  tmr->fd = fd;
  tmr->evhn.handler = handle_timer;

  return 0;
}

static int io_loop_init(io_loop *loop) {
  int epfd;

  epfd = epoll_create1(0);

  if (epfd == -1) {
    print_errno("epoll_create", errno);
    return -1;
  }

  loop->epfd = epfd;

  return 0;
}

static int io_loop_ctl(io_loop *loop, int op, int fd, uint32_t events,
                       void *ptr) {
  int rv;
  struct epoll_event ev;

  ev.events = events;
  ev.data.ptr = ptr;

  rv = epoll_ctl(loop->epfd, op, fd, &ev);

  if (rv != 0) {
    print_errno("epoll_ctl", errno);
    return -1;
  }

  return 0;
}

static int io_loop_add(io_loop *loop, int fd, uint32_t events, void *ptr) {
  return io_loop_ctl(loop, EPOLL_CTL_ADD, fd, events, ptr);
}

static int io_loop_mod(io_loop *loop, int fd, uint32_t events, void *ptr) {
  return io_loop_ctl(loop, EPOLL_CTL_MOD, fd, events, ptr);
}

static int io_loop_run(io_loop *loop, server *serv _U_) {
#define NUM_EVENTS 1024
  struct epoll_event events[NUM_EVENTS];

  for (;;) {
    int nev;
    evhandle *evhn;
    struct epoll_event *ev, *end;

    while ((nev = epoll_wait(loop->epfd, events, NUM_EVENTS, -1)) == -1 &&
           errno == EINTR)
      ;

    if (nev == -1) {
      print_errno("epoll_wait", errno);
      return -1;
    }

    for (ev = events, end = events + nev; ev != end; ++ev) {
      evhn = ev->data.ptr;
      evhn->handler(loop, ev->events, ev->data.ptr);
    }
  }
}

static int handle_timer(io_loop *loop _U_, uint32_t events _U_, void *ptr) {
  timer *tmr = ptr;
  int64_t buf;
  ssize_t nread;

  while ((nread = read(tmr->fd, &buf, sizeof(buf))) == -1 && errno == EINTR)
    ;

  assert(nread == sizeof(buf));

  update_date();

  return 0;
}

static int handle_accept(io_loop *loop, uint32_t events _U_, void *ptr) {
  int acfd;
  server *serv = ptr;
  int on = 1;
  socklen_t optlen = sizeof(on);
  int rv;

  for (;;) {
    connection *conn;

    while ((acfd = accept4(serv->fd, NULL, NULL, SOCK_NONBLOCK)) == -1 &&
           errno == EINTR)
      ;

    if (acfd == -1) {
      switch (errno) {
      case ENETDOWN:
      case EPROTO:
      case ENOPROTOOPT:
      case EHOSTDOWN:
      case ENONET:
      case EHOSTUNREACH:
      case EOPNOTSUPP:
      case ENETUNREACH:
        continue;
      }
      return 0;
    }

    rv = setsockopt(acfd, IPPROTO_TCP, TCP_NODELAY, &on, optlen);

    if (rv == -1) {
      print_errno("setsockopt", errno);
    }

    conn = connection_new(acfd);

    if (conn == NULL) {
      close(acfd);
      continue;
    }

    if (connection_start(conn) != 0 ||
        io_loop_add(loop, acfd, EPOLLIN | EPOLLOUT, conn) != 0) {
      connection_del(conn);
    }
  }
}

static void stream_error(connection *conn, int32_t stream_id,
                         uint32_t error_code) {
  nghttp2_submit_rst_stream(conn->session, NGHTTP2_FLAG_NONE, stream_id,
                            error_code);
}

static ssize_t fd_read_callback(nghttp2_session *session _U_,
                                int32_t stream_id _U_, uint8_t *buf,
                                size_t length, uint32_t *data_flags,
                                nghttp2_data_source *source,
                                void *user_data _U_) {
  stream *strm = source->ptr;
  ssize_t nread;

  while ((nread = read(strm->filefd, buf, length)) == -1 && errno == EINTR)
    ;
  if (nread == -1) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  strm->fileleft -= nread;
  if (nread == 0 || strm->fileleft == 0) {
    if (strm->fileleft != 0) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }
  return nread;
}

static ssize_t resbuf_read_callback(nghttp2_session *session _U_,
                                    int32_t stream_id _U_, uint8_t *buf,
                                    size_t length, uint32_t *data_flags,
                                    nghttp2_data_source *source,
                                    void *user_data _U_) {
  stream *strm = source->ptr;
  size_t left = strm->res_end - strm->res_begin;
  size_t nwrite = length < left ? length : left;

  memcpy(buf, strm->res_begin, nwrite);
  strm->res_begin += nwrite;

  if (strm->res_begin == strm->res_end) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }

  return nwrite;
}

static int hex_digit(char c) {
  return ('0' <= c && c <= '9') || ('A' <= c && c <= 'F') ||
         ('a' <= c && c <= 'f');
}

static unsigned int hex_to_uint(char c) {
  if (c <= '9') {
    return c - '0';
  }

  if (c <= 'F') {
    return c - 'A' + 10;
  }

  return c - 'a' + 10;
}

static void percent_decode(io_buf *buf, const char *s) {
  for (; *s; ++s) {
    if (*s == '?' || *s == '#') {
      break;
    }

    if (*s == '%' && hex_digit(*(s + 1)) && hex_digit(*(s + 2))) {
      *buf->last++ = (hex_to_uint(*(s + 1)) << 4) + hex_to_uint(*(s + 2));
      s += 2;
      continue;
    }

    *buf->last++ = *s;
  }
}

static int check_path(const char *path, size_t len) {
  return path[0] == '/' && strchr(path, '\\') == NULL &&
         strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
         (len < 3 || memcmp(path + len - 3, "/..", 3) != 0) &&
         (len < 2 || memcmp(path + len - 2, "/.", 2) != 0);
}

static int make_path(io_buf *pathbuf, const char *req, size_t reqlen _U_) {
  uint8_t *p;

  if (req[0] != '/') {
    return -1;
  }

  if (docrootlen + strlen(req) + sizeof("index.html") >
      (size_t)io_buf_left(pathbuf)) {
    return -1;
  }

  io_buf_add(pathbuf, docroot, docrootlen);

  p = pathbuf->last;

  percent_decode(pathbuf, req);

  if (*(pathbuf->last - 1) == '/') {
    io_buf_add(pathbuf, "index.html", sizeof("index.html") - 1);
  }

  *pathbuf->last++ = '\0';

  if (!check_path((const char *)p, pathbuf->last - 1 - p)) {

    return -1;
  }

  return 0;
}

static int status_response(stream *strm, connection *conn,
                           const char *status_code) {
  int rv;
  size_t status_codelen = strlen(status_code);
  char contentlength[19];
  size_t contentlengthlen;
  size_t reslen;
  nghttp2_data_provider prd, *prdptr;
  nghttp2_nv nva[5] = {
      MAKE_NV(":status", ""), MAKE_NV("server", SERVER_NAME),
      MAKE_NV2("date", date, datelen), MAKE_NV("content-length", ""),
  };
  size_t nvlen = 3;

  nva[0].value = (uint8_t *)status_code;
  nva[0].valuelen = strlen(status_code);

#define BODY1 "<html><head><title>"
#define BODY2 "</title></head><body><h1>"
#define BODY3 "</h1></body></html>"

  reslen = sizeof(BODY1) - 1 + sizeof(BODY2) - 1 + sizeof(BODY3) - 1 +
           status_codelen * 2;

  if ((size_t)io_buf_left(&strm->scrbuf) < reslen) {
    contentlength[0] = '0';
    contentlengthlen = 1;
    prdptr = NULL;
  } else {
    contentlengthlen = utos(contentlength, sizeof(contentlength), reslen);

    strm->res_begin = strm->scrbuf.last;

    io_buf_add(&strm->scrbuf, BODY1, sizeof(BODY1) - 1);
    io_buf_add(&strm->scrbuf, status_code, strlen(status_code));
    io_buf_add(&strm->scrbuf, BODY2, sizeof(BODY2) - 1);
    io_buf_add(&strm->scrbuf, status_code, strlen(status_code));
    io_buf_add(&strm->scrbuf, BODY3, sizeof(BODY3) - 1);

    strm->res_end = strm->scrbuf.last;
    prdptr = &prd;
  }

  nva[nvlen].value = (uint8_t *)contentlength;
  nva[nvlen].valuelen = contentlengthlen;

  ++nvlen;

  prd.source.ptr = strm;
  prd.read_callback = resbuf_read_callback;

  rv = nghttp2_submit_response(conn->session, strm->stream_id, nva, nvlen,
                               prdptr);
  if (rv != 0) {
    return -1;
  }

  return 0;
}

static int redirect_response(stream *strm, connection *conn) {
  int rv;
  size_t locationlen;
  nghttp2_nv nva[5] = {
      MAKE_NV(":status", "301"),       MAKE_NV("server", SERVER_NAME),
      MAKE_NV2("date", date, datelen), MAKE_NV("content-length", "0"),
      MAKE_NV("location", ""),
  };

  /* + 1 for trailing '/' */
  locationlen = strm->schemelen + 3 + strm->hostlen + strm->pathlen + 1;
  if ((size_t)io_buf_left(&strm->scrbuf) < locationlen) {
    return -1;
  }

  nva[4].value = strm->scrbuf.last;
  nva[4].valuelen = locationlen;

  io_buf_add(&strm->scrbuf, strm->scheme, strm->schemelen);
  io_buf_add(&strm->scrbuf, "://", 3);
  io_buf_add(&strm->scrbuf, strm->host, strm->hostlen);
  io_buf_add(&strm->scrbuf, strm->path, strm->pathlen);
  *strm->scrbuf.last++ = '/';

  rv = nghttp2_submit_response(conn->session, strm->stream_id, nva,
                               array_size(nva), NULL);

  if (rv != 0) {
    return -1;
  }

  return 0;
}

static int process_request(stream *strm, connection *conn) {
  int fd;
  struct stat stbuf;
  int rv;
  nghttp2_data_provider prd;
  char lastmod[32];
  size_t lastmodlen;
  char contentlength[19];
  size_t contentlengthlen;
  char path[1024];
  io_buf pathbuf;
  nghttp2_nv nva[5] = {
      MAKE_NV(":status", "200"), MAKE_NV("server", SERVER_NAME),
      MAKE_NV2("date", date, datelen), MAKE_NV("content-length", ""),
  };
  size_t nvlen = 3;

  io_buf_init(&pathbuf, (uint8_t *)path, sizeof(path));

  rv = make_path(&pathbuf, strm->path, strm->pathlen);

  if (rv != 0) {
    return status_response(strm, conn, "400");
  }

  fd = open(path, O_RDONLY);

  if (fd == -1) {
    return status_response(strm, conn, "404");
  }

  strm->filefd = fd;

  rv = fstat(fd, &stbuf);

  if (rv == -1) {
    return status_response(strm, conn, "404");
  }

  if (stbuf.st_mode & S_IFDIR) {
    return redirect_response(strm, conn);
  }

  prd.source.ptr = strm;
  prd.read_callback = fd_read_callback;

  strm->fileleft = stbuf.st_size;

  lastmodlen = http_date(lastmod, stbuf.st_mtime.tv_sec);
  contentlengthlen = utos(contentlength, sizeof(contentlength), stbuf.st_size);

  nva[nvlen].value = (uint8_t *)contentlength;
  nva[nvlen].valuelen = contentlengthlen;

  ++nvlen;

  if (lastmodlen) {
    nva[nvlen].name = (uint8_t *)"last-modified";
    nva[nvlen].namelen = sizeof("last-modified") - 1;
    nva[nvlen].value = (uint8_t *)lastmod;
    nva[nvlen].valuelen = lastmodlen;
    nva[nvlen].flags = NGHTTP2_NV_FLAG_NONE;

    ++nvlen;
  }

  rv =
      nghttp2_submit_response(conn->session, strm->stream_id, nva, nvlen, &prd);
  if (rv != 0) {
    return -1;
  }

  return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  connection *conn = user_data;
  stream *strm;

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  strm = stream_new(frame->hd.stream_id, conn);

  if (!strm) {
    nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, frame->hd.stream_id,
                              NGHTTP2_INTERNAL_ERROR);
    return 0;
  }

  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, strm);

  return 0;
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags _U_,
                              void *user_data) {
  connection *conn = user_data;
  stream *strm;

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  strm = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

  if (!strm) {
    return 0;
  }

  if (!nghttp2_check_header_name(name, namelen) ||
      !nghttp2_check_header_value(value, valuelen)) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  if (memseq(name, namelen, ":method")) {
    if (strm->method) {
      stream_error(conn, strm->stream_id, NGHTTP2_PROTOCOL_ERROR);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    strm->method = io_buf_add_str(&strm->scrbuf, value, valuelen);
    if (!strm->method) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    strm->methodlen = valuelen;
    return 0;
  }

  if (memseq(name, namelen, ":scheme")) {
    if (strm->scheme) {
      stream_error(conn, strm->stream_id, NGHTTP2_PROTOCOL_ERROR);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    strm->scheme = io_buf_add_str(&strm->scrbuf, value, valuelen);
    if (!strm->scheme) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    strm->schemelen = valuelen;
    return 0;
  }

  if (memseq(name, namelen, ":authority")) {
    if (strm->authority) {
      stream_error(conn, strm->stream_id, NGHTTP2_PROTOCOL_ERROR);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    strm->authority = io_buf_add_str(&strm->scrbuf, value, valuelen);
    if (!strm->authority) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    strm->authoritylen = valuelen;
    return 0;
  }

  if (memseq(name, namelen, ":path")) {
    if (strm->path) {
      stream_error(conn, strm->stream_id, NGHTTP2_PROTOCOL_ERROR);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    strm->path = io_buf_add_str(&strm->scrbuf, value, valuelen);
    if (!strm->path) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    strm->pathlen = valuelen;
    return 0;
  }

  if (name[0] == ':') {
    stream_error(conn, strm->stream_id, NGHTTP2_PROTOCOL_ERROR);
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  if (memseq(name, namelen, "host") && !strm->host) {
    strm->host = io_buf_add_str(&strm->scrbuf, value, valuelen);
    if (!strm->host) {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    strm->hostlen = valuelen;
  }

  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  connection *conn = user_data;
  stream *strm;

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  strm = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

  if (!strm) {
    return 0;
  }

  if (!strm->method || !strm->scheme || !strm->path ||
      (!strm->authority && !strm->host)) {
    stream_error(conn, strm->stream_id, NGHTTP2_PROTOCOL_ERROR);
    return 0;
  }

  if (!strm->host) {
    strm->host = strm->authority;
    strm->hostlen = strm->authoritylen;
  }

  if (process_request(strm, conn) != 0) {
    stream_error(conn, strm->stream_id, NGHTTP2_INTERNAL_ERROR);
    return 0;
  }

  return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code _U_,
                                    void *user_data _U_) {
  stream *strm;

  strm = nghttp2_session_get_stream_user_data(session, stream_id);

  if (!strm) {
    return 0;
  }

  stream_del(strm);

  return 0;
}

static int on_frame_not_send_callback(nghttp2_session *session _U_,
                                      const nghttp2_frame *frame,
                                      int lib_error_code _U_, void *user_data) {
  connection *conn = user_data;

  if (frame->hd.type != NGHTTP2_HEADERS) {
    return 0;
  }

  /* Issue RST_STREAM so that stream does not hang around. */
  nghttp2_submit_rst_stream(conn->session, NGHTTP2_FLAG_NONE,
                            frame->hd.stream_id, NGHTTP2_INTERNAL_ERROR);

  return 0;
}

static int do_read(connection *conn) {
  uint8_t buf[32768];

  for (;;) {
    ssize_t nread;
    ssize_t nproc;

    while ((nread = read(conn->fd, buf, sizeof(buf))) == -1 && errno == EINTR)
      ;
    if (nread == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return 0;
      }

      return -1;
    }

    if (nread == 0) {
      return -1;
    }

    nproc = nghttp2_session_mem_recv(conn->session, buf, nread);

    if (nproc < 0) {
      return -1;
    }
  }
}

static int do_write(connection *conn) {
  for (;;) {
    if (io_buf_len(&conn->buf)) {
      ssize_t nwrite;
      while ((nwrite = write(conn->fd, conn->buf.pos,
                             io_buf_len(&conn->buf))) == -1 &&
             errno == EINTR)
        ;
      if (nwrite == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          return 0;
        }
        return -1;
      }

      conn->buf.pos += nwrite;

      if (io_buf_len(&conn->buf)) {
        return 0;
      }

      io_buf_init(&conn->buf, conn->rawoutbuf, sizeof(conn->rawoutbuf));
    }

    if (conn->cache) {
      io_buf_add(&conn->buf, conn->cache, conn->cachelen);
      conn->cache = NULL;
      conn->cachelen = 0;
    }

    for (;;) {
      ssize_t n;
      const uint8_t *b;

      n = nghttp2_session_mem_send(conn->session, &b);

      if (n < 0) {
        return -1;
      }

      if (n == 0) {
        if (io_buf_len(&conn->buf) == 0) {
          return 0;
        }
        break;
      }

      if (io_buf_left(&conn->buf) < n) {
        conn->cache = b;
        conn->cachelen = n;
        break;
      }

      io_buf_add(&conn->buf, b, n);
    }
  }
}

static int handle_connection(io_loop *loop, uint32_t events, void *ptr) {
  connection *conn = ptr;
  int rv;
  uint32_t nextev = 0;

  if (events & (EPOLLHUP | EPOLLERR)) {
    goto cleanup;
  }

  if (events & EPOLLIN) {
    rv = do_read(conn);

    if (rv != 0) {
      goto cleanup;
    }
  }

  rv = do_write(conn);

  if (rv != 0) {
    goto cleanup;
  }

  if (nghttp2_session_want_read(conn->session)) {
    nextev |= EPOLLIN;
  }

  if (io_buf_len(&conn->buf) || nghttp2_session_want_write(conn->session)) {
    nextev |= EPOLLOUT;
  }

  if (!nextev) {
    goto cleanup;
  }

  io_loop_mod(loop, conn->fd, nextev, conn);

  return 0;

cleanup:
  connection_del(conn);

  return 0;
}

int main(int argc, char **argv) {
  int rv;
  server serv;
  timer tmr;
  io_loop loop;
  struct sigaction act;
  const char *address;
  const char *service;

  if (argc < 4) {
    fprintf(stderr, "Usage: tiny-nghttpd <address> <port> <doc-root>\n");
    exit(EXIT_FAILURE);
  }

  address = argv[1];
  service = argv[2];
  docroot = argv[3];
  docrootlen = strlen(docroot);

  memset(&act, 0, sizeof(act));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);

  rv = server_init(&serv, address, service);

  if (rv != 0) {
    exit(EXIT_FAILURE);
  }

  rv = timer_init(&tmr);

  if (rv != 0) {
    exit(EXIT_FAILURE);
  }

  rv = io_loop_init(&loop);

  if (rv != 0) {
    exit(EXIT_FAILURE);
  }

  rv = nghttp2_session_callbacks_new(&shared_callbacks);
  if (rv != 0) {
    fprintf(stderr, "nghttp2_session_callbacks_new: %s", nghttp2_strerror(rv));
    exit(EXIT_FAILURE);
  }

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      shared_callbacks, on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_header_callback(shared_callbacks,
                                                   on_header_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(shared_callbacks,
                                                       on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(
      shared_callbacks, on_stream_close_callback);
  nghttp2_session_callbacks_set_on_frame_not_send_callback(
      shared_callbacks, on_frame_not_send_callback);

  rv = nghttp2_option_new(&shared_option);
  if (rv != 0) {
    fprintf(stderr, "nghttp2_option_new: %s", nghttp2_strerror(rv));
    exit(EXIT_FAILURE);
  }

  nghttp2_option_set_recv_client_preface(shared_option, 1);

  rv = io_loop_add(&loop, serv.fd, EPOLLIN, &serv);

  if (rv != 0) {
    exit(EXIT_FAILURE);
  }

  rv = io_loop_add(&loop, tmr.fd, EPOLLIN, &tmr);

  if (rv != 0) {
    exit(EXIT_FAILURE);
  }

  update_date();

  io_loop_run(&loop, &serv);

  nghttp2_option_del(shared_option);
  nghttp2_session_callbacks_del(shared_callbacks);

  return 0;
}
