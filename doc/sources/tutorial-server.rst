Tutorial: HTTP/2 server
=========================

In this tutorial, we are going to write single-threaded, event-based
HTTP/2 web server, which supports HTTPS only. It can handle
concurrent multiple requests, but only the GET method is supported. The
complete source code, `libevent-server.c`_, is attached at the end of
this page.  It also resides in examples directory in the archive or
repository.

This simple server takes 3 arguments, a port number to listen to, a path to
your SSL/TLS private key file and a path to your certificate file.  Its
synopsis is like this::

    $ libevent-server PORT /path/to/server.key /path/to/server.crt

We use libevent in this tutorial to handle networking I/O.  Please
note that nghttp2 itself does not depend on libevent.

First we create a setup routine for libevent and OpenSSL in the functions
``main()`` and ``run()``. One thing in there you should look at, is the setup
of the NPN callback.  The NPN callback is used for the server to advertise
which application protocols the server supports to a client.  In this example
program, when creating ``SSL_CTX`` object, we store the application protocol
name in the wire format of NPN in a statically allocated buffer. This is safe
because we only create one ``SSL_CTX`` object in the program's entire life
time::

    static unsigned char next_proto_list[256];
    static size_t next_proto_list_len;

    static int next_proto_cb(SSL *s, const unsigned char **data, unsigned int *len,
                             void *arg)
    {
      *data = next_proto_list;
      *len = (unsigned int)next_proto_list_len;
      return SSL_TLSEXT_ERR_OK;
    }

    static SSL_CTX* create_ssl_ctx(const char *key_file, const char *cert_file)
    {
      SSL_CTX *ssl_ctx;
      ssl_ctx = SSL_CTX_new(SSLv23_server_method());

      ...

      next_proto_list[0] = NGHTTP2_PROTO_VERSION_ID_LEN;
      memcpy(&next_proto_list[1], NGHTTP2_PROTO_VERSION_ID,
             NGHTTP2_PROTO_VERSION_ID_LEN);
      next_proto_list_len = 1 + NGHTTP2_PROTO_VERSION_ID_LEN;

      SSL_CTX_set_next_protos_advertised_cb(ssl_ctx, next_proto_cb, NULL);
      return ssl_ctx;
    }

The wire format of NPN is a sequence of length prefixed string. Exactly one
byte is used to specify the length of each protocol identifier.  In this
tutorial, we advertise the specific HTTP/2 protocol version the current
nghttp2 library supports. The nghttp2 library exports its identifier in
:macro:`NGHTTP2_PROTO_VERSION_ID`. The ``next_proto_cb()`` function is the
server-side NPN callback. In the OpenSSL implementation, we just assign the
pointer to the NPN buffers we filled in earlier. The NPN callback function is
set to the ``SSL_CTX`` object using
``SSL_CTX_set_next_protos_advertised_cb()``.

We use the ``app_content`` structure to store application-wide data::

    struct app_context {
      SSL_CTX *ssl_ctx;
      struct event_base *evbase;
    };

We use the ``http2_session_data`` structure to store session-level
(which corresponds to one HTTP/2 connection) data::

    typedef struct http2_session_data {
      struct http2_stream_data root;
      struct bufferevent *bev;
      app_context *app_ctx;
      nghttp2_session *session;
      char *client_addr;
      size_t handshake_leftlen;
    } http2_session_data;

We use the ``http2_stream_data`` structure to store stream-level data::

    typedef struct http2_stream_data {
      struct http2_stream_data *prev, *next;
      char *request_path;
      int32_t stream_id;
      int fd;
    } http2_stream_data;

A single HTTP/2 session can have multiple streams.  We manage these multiple
streams with a doubly linked list. The first element of this list is pointed
to by the ``root->next`` in ``http2_session_data``.  Initially, ``root->next``
is ``NULL``.  The ``handshake_leftlen`` member of ``http2_session_data`` is
used to track the number of bytes remaining when receiving the first client
connection preface (:macro:`NGHTTP2_CLIENT_CONNECTION_PREFACE`), which is a 24
bytes long magic string from the client.  We use libevent's bufferevent
structure to perform network I/O. Note that the bufferevent object is kept in
``http2_session_data`` and not in ``http2_stream_data``. This is because
``http2_stream_data`` is just a logical stream multiplexed over the single
connection managed by bufferevent in ``http2_session_data``.

We first create a listener object to accept incoming connections.  We use
libevent's ``struct evconnlistener`` for this purpose::

    static void start_listen(struct event_base *evbase, const char *service,
                             app_context *app_ctx)
    {
      int rv;
      struct addrinfo hints;
      struct addrinfo *res, *rp;

      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_PASSIVE;
    #ifdef AI_ADDRCONFIG
      hints.ai_flags |= AI_ADDRCONFIG;
    #endif // AI_ADDRCONFIG

      rv = getaddrinfo(NULL, service, &hints, &res);
      if(rv != 0) {
        errx(1, NULL);
      }
      for(rp = res; rp; rp = rp->ai_next) {
        struct evconnlistener *listener;
        listener = evconnlistener_new_bind(evbase, acceptcb, app_ctx,
                                           LEV_OPT_CLOSE_ON_FREE |
                                           LEV_OPT_REUSEABLE, -1,
                                           rp->ai_addr, rp->ai_addrlen);
        if(listener) {
          return;
        }
      }
      errx(1, "Could not start listener");
    }

We specify the ``acceptcb`` callback which is called when a new connection is
accepted::

    static void acceptcb(struct evconnlistener *listener, int fd,
                         struct sockaddr *addr, int addrlen, void *arg)
    {
      app_context *app_ctx = (app_context*)arg;
      http2_session_data *session_data;

      session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);
      bufferevent_setcb(session_data->bev, handshake_readcb, NULL, eventcb,
                        session_data);
    }

Here we create the ``http2_session_data`` object. The bufferevent for this
connection is also initialized at this time. We specify two callbacks for the
bufferevent: ``handshake_readcb`` and ``eventcb``.

The ``eventcb()`` callback is invoked by the libevent event loop when an event
(e.g., connection has been established, timeout, etc) happens on the
underlying network socket::

    static void eventcb(struct bufferevent *bev, short events, void *ptr)
    {
      http2_session_data *session_data = (http2_session_data*)ptr;
      if(events & BEV_EVENT_CONNECTED) {
        fprintf(stderr, "%s connected\n", session_data->client_addr);
        return;
      }
      if(events & BEV_EVENT_EOF) {
        fprintf(stderr, "%s EOF\n", session_data->client_addr);
      } else if(events & BEV_EVENT_ERROR) {
        fprintf(stderr, "%s network error\n", session_data->client_addr);
      } else if(events & BEV_EVENT_TIMEOUT) {
        fprintf(stderr, "%s timeout\n", session_data->client_addr);
      }
      delete_http2_session_data(session_data);
    }

For the ``BEV_EVENT_EOF``, ``BEV_EVENT_ERROR`` and ``BEV_EVENT_TIMEOUT``
events, we just simply tear down the connection. The
``delete_http2_session_data()`` function destroys the ``http2_session_data``
object and thus also its bufferevent member. As a result, the underlying
connection is closed.  The ``BEV_EVENT_CONNECTED`` event is invoked when
SSL/TLS handshake is finished successfully.

``handshake_readcb()`` is a callback function to handle a 24 bytes magic byte
string coming from a client, since the nghttp2 library does not handle it::

    static void handshake_readcb(struct bufferevent *bev, void *ptr)
    {
      http2_session_data *session_data = (http2_session_data*)ptr;
      uint8_t data[24];
      struct evbuffer *input = bufferevent_get_input(session_data->bev);
      int readlen = evbuffer_remove(input, data, session_data->handshake_leftlen);
      const char *conhead = NGHTTP2_CLIENT_CONNECTION_PREFACE;

      if(memcmp(conhead + NGHTTP2_CLIENT_CONNECTION_PREFACE_LEN
                - session_data->handshake_leftlen, data, readlen) != 0) {
        delete_http2_session_data(session_data);
        return;
      }
      session_data->handshake_leftlen -= readlen;
      if(session_data->handshake_leftlen == 0) {
        bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, ptr);
        /* Process pending data in buffer since they are not notified
           further */
        initialize_nghttp2_session(session_data);
        if(send_server_connection_header(session_data) != 0) {
          delete_http2_session_data(session_data);
          return;
        }
        if(session_recv(session_data) != 0) {
          delete_http2_session_data(session_data);
          return;
        }
      }
    }

We check that the received byte string matches
:macro:`NGHTTP2_CLIENT_CONNECTION_PREFACE`.  When they match, the connection
state is ready to start the HTTP/2 communication. First we change the callback
functions for the bufferevent object. We use the same ``eventcb`` callback as
before, but we specify new ``readcb`` and ``writecb`` functions to handle the
HTTP/2 communication. These two functions are described later.

We initialize a nghttp2 session object which is done in
``initialize_nghttp2_session()``::

    static void initialize_nghttp2_session(http2_session_data *session_data)
    {
      nghttp2_session_callbacks *callbacks;

      nghttp2_session_callbacks_new(&callbacks);

      nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

      nghttp2_session_callbacks_set_on_frame_recv_callback
        (callbacks, on_frame_recv_callback);

      nghttp2_session_callbacks_set_on_stream_close_callback
        (callbacks, on_stream_close_callback);

      nghttp2_session_callbacks_set_on_header_callback
        (callbacks, on_header_callback);

      nghttp2_session_callbacks_set_on_begin_headers_callback
        (callbacks, on_begin_headers_callback);

      nghttp2_session_server_new(&session_data->session, callbacks, session_data);

      nghttp2_session_callbacks_del(callbacks);
    }

Since we are creating a server, the nghttp2 session object is created using
`nghttp2_session_server_new()` function. We registers five callbacks for
nghttp2 session object. We'll talk about these callbacks later.

After initialization of the nghttp2 session object, we are going to send
a server connection header in ``send_server_connection_header()``::

    static int send_server_connection_header(http2_session_data *session_data)
    {
      nghttp2_settings_entry iv[1] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
      };
      int rv;

      rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE,
                                   iv, ARRLEN(iv));
      if(rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
      }
      return 0;
    }

The server connection header is a SETTINGS frame. We specify
SETTINGS_MAX_CONCURRENT_STREAMS to 100 in the SETTINGS frame.  To queue
the SETTINGS frame for the transmission, we use
`nghttp2_submit_settings()`. Note that `nghttp2_submit_settings()`
function only queues the frame and it does not actually send it. All
functions in the ``nghttp2_submit_*()`` family have this property. To
actually send the frame, `nghttp2_session_send()` should be used, as
described later.

Since bufferevent may buffer more than the first 24 bytes from the client, we
have to process them here since libevent won't invoke callback functions for
this pending data. To process the received data, we call the
``session_recv()`` function::

    static int session_recv(http2_session_data *session_data)
    {
      ssize_t readlen;
      struct evbuffer *input = bufferevent_get_input(session_data->bev);
      size_t datalen = evbuffer_get_length(input);
      unsigned char *data = evbuffer_pullup(input, -1);

      readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
      if(readlen < 0) {
        warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
        return -1;
      }
      if(evbuffer_drain(input, readlen) != 0) {
        warnx("Fatal error: evbuffer_drain failed");
        return -1;
      }
      if(session_send(session_data) != 0) {
        return -1;
      }
      return 0;
    }

In this function, we feed all unprocessed but already received data to the
nghttp2 session object using the `nghttp2_session_mem_recv()` function. The
`nghttp2_session_mem_recv()` function processes the data and may invoke the
nghttp2 callbacks and also queue outgoing frames. Since there may be pending
outgoing frames, we call ``session_send()`` function to send off those
frames. The ``session_send()`` function is defined as follows::

    static int session_send(http2_session_data *session_data)
    {
      int rv;
      rv = nghttp2_session_send(session_data->session);
      if(rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
      }
      return 0;
    }

The `nghttp2_session_send()` function serializes the frame into wire
format and calls ``send_callback()`` of type
:type:`nghttp2_send_callback`.  The ``send_callback()`` is defined as
follows::

    static ssize_t send_callback(nghttp2_session *session,
                                 const uint8_t *data, size_t length,
                                 int flags, void *user_data)
    {
      http2_session_data *session_data = (http2_session_data*)user_data;
      struct bufferevent *bev = session_data->bev;
      /* Avoid excessive buffering in server side. */
      if(evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
         OUTPUT_WOULDBLOCK_THRESHOLD) {
        return NGHTTP2_ERR_WOULDBLOCK;
      }
      bufferevent_write(bev, data, length);
      return length;
    }

Since we use bufferevent to abstract network I/O, we just write the
data to the bufferevent object. Note that `nghttp2_session_send()`
continues to write all frames queued so far. If we were writing the
data to a non-blocking socket directly using ``write()`` system call
in the ``send_callback()``, we would surely get ``EAGAIN`` or
``EWOULDBLOCK`` back since the socket has limited send buffer. If that
happens, we can return :macro:`NGHTTP2_ERR_WOULDBLOCK` to signal the
nghttp2 library to stop sending further data. But when writing to the
bufferevent, we have to regulate the amount data to get buffered
ourselves to avoid using huge amounts of memory. To achieve this, we
check the size of the output buffer and if it reaches more than or
equal to ``OUTPUT_WOULDBLOCK_THRESHOLD`` bytes, we stop writing data
and return :macro:`NGHTTP2_ERR_WOULDBLOCK` to tell the library to stop
calling send_callback.

The next bufferevent callback is ``readcb()``, which is invoked when
data is available to read in the bufferevent input buffer::

    static void readcb(struct bufferevent *bev, void *ptr)
    {
      http2_session_data *session_data = (http2_session_data*)ptr;
      if(session_recv(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
      }
    }

In this function, we just call ``session_recv()`` to process incoming
data.

The third bufferevent callback is ``writecb()``, which is invoked when all
data in the bufferevent output buffer has been sent::

    static void writecb(struct bufferevent *bev, void *ptr)
    {
      http2_session_data *session_data = (http2_session_data*)ptr;
      if(evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
        return;
      }
      if(nghttp2_session_want_read(session_data->session) == 0 &&
         nghttp2_session_want_write(session_data->session) == 0) {
        delete_http2_session_data(session_data);
        return;
      }
      if(session_send(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
      }
    }

First we check whether we should drop the connection or not. The nghttp2
session object keeps track of reception and transmission of GOAWAY frames and
other error conditions as well. Using this information, the nghttp2 session
object will tell whether the connection should be dropped or not. More
specifically, if both `nghttp2_session_want_read()` and
`nghttp2_session_want_write()` return 0, we have no business left in the
connection. But since we are using bufferevent and its deferred callback
option, the bufferevent output buffer may contain pending data when the
``writecb()`` is called. To handle this, we check whether the output buffer is
empty or not. If all these conditions are met, we drop connection.

Otherwise, we call ``session_send()`` to process the pending output
data. Remember that in ``send_callback()``, we must not write all data to
bufferevent to avoid excessive buffering. We continue processing pending data
when the output buffer becomes empty.

We have already described the nghttp2 callback ``send_callback()``.  Let's
learn about the remaining nghttp2 callbacks we setup in
``initialize_nghttp2_setup()`` function.

The ``on_begin_headers_callback()`` function is invoked when the reception of
a header block in HEADERS or PUSH_PROMISE frame is started::

    static int on_begin_headers_callback(nghttp2_session *session,
                                         const nghttp2_frame *frame,
                                         void *user_data)
    {
      http2_session_data *session_data = (http2_session_data*)user_data;
      http2_stream_data *stream_data;

      if(frame->hd.type != NGHTTP2_HEADERS ||
         frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
      }
      stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
      nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                           stream_data);
      return 0;
    }

We are only interested in the HEADERS frame in this function. Since the
HEADERS frame has several roles in the HTTP/2 protocol, we check that it is a
request HEADERS, which opens new stream. If the frame is a request HEADERS, we
create a ``http2_stream_data`` object to store the stream related data. We
associate the created ``http2_stream_data`` object with the stream in the
nghttp2 session object using `nghttp2_set_stream_user_data()` to get the
object without searching through the doubly linked list.

In this example server, we want to serve files relative to the current working
directory in which the program was invoked. Each header name/value pair is
emitted via ``on_header_callback`` function, which is called after
``on_begin_headers_callback()``::

    static int on_header_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame,
                                  const uint8_t *name, size_t namelen,
                                  const uint8_t *value, size_t valuelen,
                                  void *user_data)
    {
      http2_stream_data *stream_data;
      const char PATH[] = ":path";
      switch(frame->hd.type) {
      case NGHTTP2_HEADERS:
        if(frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
          break;
        }
        stream_data = nghttp2_session_get_stream_user_data(session,
                                                           frame->hd.stream_id);
        if(!stream_data || stream_data->request_path) {
          break;
        }
        if(namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
          size_t j;
          for(j = 0; j < valuelen && value[j] != '?'; ++j);
          stream_data->request_path = percent_decode(value, j);
        }
        break;
      }
      return 0;
    }

We search for the ``:path`` header field among the request headers and store
the requested path in the ``http2_stream_data`` object. In this example
program, we ignore ``:method`` header field and always treat the request as a
GET request.

The ``on_frame_recv_callback()`` function is invoked when a frame is
fully received::

    static int on_frame_recv_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame, void *user_data)
    {
      http2_session_data *session_data = (http2_session_data*)user_data;
      http2_stream_data *stream_data;
      switch(frame->hd.type) {
      case NGHTTP2_DATA:
      case NGHTTP2_HEADERS:
        /* Check that the client request has finished */
        if(frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
          stream_data = nghttp2_session_get_stream_user_data(session,
                                                             frame->hd.stream_id);
          /* For DATA and HEADERS frame, this callback may be called after
             on_stream_close_callback. Check that stream still alive. */
          if(!stream_data) {
            return 0;
          }
          return on_request_recv(session, session_data, stream_data);
        }
        break;
      default:
        break;
      }
      return 0;
    }

First we retrieve the ``http2_stream_data`` object associated with the stream
in ``on_begin_headers_callback()``. It is done using
`nghttp2_session_get_stream_user_data()`. If the requested path cannot be
served for some reason (e.g., file is not found), we send a 404 response,
which is done in ``error_reply()``.  Otherwise, we open the requested file and
send its content. We send the header field ``:status`` as a single response
header.

Sending the content of the file is done in ``send_response()`` function::

    static int send_response(nghttp2_session *session, int32_t stream_id,
                             nghttp2_nv *nva, size_t nvlen, int fd)
    {
      int rv;
      nghttp2_data_provider data_prd;
      data_prd.source.fd = fd;
      data_prd.read_callback = file_read_callback;

      rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
      if(rv != 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        return -1;
      }
      return 0;
    }

The nghttp2 library uses the :type:`nghttp2_data_provider` structure to
send entity body to the remote peer. The ``source`` member of this
structure is a union and it can be either void pointer or int which is
intended to be used as file descriptor. In this example server, we use
the file descriptor. We also set the ``file_read_callback()`` callback
function to read the contents of the file::

    static ssize_t file_read_callback
    (nghttp2_session *session, int32_t stream_id,
     uint8_t *buf, size_t length, uint32_t *data_flags,
     nghttp2_data_source *source, void *user_data)
    {
      int fd = source->fd;
      ssize_t r;
      while((r = read(fd, buf, length)) == -1 && errno == EINTR);
      if(r == -1) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
      if(r == 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      }
      return r;
    }

If an error happens while reading the file, we return
:macro:`NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE`.  This tells the
library to send RST_STREAM to the stream.  When all data has been read, set
the :macro:`NGHTTP2_DATA_FLAG_EOF` flag to ``*data_flags`` to tell the
nghttp2 library that we have finished reading the file.

The `nghttp2_submit_response()` function is used to send the response to the
remote peer.

The ``on_stream_close_callback()`` function is invoked when the stream
is about to close::

    static int on_stream_close_callback(nghttp2_session *session,
                                        int32_t stream_id,
                                        nghttp2_error_code error_code,
                                        void *user_data)
    {
      http2_session_data *session_data = (http2_session_data*)user_data;
      http2_stream_data *stream_data;

      stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
      if(!stream_data) {
        return 0;
      }
      remove_stream(session_data, stream_data);
      delete_http2_stream_data(stream_data);
      return 0;
    }

We destroy the ``http2_stream_data`` object in this function since the stream
is about to close and we no longer use that object.
