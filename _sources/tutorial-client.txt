Tutorial: HTTP/2.0 client
=========================

In this tutorial, we are going to write very primitive HTTP/2.0
client. The complete source code, `libevent-client.c`_, is attached at
the end of this page.  It also resides in examples directory in the
archive or repository.

This simple client takes 1 argument, HTTPS URI, and retrieves the
resource denoted by the URI. Its synopsis is like this::

    $ libevent-client HTTPS_URI

We use libevent in this tutorial to handle networking I/O.  Please
note that nghttp2 itself does not depend on libevent.

First we do some setup routine for libevent and OpenSSL library in
function ``main()`` and ``run()``, which is not so relevant to nghttp2
library use. The one thing you should look at is setup NPN callback.
The NPN callback is used for the client to select the next application
protocol over the SSL/TLS transport. In this tutorial, we use
`nghttp2_select_next_protocol()` function to select the HTTP/2.0
protocol the library supports::

    static int select_next_proto_cb(SSL* ssl,
                                    unsigned char **out, unsigned char *outlen,
                                    const unsigned char *in, unsigned int inlen,
                                    void *arg)
    {
      if(nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
        errx(1, "Server did not advertise " NGHTTP2_PROTO_VERSION_ID);
      }
      return SSL_TLSEXT_ERR_OK;
    }

The callback is set to the SSL_CTX object using
``SSL_CTX_set_next_proto_select_cb()`` function::

    static SSL_CTX* create_ssl_ctx(void)
    {
      SSL_CTX *ssl_ctx;
      ssl_ctx = SSL_CTX_new(SSLv23_client_method());
      if(!ssl_ctx) {
        errx(1, "Could not create SSL/TLS context: %s",
             ERR_error_string(ERR_get_error(), NULL));
      }
      SSL_CTX_set_options(ssl_ctx,
                          SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION |
                          SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
      SSL_CTX_set_next_proto_select_cb(ssl_ctx, select_next_proto_cb, NULL);
      return ssl_ctx;
    }

We use ``http2_session_data`` structure to store the data related to
the HTTP/2.0 session::

    typedef struct {
      nghttp2_session *session;
      struct evdns_base *dnsbase;
      struct bufferevent *bev;
      http2_stream_data *stream_data;
    } http2_session_data;

Since this program only handles 1 URI, it uses only 1 stream. We store
its stream specific data in ``http2_stream_data`` structure and the
``stream_data`` points to it. The ``struct http2_stream_data`` is
defined as follows::

    typedef struct {
      /* The NULL-terminated URI string to retreive. */
      const char *uri;
      /* Parsed result of the |uri| */
      struct http_parser_url *u;
      /* The authroity portion of the |uri|, not NULL-terminated */
      char *authority;
      /* The path portion of the |uri|, including query, not
         NULL-terminated */
      char *path;
      /* The length of the |authority| */
      size_t authoritylen;
      /* The length of the |path| */
      size_t pathlen;
      /* The stream ID of this stream */
      int32_t stream_id;
    } http2_stream_data;

We creates and initializes these structures in
``create_http2_session_data()`` and ``create_http2_stream_data()``
respectively.

Then we call function ``initiate_connection()`` to start connecting to
the remote server::

    static void initiate_connection(struct event_base *evbase,
                                    SSL_CTX *ssl_ctx,
                                    const char *host, uint16_t port,
                                    http2_session_data *session_data)
    {
      int rv;
      struct bufferevent *bev;
      SSL *ssl;

      ssl = create_ssl(ssl_ctx);
      bev = bufferevent_openssl_socket_new(evbase, -1, ssl,
                                           BUFFEREVENT_SSL_CONNECTING,
                                           BEV_OPT_DEFER_CALLBACKS |
                                           BEV_OPT_CLOSE_ON_FREE);
      bufferevent_setcb(bev, readcb, writecb, eventcb, session_data);
      rv = bufferevent_socket_connect_hostname(bev, session_data->dnsbase,
                                               AF_UNSPEC, host, port);

      if(rv != 0) {
        errx(1, "Could not connect to the remote host %s", host);
      }
      session_data->bev = bev;
    }

We set 3 callbacks for the bufferevent: ``reacb``, ``writecb`` and
``eventcb``.

The ``eventcb()`` is invoked by libevent event loop when an event
(e.g., connection has been established, timeout, etc) happens on the
underlying network socket::

    static void eventcb(struct bufferevent *bev, short events, void *ptr)
    {
      http2_session_data *session_data = (http2_session_data*)ptr;
      if(events & BEV_EVENT_CONNECTED) {
        int fd = bufferevent_getfd(bev);
        int val = 1;
        fprintf(stderr, "Connected\n");
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
        initialize_nghttp2_session(session_data);
        send_client_connection_header(session_data);
        submit_request(session_data);
        if(session_send(session_data) != 0) {
          delete_http2_session_data(session_data);
        }
        return;
      }
      if(events & BEV_EVENT_EOF) {
        warnx("Disconnected from the remote host");
      } else if(events & BEV_EVENT_ERROR) {
        warnx("Network error");
      } else if(events & BEV_EVENT_TIMEOUT) {
        warnx("Timeout");
      }
      delete_http2_session_data(session_data);
    }

For ``BEV_EVENT_EOF``, ``BEV_EVENT_ERROR`` and ``BEV_EVENT_TIMEOUT``
event, we just simply tear down the connection. The
``BEV_EVENT_CONNECTED`` event is invoked when SSL/TLS handshake is
finished successfully. We first initialize nghttp2 session object in
``initialize_nghttp2_session()`` function::

    static void initialize_nghttp2_session(http2_session_data *session_data)
    {
      nghttp2_session_callbacks callbacks = {0};

      callbacks.send_callback = send_callback;
      callbacks.before_frame_send_callback = before_frame_send_callback;
      callbacks.on_frame_recv_callback = on_frame_recv_callback;
      callbacks.on_data_chunk_recv_callback = on_data_chunk_recv_callback;
      callbacks.on_stream_close_callback = on_stream_close_callback;
      nghttp2_session_client_new(&session_data->session, &callbacks, session_data);
    }

Since we are creating client, we use `nghttp2_session_client_new()` to
initialize nghttp2 session object.  We setup 5 callbacks for the
nghttp2 session. We'll explain these callbacks later.

The `delete_http2_session_data()` destroys ``session_data`` and frees
its bufferevent, so it closes underlying connection as well. It also
calls `nghttp2_session_del()` to delete nghttp2 session object.

We begin HTTP/2.0 communication by sending client connection header,
which is 24 bytes magic byte sequence
(:macro:`NGHTTP2_CLIENT_CONNECTION_HEADER`) followed by SETTINGS
frame.  The transmission of client connection header is done in
``send_client_connection_header()``::

    static void send_client_connection_header(http2_session_data *session_data)
    {
      nghttp2_settings_entry iv[1] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100 }
      };
      int rv;

      bufferevent_write(session_data->bev,
                        NGHTTP2_CLIENT_CONNECTION_HEADER,
                        NGHTTP2_CLIENT_CONNECTION_HEADER_LEN);
      rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE,
                                   iv, ARRLEN(iv));
      if(rv != 0) {
        errx(1, "Could not submit SETTINGS: %s", nghttp2_strerror(rv));
      }
    }

Here we specify SETTINGS_MAX_CONCURRENT_STREAMS to 100, which is
really not needed for this tiny example progoram, but we are
demonstrating the use of SETTINGS frame. To queue the SETTINGS frame
for the transmission, we use `nghttp2_submit_settings()`. Note that
`nghttp2_submit_settings()` function only queues the frame and not
actually send it. All ``nghttp2_submit_*()`` family functions have
this property. To actually send the frame, `nghttp2_session_send()` is
used, which is described about later.

After the transmission of client connection header, we enqueue HTTP
request in ``submit_request()`` function::

    static void submit_request(http2_session_data *session_data)
    {
      int rv;
      http2_stream_data *stream_data = session_data->stream_data;
      const char *uri = stream_data->uri;
      const struct http_parser_url *u = stream_data->u;
      nghttp2_nv hdrs[] = {
        MAKE_NV2(":method", "GET"),
        MAKE_NV(":scheme",
                &uri[u->field_data[UF_SCHEMA].off], u->field_data[UF_SCHEMA].len),
        MAKE_NV(":authority", stream_data->authority, stream_data->authoritylen),
        MAKE_NV(":path", stream_data->path, stream_data->pathlen)
      };
      fprintf(stderr, "Request headers:\n");
      print_headers(stderr, hdrs, ARRLEN(hdrs));
      rv = nghttp2_submit_request(session_data->session, NGHTTP2_PRI_DEFAULT,
                                  hdrs, ARRLEN(hdrs), NULL, stream_data);
      if(rv != 0) {
        errx(1, "Could not submit HTTP request: %s", nghttp2_strerror(rv));
      }
    }

We build HTTP request header fields in ``hdrs`` which is an array of
:type:`nghttp2_nv`. There are 4 header fields to be sent: ``:method``,
``:scheme``, ``:authority`` and ``:path``. To queue this HTTP request,
we use `nghttp2_submit_request()` function. The `stream_data` is
passed in *stream_user_data* parameter. It is used in nghttp2
callbacks which we'll describe about later.

The next bufferevent callback is ``readcb()``, which is invoked when
data is available to read in the bufferevent input buffer::

    static void readcb(struct bufferevent *bev, void *ptr)
    {
      http2_session_data *session_data = (http2_session_data*)ptr;
      int rv;
      struct evbuffer *input = bufferevent_get_input(bev);
      size_t datalen = evbuffer_get_length(input);
      unsigned char *data = evbuffer_pullup(input, -1);
      rv = nghttp2_session_mem_recv(session_data->session, data, datalen);
      if(rv < 0) {
        warnx("Fatal error: %s", nghttp2_strerror(rv));
        delete_http2_session_data(session_data);
        return;
      }
      evbuffer_drain(input, rv);
      if(session_send(session_data) != 0) {
        delete_http2_session_data(session_data);
        return;
      }
    }

In this function, we feed all unprocessed, received data to nghttp2
session object using `nghttp2_session_mem_recv()` function. The
`nghttp2_session_mem_recv()` processes the received data and may
invoke nghttp2 callbacks and also queue frames. Since there may be
pending frames, we call ``session_send()`` function to send those
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
format and call :member:`nghttp2_session_callbacks.send_callback` with
it. We set ``send_callback()`` function to
:member:`nghttp2_session_callbacks.send_callback` in
``initialize_nghttp2_session()`` function described earlier. It is
defined as follows::

    static ssize_t send_callback(nghttp2_session *session,
                                 const uint8_t *data, size_t length,
                                 int flags, void *user_data)
    {
      http2_session_data *session_data = (http2_session_data*)user_data;
      struct bufferevent *bev = session_data->bev;
      bufferevent_write(bev, data, length);
      return length;
    }

Since we use bufferevent to abstract network I/O, we just write the
data to the bufferevent object. Note that `nghttp2_session_send()`
continues to write all frames queued so far. If we were writing the
data to the non-blocking socket directly using ``write()`` system call
in the :member:`nghttp2_session_callbacks.send_callback`, we will
surely get ``EAGAIN`` or ``EWOULDBLOCK`` since the socket has limited
send buffer. If that happens, we can return
:macro:`NGHTTP2_ERR_WOULDBLOCK` to signal the nghttp2 library to stop
sending further data. But writing to the bufferevent, we have to
regulate the amount data to be buffered by ourselves to avoid possible
huge memory consumption. In this example client, we do not limit
anything. To see how to regulate the amount of buffered data, see the
``send_callback()`` in the server tutorial.

The third bufferevent callback is ``writecb()``, which is invoked when
all data written in the bufferevent output buffer have been sent::

    static void writecb(struct bufferevent *bev, void *ptr)
    {
      http2_session_data *session_data = (http2_session_data*)ptr;
      if(nghttp2_session_want_read(session_data->session) == 0 &&
         nghttp2_session_want_write(session_data->session) == 0 &&
         evbuffer_get_length(bufferevent_get_output(session_data->bev)) == 0) {
        delete_http2_session_data(session_data);
      }
    }

As described earlier, we just write off all data in `send_callback()`,
we have no data to write in this function. All we have to do is check
we have to drop connection or not. The nghttp2 session object keeps
track of reception and transmission of GOAWAY frame and other error
conditions as well. Using these information, nghttp2 session object
will tell whether the connection should be dropped or not. More
specifically, both `nghttp2_session_want_read()` and
`nghttp2_session_want_write()` return 0, we have no business in the
connection. But since we are using bufferevent and its deferred
callback option, the bufferevent output buffer may contain the pending
data when the ``writecb()`` is called. To handle this situation, we
also check whether the output buffer is empty or not. If these
conditions are met, we drop connection.

We have already described about nghttp2 callback ``send_callback()``.
Let's describe remaining nghttp2 callbacks we setup in
``initialize_nghttp2_setup()`` function.

The `before_frame_send_callback()` function is invoked when a frame is
about to be sent::

    static int before_frame_send_callback
    (nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
    {
      http2_session_data *session_data = (http2_session_data*)user_data;
      http2_stream_data *stream_data;

      if(frame->hd.type == NGHTTP2_HEADERS &&
         frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        stream_data =
          (http2_stream_data*)nghttp2_session_get_stream_user_data
          (session, frame->hd.stream_id);
        if(stream_data == session_data->stream_data) {
          stream_data->stream_id = frame->hd.stream_id;
        }
      }
      return 0;
    }

Remember that we have not get stream ID when we submit HTTP request
using `nghttp2_submit_request()`. Since nghttp2 library reorders the
request based on priority and stream ID must be monotonically
increased, the stream ID is not assigned just before transmission.
The one of the purpose of this callback is get the stream ID assigned
to the frame. First we check that the frame is HEADERS frame. Since
HEADERS has several meanings in HTTP/2.0, we check that it is request
HEADERS (which means that the first HEADERS frame to create a stream).
The assigned stream ID is ``frame->hd.stream_id``.  Recall that we
passed ``stream_data`` in the *stream_user_data* parameter of
`nghttp2_submit_request()` function. We can get it using
`nghttp2_session_get_stream_user_data()` function. To really sure that
this HEADERS frame is the request HEADERS we have queued, we check
that ``session_data->stream_data`` and ``stream_data`` returned from
`nghttp2_session_get_stream_user_data()` are pointing the same
location. In this example program, we just only uses 1 stream, it is
unnecessary to compare them, but real applications surely deal with
multiple streams, and *stream_user_data* is very handy to identify
which HEADERS we are seeing in the callback. Therefore we just show
how to use it here.

The ``on_frame_recv_callback()`` function is invoked when a frame is
received from the remote peer::

    static int on_frame_recv_callback(nghttp2_session *session,
                                      const nghttp2_frame *frame, void *user_data)
    {
      http2_session_data *session_data = (http2_session_data*)user_data;
      switch(frame->hd.type) {
      case NGHTTP2_HEADERS:
        if(frame->headers.cat == NGHTTP2_HCAT_RESPONSE &&
           session_data->stream_data->stream_id == frame->hd.stream_id) {
          /* Print response headers for the initiated request. */
          fprintf(stderr, "Response headers:\n");
          print_headers(stderr, frame->headers.nva, frame->headers.nvlen);
        }
        break;
      }
      return 0;
    }

In this tutorial, we are just interested in the HTTP response
HEADERS. We check te frame type and its category (it should be
:macro:`NGHTTP2_HCAT_RESPONSE` for HTTP response HEADERS). Also check
its stream ID.

The ``on_data_chunk_recv_callback()`` function is invoked when a chunk
of data is received from the remote peer::

    static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                           int32_t stream_id,
                                           const uint8_t *data, size_t len,
                                           void *user_data)
    {
      http2_session_data *session_data = (http2_session_data*)user_data;
      if(session_data->stream_data->stream_id == stream_id) {
        fwrite(data, len, 1, stdout);
      }
      return 0;
    }

In our case, a chunk of data is response body. After checking stream
ID, we just write the recieved data to the stdout. Note that the
output in the terminal may be corrupted if the response body contains
some binary data.

The ``on_stream_close_callback()`` function is invoked when the stream
is about to close::

    static int on_stream_close_callback(nghttp2_session *session,
                                        int32_t stream_id,
                                        nghttp2_error_code error_code,
                                        void *user_data)
    {
      http2_session_data *session_data = (http2_session_data*)user_data;
      int rv;

      if(session_data->stream_data->stream_id == stream_id) {
        fprintf(stderr, "Stream %d closed with error_code=%d\n",
                stream_id, error_code);
        rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
        if(rv != 0) {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
      return 0;
    }

If the stream ID matches the one we initiated, it means that its
stream is going to be closed. Since we have finished to get the
resource we want (or the stream was reset by RST_STREAM from the
remote peer), we call `nghttp2_session_terminate_session()` to
commencing the closure of the HTTP/2.0 session gracefully. If you have
some data associated for the stream to be closed, you may delete it
here.

libevent-client.c
-----------------

.. literalinclude:: ../examples/libevent-client.c
