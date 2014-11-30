libnghttp2_asio: High level HTTP/2 C++ library
==============================================

libnghttp2_asio is C++ library built on top of libnghttp2 and provides
high level abstraction API to build HTTP/2 applications.  It depends
on Boost::ASIO library and OpenSSL.  Currently libnghttp2_asio
provides server side API.

libnghttp2_asio is not built by default.  Use ``--enable-asio-lib``
configure flag to build libnghttp2_asio.  The required Boost libraries
are:

* Boost::Asio
* Boost::System
* Boost::Thread

To use libnghttp2_asio, first include following header file:

.. code-block:: cpp

    #include <nghttp2/asio_http2.h>

Also take a look at that header file :doc:`asio_http2.h`.

Server API
----------

Server API is designed to build HTTP/2 server very easily to utilize
C++11 anonymous function and closure.  The bare minimum example of
HTTP/2 server looks like this:

.. code-block:: cpp

    #include <nghttp2/asio_http2.h>

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::server;

    int main(int argc, char *argv[]) {
      http2 server;

      server.listen("*", 3000, [](const std::shared_ptr<request> &req,
                                  const std::shared_ptr<response> &res) {
        res->write_head(200);
        res->end("hello, world");
      });
    }

First we instantiate ``nghttp2::asio_http2::server::http2`` object.
Then call ``nghttp2::asio_http2::server::http2::listen`` function with
address and port to listen to and callback function, namely "request
callback", invoked when request arrives.

The ``req`` and ``res`` represent HTTP request and response
respectively.  ``nghttp2::asio_http2_::server::response::write_head``
constructs HTTP response header fields.  The first argument is HTTP
status code, in the above example, which is 200.  The second argument,
which is omitted in the above example, is additional header fields to
send.

``nghttp2::asio_http2::server::response::end`` sends responde body.
In the above example, we send string "hello, world".

Serving static files and enabling SSL/TLS
+++++++++++++++++++++++++++++++++++++++++

In this example, we serve a couple of static files and also enable
SSL/TLS.

.. code-block:: cpp

    #include <nghttp2/asio_http2.h>

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::server;

    int main(int argc, char *argv[]) {
      http2 server;

      server.tls("server.key", "server.crt");

      server.listen("*", 3000, [](const std::shared_ptr<request> &req,
                                  const std::shared_ptr<response> &res) {
        if (req->path() == "/" || req->path() == "/index.html") {
          res->write_head(200);
          res->end(file_reader("index.html"));
        } else {
          res->write_head(404);
          res->end("<html><head><title>404</title></head>"
                   "<body>404 Not Found</body></html>");
        }
      });
    }

Specifying path to private key file and certificate file in
``nghttp2::asio_http2::server::http2::tls`` will enable SSL/TLS.  Both
files must be in PEM format.

In the above example, if request path is either "/" or "/index.html",
we serve index.html file in the current working directory.
``nghttp2::asio_http2::server::response::end`` has overload to take
function of type ``nghttp2::asio_http2::read_cb`` and application pass
its implementation to generate response body.  For the convenience,
libnghttp2_asio library provides ``nghttp2::asio_http2::file_reader``
function to generate function to server static file.

Server push
+++++++++++

Server push is also supported.

.. code-block:: cpp

    #include <nghttp2/asio_http2.h>

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::server;

    int main(int argc, char *argv[]) {
      http2 server;

      server.tls("server.key", "server.crt");

      server.listen("*", 3000, [](const std::shared_ptr<request> &req,
                                  const std::shared_ptr<response> &res) {
        if (req->path() == "/") {
          req->push("GET", "/my.css");

          res->write_head(200);
          res->end(file_reader("index.html"));

          return;
        }

        if (req->path() == "/my.css") {
          res->write_head(200);
          res->end(file_reader("my.css"));

          return;
        }

        res->write_head(404);
        res->end("<html><head><title>404</title></head>"
                 "<body>404 Not Found</body></html>");
      });
    }

When client requested "/", we push "/my.css".  To push resource, call
``nghttp2::asio_http2::server::request::push`` function with desired
method and path.  Later, the callback will be called with the pushed
resource "/my.css".

Enable multi-threading
++++++++++++++++++++++

Enabling multi-threading is very easy.  Just call
``nghttp2::asio_http2::server::http2::num_threads`` function with the
desired number of threads:

.. code-block:: cpp

    http2 server;

    // Use 4 native threads
    server.num_threads(4);

Run blocking tasks in background thread
+++++++++++++++++++++++++++++++++++++++

The request callback is called in the same thread where HTTP request
is handled.  And many connections shares the same thread, we cannot
directly run blocking tasks in request callback.

To run blocking tasks, use
``nghttp2::asio_http2::server::request::run_task``.  The passed
callback will be executed in the different thread from the thread
where request callback was executed.  So application can perform
blocking task there.  The example follows:

.. code-block:: cpp

    #include <unistd.h>
    #include <nghttp2/asio_http2.h>

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::server;

    int main(int argc, char *argv[]) {
      http2 server;

      server.num_concurrent_tasks(16);

      server.listen("*", 3000, [](const std::shared_ptr<request> &req,
                                  const std::shared_ptr<response> &res) {
        req->run_task([res](channel &channel) {
          // executed in different thread than the thread where
          // request callback was executed.

          // using res directly here is not safe.  Capturing it by
          // value is safe because it is std::shared_ptr.

          sleep(1);

          channel.post([res]() {
            // executed in the same thread where request callback
            // was executed.
            res->write_head(200);
            res->end("hello, world");
          });
        });
      });
    }

First we set the number of background threads which run tasks.  By
default it is set to 1.  In this example, we set it to 16, so at most
16 tasks can be executed concurrently without blocking handling new
requests.

We call ``req->run_task()`` to execute task in background thread.  In
the passed callback, we just simply sleeps 1 second.  After sleep is
over, we schedule another callback to send response to the client.
Since the callback passed to ``req->run_task()`` is executed in the
different thread from the thread where request callback is called,
using ``req`` or ``res`` object directly there may cause undefined
behaviour.  To avoid this issue, we can use
``nghttp2::asio_http2::channel::post`` by supplying a callback which
in turn get called in the same thread where request callback was
called.
