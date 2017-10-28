libnghttp2_asio: High level HTTP/2 C++ library
==============================================

libnghttp2_asio is C++ library built on top of libnghttp2 and provides
high level abstraction API to build HTTP/2 applications.  It depends
on Boost::ASIO library and OpenSSL.  Currently libnghttp2_asio
provides server and client side API.

libnghttp2_asio is not built by default.  Use ``--enable-asio-lib``
configure flag to build libnghttp2_asio.  The required Boost libraries
are:

* Boost::Asio
* Boost::System
* Boost::Thread

We have 3 header files for this library:

* :doc:`asio_http2_server.h`
* :doc:`asio_http2_client.h`
* :doc:`asio_http2.h`

asio_http2.h is included from the other two files.

To build a program with libnghttp2_asio, link to the following
libraries::

    -lnghttp2_asio -lboost_system

If ``boost::asio::ssl`` is used in application code, OpenSSL is also
required in link line::

    -lnghttp2_asio -lboost_system -lssl -lcrypto

Server API
----------

To use server API, first include following header file:

.. code-block:: cpp

    #include <nghttp2/asio_http2_server.h>

Also take a look at that header file :doc:`asio_http2_server.h`.

Server API is designed to build HTTP/2 server very easily to utilize
C++11 anonymous function and closure.  The bare minimum example of
HTTP/2 server looks like this:

.. code-block:: cpp

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::server;

    int main(int argc, char *argv[]) {
      boost::system::error_code ec;
      http2 server;

      server.handle("/", [](const request &req, const response &res) {
        res.write_head(200);
        res.end("hello, world\n");
      });

      if (server.listen_and_serve(ec, "localhost", "3000")) {
        std::cerr << "error: " << ec.message() << std::endl;
      }
    }

First we instantiate ``nghttp2::asio_http2::server::http2`` object.
``nghttp2::asio_http2::server::http2::handle`` function registers
pattern and its handler function.  In this example, we register "/" as
pattern, which matches all requests.  Then call
``nghttp2::asio_http2::server::http2::listen_and_serve`` function with
address and port to listen to.

The ``req`` and ``res`` represent HTTP request and response
respectively.  ``nghttp2::asio_http2_::server::response::write_head``
constructs HTTP response header fields.  The first argument is HTTP
status code, in the above example, which is 200.  The second argument,
which is omitted in the above example, is additional header fields to
send.

``nghttp2::asio_http2::server::response::end`` sends response body.
In the above example, we send string "hello, world".

The life time of req and res object ends after the callback set by
``nghttp2::asio_http2::server::response::on_close`` function.
Application must not use those objects after this call.

Serving static files and enabling SSL/TLS
+++++++++++++++++++++++++++++++++++++++++

In this example, we serve a couple of static files and also enable
SSL/TLS.

.. code-block:: cpp

    #include <nghttp2/asio_http2_server.h>

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::server;

    int main(int argc, char *argv[]) {
      boost::system::error_code ec;
      boost::asio::ssl::context tls(boost::asio::ssl::context::sslv23);

      tls.use_private_key_file("server.key", boost::asio::ssl::context::pem);
      tls.use_certificate_chain_file("server.crt");

      configure_tls_context_easy(ec, tls);

      http2 server;

      server.handle("/index.html", [](const request &req, const response &res) {
        res.write_head(200);
        res.end(file_generator("index.html"));
      });

      if (server.listen_and_serve(ec, tls, "localhost", "3000")) {
        std::cerr << "error: " << ec.message() << std::endl;
      }
    }

We first create ``boost::asio::ssl::context`` object and set path to
private key file and certificate file.
``nghttp2::asio_http2::server::configure_tls_context_easy`` function
configures SSL/TLS context object for HTTP/2 server use, including NPN
callbacks.

In the above example, if request path is "/index.html", we serve
index.html file in the current working directory.
``nghttp2::asio_http2::server::response::end`` has overload to take
function of type ``nghttp2::asio_http2::generator_cb`` and application
pass its implementation to generate response body.  For the
convenience, libnghttp2_asio library provides
``nghttp2::asio_http2::file_generator`` function to generate function
to server static file.  If other resource is requested, server
automatically responds with 404 status code.

Server push
+++++++++++

Server push is also supported.

.. code-block:: cpp

    #include <nghttp2/asio_http2_server.h>

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::server;

    int main(int argc, char *argv[]) {
      boost::system::error_code ec;
      boost::asio::ssl::context tls(boost::asio::ssl::context::sslv23);

      tls.use_private_key_file("server.key", boost::asio::ssl::context::pem);
      tls.use_certificate_chain_file("server.crt");

      configure_tls_context_easy(ec, tls);

      http2 server;

      std::string style_css = "h1 { color: green; }";

      server.handle("/", [&style_css](const request &req, const response &res) {
        boost::system::error_code ec;
        auto push = res.push(ec, "GET", "/style.css");
        push->write_head(200);
        push->end(style_css);

        res.write_head(200);
        res.end(R"(
    <!DOCTYPE html><html lang="en">
    <title>HTTP/2 FTW</title><body>
    <link href="/style.css" rel="stylesheet" type="text/css">
    <h1>This should be green</h1>
    </body></html>
    )");
      });

      server.handle("/style.css",
                    [&style_css](const request &req, const response &res) {
        res.write_head(200);
        res.end(style_css);
      });

      if (server.listen_and_serve(ec, tls, "localhost", "3000")) {
        std::cerr << "error: " << ec.message() << std::endl;
      }
    }

When client requested any resource other than "/style.css", we push
"/style.css".  To push resource, call
``nghttp2::asio_http2::server::response::push`` function with desired
method and path.  It returns another response object and use its
functions to send push response.

Enable multi-threading
++++++++++++++++++++++

Enabling multi-threading is very easy.  Just call
``nghttp2::asio_http2::server::http2::num_threads`` function with the
desired number of threads:

.. code-block:: cpp

    http2 server;

    // Use 4 native threads
    server.num_threads(4);

Client API
----------

To use client API, first include following header file:

.. code-block:: cpp

    #include <nghttp2/asio_http2_client.h>

Also take a look at that header file :doc:`asio_http2_client.h`.

Here is the sample client code to access HTTP/2 server and print out
response header fields and response body to the console screen:

.. code-block:: cpp

    #include <iostream>

    #include <nghttp2/asio_http2_client.h>

    using boost::asio::ip::tcp;

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::client;

    int main(int argc, char *argv[]) {
      boost::system::error_code ec;
      boost::asio::io_service io_service;

      // connect to localhost:3000
      session sess(io_service, "localhost", "3000");

      sess.on_connect([&sess](tcp::resolver::iterator endpoint_it) {
	boost::system::error_code ec;

	auto req = sess.submit(ec, "GET", "http://localhost:3000/");

	req->on_response([](const response &res) {
	  // print status code and response header fields.
	  std::cerr << "HTTP/2 " << res.status_code() << std::endl;
	  for (auto &kv : res.header()) {
	    std::cerr << kv.first << ": " << kv.second.value << "\n";
	  }
	  std::cerr << std::endl;

	  res.on_data([](const uint8_t *data, std::size_t len) {
	    std::cerr.write(reinterpret_cast<const char *>(data), len);
	    std::cerr << std::endl;
	  });
	});

	req->on_close([&sess](uint32_t error_code) {
	  // shutdown session after first request was done.
	  sess.shutdown();
	});
      });

      sess.on_error([](const boost::system::error_code &ec) {
	std::cerr << "error: " << ec.message() << std::endl;
      });

      io_service.run();
    }

``nghttp2::asio_http2::client::session`` object takes
``boost::asio::io_service`` object and remote server address.  When
connection is made, the callback function passed to
``nghttp2::asio_http2::client::on_connect`` is invoked with connected
address as its parameter.  After this callback call, use
``nghttp2::asio_http2::session::submit`` to send request to the
server.  You can submit multiple requests at once without waiting for
the completion of previous request.

The life time of req and res object ends after the callback set by
``nghttp2::asio_http2::server::request::on_close`` function.
Application must not use those objects after this call.

Normally, client does not stop even after all requests are done unless
connection is lost.  To stop client, call
``nghttp2::asio_http2::server::session::shutdown()``.

Receive server push and enable SSL/TLS
++++++++++++++++++++++++++++++++++++++

.. code-block:: cpp

    #include <iostream>

    #include <nghttp2/asio_http2_client.h>

    using boost::asio::ip::tcp;

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::client;

    int main(int argc, char *argv[]) {
      boost::system::error_code ec;
      boost::asio::io_service io_service;

      boost::asio::ssl::context tls(boost::asio::ssl::context::sslv23);
      tls.set_default_verify_paths();
      // disabled to make development easier...
      // tls_ctx.set_verify_mode(boost::asio::ssl::verify_peer);
      configure_tls_context(ec, tls);

      // connect to localhost:3000
      session sess(io_service, tls, "localhost", "3000");

      sess.on_connect([&sess](tcp::resolver::iterator endpoint_it) {
	boost::system::error_code ec;

	auto req = sess.submit(ec, "GET", "http://localhost:3000/");

	req->on_response([&sess](const response &res) {
	  std::cerr << "response received!" << std::endl;
	  res.on_data([&sess](const uint8_t *data, std::size_t len) {
	    std::cerr.write(reinterpret_cast<const char *>(data), len);
	    std::cerr << std::endl;
	  });
	});

	req->on_push([](const request &push) {
	  std::cerr << "push request received!" << std::endl;
	  push.on_response([](const response &res) {
	    std::cerr << "push response received!" << std::endl;
	    res.on_data([](const uint8_t *data, std::size_t len) {
	      std::cerr.write(reinterpret_cast<const char *>(data), len);
	      std::cerr << std::endl;
	    });
	  });
	});
      });

      sess.on_error([](const boost::system::error_code &ec) {
	std::cerr << "error: " << ec.message() << std::endl;
      });

      io_service.run();
    }

The above sample code demonstrates how to enable SSL/TLS and receive
server push.  Currently,
``nghttp2::asio_http2::client::configure_tls_context`` function setups
NPN callbacks for SSL/TLS context for HTTP/2 use.

To receive server push, use
``nghttp2::asio_http2::client::request::on_push`` function to set
callback function which is invoked when server push request is
arrived.  The callback function takes
``nghttp2::asio_http2::client::request`` object, which contains the
pushed request.  To get server push response, set callback using
``nghttp2::asio_http2::client::request::on_response``.

As stated in the previous section, client does not stop automatically
as long as HTTP/2 session is fine and connection is alive.  We don't
call ``nghttp2::asio_http2::client::session::shutdown`` in this
example, so the program does not terminate after all responses are
received.  Hit Ctrl-C to terminate the program.

Multiple concurrent requests
++++++++++++++++++++++++++++

.. code-block:: cpp

    #include <iostream>

    #include <nghttp2/asio_http2_client.h>

    using boost::asio::ip::tcp;

    using namespace nghttp2::asio_http2;
    using namespace nghttp2::asio_http2::client;

    int main(int argc, char *argv[]) {
      boost::system::error_code ec;
      boost::asio::io_service io_service;

      // connect to localhost:3000
      session sess(io_service, "localhost", "3000");

      sess.on_connect([&sess](tcp::resolver::iterator endpoint_it) {
	boost::system::error_code ec;

	auto printer = [](const response &res) {
	  res.on_data([](const uint8_t *data, std::size_t len) {
	    std::cerr.write(reinterpret_cast<const char *>(data), len);
	    std::cerr << std::endl;
	  });
	};

	std::size_t num = 3;
	auto count = std::make_shared<int>(num);

	for (std::size_t i = 0; i < num; ++i) {
	  auto req = sess.submit(ec, "GET",
				 "http://localhost:3000/" + std::to_string(i + 1));

	  req->on_response(printer);
	  req->on_close([&sess, count](uint32_t error_code) {
	    if (--*count == 0) {
	      // shutdown session after |num| requests were done.
	      sess.shutdown();
	    }
	  });
	}
      });

      sess.on_error([](const boost::system::error_code &ec) {
	std::cerr << "error: " << ec.message() << std::endl;
      });

      io_service.run();
    }

Here is the sample to send 3 requests at once.  Depending on the
server settings, these requests are processed out-of-order.  In this
example, we have a trick to shutdown session after all requests were
done.  We made ``count`` object which is shared pointer to int and is
initialized to 3.  On each request closure (the invocation of the
callback set by ``nghttp2::asio_http2::client::request::on_close``),
we decrement the count.  If count becomes 0, we are sure that all
requests have been done and initiate shutdown.
