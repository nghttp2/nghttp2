/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2022 Nils Carlson
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

#include <nghttp2/asio_grpc_server.h>

#include "helloworld.pb.h"

using namespace nghttp2::asio_http2::server;
using namespace nghttp2::asio_grpc::server;

using SayHello_request = grpc_unary_request<helloworld::HelloRequest, helloworld::HelloReply >;
using SayHello_response = grpc_unary_response<helloworld::HelloReply>;
using SayHello_handler = grpc_unary_handler<helloworld::HelloRequest, helloworld::HelloReply >;

int main(int , char *[]) {
  boost::system::error_code ec;
  http2 server;

  server.handle("/helloworld.Greeter/SayHello", SayHello_handler{[](const SayHello_request &&request, SayHello_response &&response )
                                        {

                                            auto hello = request.get_message();
                                            std::cerr << "Got message with name :" << hello.name() << "\n";
                                            response.getMessage().set_message( "Hello " + hello.name() );
                                            response.write_response();
                                        }});
  if (server.listen_and_serve(ec, "localhost", "3000")) {
    std::cerr << "error: " << ec.message() << std::endl;
  }
}
