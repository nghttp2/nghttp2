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
// We wrote this code based on the original code which has the
// following license:
//
// main.cpp
// ~~~~~~~~
//
// Copyright (c) 2003-2013 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <unistd.h>
#include <iostream>
#include <string>
#include <deque>

#include <nghttp2/asio_http2.h>

using namespace nghttp2::asio_http2;
using namespace nghttp2::asio_http2::server;

int main(int argc, char* argv[])
{
  try {
    // Check command line arguments.
    if (argc < 4) {
      std::cerr << "Usage: asio-sv3 <port> <threads> <tasks> "
                << " <private-key-file> <cert-file>\n";
      return 1;
    }

    uint16_t port = std::stoi(argv[1]);
    std::size_t num_threads = std::stoi(argv[2]);
    std::size_t num_concurrent_tasks = std::stoi(argv[3]);

    http2 server;

    server.num_threads(num_threads);

    if(argc >= 5) {
      server.tls(argv[4], argv[5]);
    }

    server.num_concurrent_tasks(num_concurrent_tasks);

    server.listen
      ("*", port,
       [](std::shared_ptr<request> req, std::shared_ptr<response> res)
       {
         res->write_head(200);

         auto msgq = std::make_shared<std::deque<std::string>>();

         res->end
           ([msgq](uint8_t *buf, std::size_t len) -> std::pair<ssize_t, bool>
            {
              if(msgq->empty()) {
                // if msgq is empty, tells the library that don't call
                // this callback until we call res->resume().  This is
                // done by returing std::make_pair(0, false).
                return std::make_pair(0, false);
              }
              auto msg = std::move(msgq->front());
              msgq->pop_front();

              if(msg.empty()) {
                // The empty message signals the end of response in
                // this simple protocol.
                return std::make_pair(0, true);
              }

              auto nwrite = std::min(len, msg.size());
              std::copy(std::begin(msg), std::begin(msg) + nwrite, buf);
              if(msg.size() > nwrite) {
                msgq->push_front(msg.substr(nwrite));
              }
              return std::make_pair(nwrite, false);
            });

         req->run_task
           ([res, msgq](channel& channel)
            {
              // executed in different thread from request callback
              // was called.

              // Using res and msgq is not safe inside this callback.
              // But using them in callback passed to channel::post is
              // safe.

              // We just emit simple message "message N\n" in every 1
              // second and 3 times in total.
              for(std::size_t i = 0; i < 3; ++i) {
                msgq->push_back("message " + std::to_string(i + 1) + "\n");

                channel.post([res]()
                             {
                               // executed in same thread where
                               // request callback was called.

                               // Tells library we have new message.
                               res->resume();
                             });

                sleep(1);
              }

              // Send empty message to signal the end of response
              // body.
              msgq->push_back("");

              channel.post([res]()
                           {
                             // executed in same thread where request
                             // callback was called.
                             res->resume();
                           });

            });

       });
  } catch (std::exception& e) {
    std::cerr << "exception: " << e.what() << "\n";
  }

  return 0;
}
