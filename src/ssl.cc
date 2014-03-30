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
#include "ssl.h"

#include <cassert>
#include <vector>
#include <mutex>
#include <iostream>

#include <openssl/crypto.h>

namespace nghttp2 {

namespace ssl {

namespace {
std::vector<std::mutex> ssl_global_locks;
} // namespace

namespace {
void ssl_locking_cb(int mode, int type, const char *file, int line)
{
  if(mode & CRYPTO_LOCK) {
    ssl_global_locks[type].lock();
  } else {
    ssl_global_locks[type].unlock();
  }
}
} // namespace

LibsslGlobalLock::LibsslGlobalLock()
{
  if(!ssl_global_locks.empty()) {
    std::cerr << "OpenSSL global lock has been already set" << std::endl;
    assert(0);
  }
  ssl_global_locks = std::vector<std::mutex>(CRYPTO_num_locks());
  // CRYPTO_set_id_callback(ssl_thread_id); OpenSSL manual says that
  // if threadid_func is not specified using
  // CRYPTO_THREADID_set_callback(), then default implementation is
  // used. We use this default one.
  CRYPTO_set_locking_callback(ssl_locking_cb);
}

LibsslGlobalLock::~LibsslGlobalLock()
{
  ssl_global_locks.clear();
}

} // namespace ssl

} // namespace nghttp2
