/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2015 Tatsuhiro Tsujikawa
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
#ifndef SHRPX_MRUBY_MODULE_H
#define SHRPX_MRUBY_MODULE_H

#include "shrpx.h"

#include <mruby.h>

#include "http2.h"

using namespace nghttp2;

namespace shrpx {

class Downstream;
class FieldStore;

namespace mruby {

mrb_value init_module(mrb_state *mrb);

void delete_downstream_from_module(mrb_state *mrb, mrb_value env,
                                   Downstream *downstream);

mrb_value create_headers_hash(mrb_state *mrb, const HeaderRefs &headers);

// Checks that |name| is a valid header field name.  If not, raise
// exception.
void check_header_name(mrb_state *mrb, const std::string_view &name);

// Checks that |value|, which must be a String, is a valid header
// field value.  If not, raise exception.  Header fields are written
// to HTTP/1 connection as is, and CR or LF in |value| would inject
// header fields.
void check_header_value(mrb_state *mrb, mrb_value value);

// clear_headers clears headers in fs but keep content-length and
// transfer-encoding if exist.
void clear_headers(FieldStore &fs);

} // namespace mruby

} // namespace shrpx

#endif // !defined(SHRPX_MRUBY_MODULE_H)
