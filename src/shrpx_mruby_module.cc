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
#include "shrpx_mruby_module.h"

#include <array>

#include <mruby/variable.h>
#include <mruby/string.h>
#include <mruby/hash.h>
#include <mruby/array.h>

#include "shrpx_mruby.h"
#include "shrpx_mruby_module_request.h"
#include "shrpx_mruby_module_response.h"

namespace shrpx {

namespace mruby {

namespace {
mrb_value run(mrb_state *mrb, mrb_value self) {
  mrb_value b;
  mrb_get_args(mrb, "&", &b);

  auto module = mrb_module_get(mrb, "Nghttpx");
  auto request_class = mrb_class_get_under(mrb, module, "Request");
  auto response_class = mrb_class_get_under(mrb, module, "Response");

  std::array<mrb_value, 2> args{{mrb_obj_new(mrb, response_class, 0, nullptr),
                                 mrb_obj_new(mrb, request_class, 0, nullptr)}};
  return mrb_yield_argv(mrb, b, args.size(), args.data());
}
} // namespace

void init_module(mrb_state *mrb) {
  auto module = mrb_define_module(mrb, "Nghttpx");

  mrb_define_class_method(mrb, module, "run", run, MRB_ARGS_BLOCK());

  init_request_class(mrb, module);
  init_response_class(mrb, module);
}

mrb_value create_headers_hash(mrb_state *mrb, const Headers &headers) {
  auto hash = mrb_hash_new(mrb);

  for (auto &hd : headers) {
    if (hd.name.empty() || hd.name[0] == ':') {
      continue;
    }
    auto key = mrb_str_new(mrb, hd.name.c_str(), hd.name.size());
    auto ary = mrb_hash_get(mrb, hash, key);
    if (mrb_nil_p(ary)) {
      ary = mrb_ary_new(mrb);
      mrb_hash_set(mrb, hash, key, ary);
    }
    mrb_ary_push(mrb, ary, mrb_str_new(mrb, hd.value.c_str(), hd.value.size()));
  }

  return hash;
}

} // namespace mruby

} // namespace shrpx
