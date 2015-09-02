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

#include <mruby/variable.h>
#include <mruby/string.h>
#include <mruby/hash.h>
#include <mruby/array.h>

#include "shrpx_downstream.h"
#include "shrpx_mruby.h"
#include "util.h"

namespace shrpx {

namespace mruby {

namespace {
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
} // namespace

namespace {
mrb_value request_init(mrb_state *mrb, mrb_value self) { return self; }
} // namespace

namespace {
mrb_value request_get_path(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto &path = downstream->get_request_path();

  return mrb_str_new(mrb, path.c_str(), path.size());
}
} // namespace

namespace {
mrb_value request_set_path(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;

  const char *path;
  mrb_int pathlen;
  mrb_get_args(mrb, "s", &path, &pathlen);
  if (pathlen == 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "path must not be empty string");
  }

  downstream->set_request_path(std::string(path, pathlen));

  return self;
}
} // namespace

namespace {
mrb_value request_get_headers(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  return create_headers_hash(mrb, downstream->get_request_headers());
}
} // namespace

namespace {
mrb_value request_set_header(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;

  mrb_value key, values;
  mrb_get_args(mrb, "oo", &key, &values);

  if (RSTRING_LEN(key) == 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "empty key is not allowed");
  }

  key = mrb_funcall(mrb, key, "downcase", 0);

  // making name empty will effectively delete header fields
  for (auto &hd : downstream->get_request_headers()) {
    if (util::streq(std::begin(hd.name), hd.name.size(), RSTRING_PTR(key),
                    RSTRING_LEN(key))) {
      hd.name = "";
    }
  }

  if (mrb_obj_is_instance_of(mrb, values, mrb->array_class)) {
    auto n = mrb_ary_len(mrb, values);
    for (int i = 0; i < n; ++i) {
      auto value = mrb_ary_entry(values, i);
      downstream->add_request_header(
          std::string(RSTRING_PTR(key), RSTRING_LEN(key)),
          std::string(RSTRING_PTR(value), RSTRING_LEN(value)));
    }
  } else {
    downstream->add_request_header(
        std::string(RSTRING_PTR(key), RSTRING_LEN(key)),
        std::string(RSTRING_PTR(values), RSTRING_LEN(values)));
  }

  data->request_headers_dirty = true;

  return mrb_nil_value();
}
} // namespace

namespace {
void init_request_class(mrb_state *mrb, RClass *module) {
  auto request_class =
      mrb_define_class_under(mrb, module, "Request", mrb->object_class);

  mrb_define_method(mrb, request_class, "initialize", request_init,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, request_class, "path", request_get_path,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, request_class, "path=", request_set_path,
                    MRB_ARGS_REQ(1));
  mrb_define_method(mrb, request_class, "headers", request_get_headers,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, request_class, "set_header", request_set_header,
                    MRB_ARGS_REQ(2));
}
} // namespace

namespace {
mrb_value run(mrb_state *mrb, mrb_value self) {
  mrb_value b;
  mrb_get_args(mrb, "&", &b);

  auto module = mrb_module_get(mrb, "Nghttpx");
  auto request_class = mrb_class_get_under(mrb, module, "Request");
  auto request = mrb_obj_new(mrb, request_class, 0, nullptr);

  std::array<mrb_value, 1> args{{request}};
  return mrb_yield_argv(mrb, b, args.size(), args.data());
}
} // namespace

void init_module(mrb_state *mrb) {
  auto module = mrb_define_module(mrb, "Nghttpx");

  mrb_define_class_method(mrb, module, "run", run, MRB_ARGS_BLOCK());

  init_request_class(mrb, module);
}

} // namespace mruby

} // namespace shrpx
