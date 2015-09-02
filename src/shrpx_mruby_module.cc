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

#include "shrpx_downstream.h"
#include "util.h"

namespace shrpx {

namespace mruby {

namespace {
mrb_value request_init(mrb_state *mrb, mrb_value self) { return self; }
} // namespace

namespace {
mrb_value request_get_path(mrb_state *mrb, mrb_value self) {
  auto downstream = static_cast<Downstream *>(mrb->ud);
  auto &path = downstream->get_request_path();

  return mrb_str_new_static(mrb, path.c_str(), path.size());
}
} // namespace

namespace {
mrb_value request_set_path(mrb_state *mrb, mrb_value self) {
  auto downstream = static_cast<Downstream *>(mrb->ud);

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
  auto headers = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "RequestHeaders"));
  if (mrb_nil_p(headers)) {
    auto module = mrb_module_get(mrb, "Nghttpx");
    auto headers_class = mrb_class_get_under(mrb, module, "RequestHeaders");
    headers = mrb_obj_new(mrb, headers_class, 0, nullptr);
    mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "RequestHeaders"), headers);
  }
  return headers;
}
} // namespace

namespace {
mrb_value headers_init(mrb_state *mrb, mrb_value self) { return self; }
} // namespace

namespace {
mrb_value request_headers_get(mrb_state *mrb, mrb_value self) {
  auto downstream = static_cast<Downstream *>(mrb->ud);

  mrb_value key;
  mrb_get_args(mrb, "o", &key);

  key = mrb_funcall(mrb, key, "downcase", 0);

  if (RSTRING_LEN(key) == 0) {
    return key;
  }

  auto hd = downstream->get_request_header(
      std::string(RSTRING_PTR(key), RSTRING_LEN(key)));

  if (hd == nullptr) {
    return mrb_nil_value();
  }

  return mrb_str_new_static(mrb, hd->value.c_str(), hd->value.size());
}
} // namespace

namespace {
mrb_value request_headers_set(mrb_state *mrb, mrb_value self, bool repl) {
  auto downstream = static_cast<Downstream *>(mrb->ud);

  mrb_value key, value;
  mrb_get_args(mrb, "oo", &key, &value);

  key = mrb_funcall(mrb, key, "downcase", 0);

  if (RSTRING_LEN(key) == 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "empty key is not allowed");
  }

  if (repl) {
    for (auto &hd : downstream->get_request_headers()) {
      if (util::streq(std::begin(hd.name), hd.name.size(), RSTRING_PTR(key),
                      RSTRING_LEN(key))) {
        hd.name = "";
      }
    }
  }

  downstream->add_request_header(
      std::string(RSTRING_PTR(key), RSTRING_LEN(key)),
      std::string(RSTRING_PTR(value), RSTRING_LEN(value)));

  downstream->set_request_headers_dirty(true);

  return key;
}
} // namespace

namespace {
mrb_value request_headers_set(mrb_state *mrb, mrb_value self) {
  return request_headers_set(mrb, self, true);
}
} // namespace

namespace {
mrb_value request_headers_add(mrb_state *mrb, mrb_value self) {
  return request_headers_set(mrb, self, false);
}
} // namespace

namespace {
void init_headers_class(mrb_state *mrb, RClass *module, const char *name,
                        mrb_func_t get, mrb_func_t set, mrb_func_t add) {
  auto headers_class =
      mrb_define_class_under(mrb, module, name, mrb->object_class);

  mrb_define_method(mrb, headers_class, "initialize", headers_init,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, headers_class, "get", get, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, headers_class, "set", set, MRB_ARGS_REQ(2));
  mrb_define_method(mrb, headers_class, "add", add, MRB_ARGS_REQ(2));
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

  init_headers_class(mrb, module, "RequestHeaders", request_headers_get,
                     request_headers_set, request_headers_add);
}
} // namespace

void init_module(mrb_state *mrb) {
  auto module = mrb_define_module(mrb, "Nghttpx");

  init_request_class(mrb, module);
}

} // namespace mruby

} // namespace shrpx
