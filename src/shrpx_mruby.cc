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
#include "shrpx_mruby.h"

#include <mruby/compile.h>
#include <mruby/string.h>

#include "shrpx_downstream.h"
#include "shrpx_config.h"
#include "shrpx_mruby_module.h"
#include "shrpx_downstream_connection.h"
#include "template.h"

namespace shrpx {

namespace mruby {

MRubyContext::MRubyContext(mrb_state *mrb, RProc *on_request_proc,
                           RProc *on_response_proc)
    : mrb_(mrb), on_request_proc_(on_request_proc),
      on_response_proc_(on_response_proc), running_(false) {}

MRubyContext::~MRubyContext() { mrb_close(mrb_); }

int MRubyContext::run_request_proc(Downstream *downstream, RProc *proc) {
  if (!proc || running_) {
    return 0;
  }

  running_ = true;

  MRubyAssocData data{downstream};

  mrb_->ud = &data;

  int rv = 0;
  auto ai = mrb_gc_arena_save(mrb_);

  auto res = mrb_run(mrb_, proc, mrb_top_self(mrb_));
  (void)res;

  if (mrb_->exc) {
    // If response has been committed, ignore error
    if (downstream->get_response_state() != Downstream::MSG_COMPLETE) {
      rv = -1;
    }
    auto error =
        mrb_str_ptr(mrb_funcall(mrb_, mrb_obj_value(mrb_->exc), "inspect", 0));

    LOG(ERROR) << "Exception caught while executing mruby code: "
               << error->as.heap.ptr;
    mrb_->exc = 0;
  }

  mrb_->ud = nullptr;

  mrb_gc_arena_restore(mrb_, ai);

  if (data.request_headers_dirty) {
    downstream->index_request_headers();
  }

  if (data.response_headers_dirty) {
    downstream->index_response_headers();
  }

  running_ = false;

  return rv;
}

int MRubyContext::run_on_request_proc(Downstream *downstream) {
  return run_request_proc(downstream, on_request_proc_);
}

int MRubyContext::run_on_response_proc(Downstream *downstream) {
  return run_request_proc(downstream, on_response_proc_);
}

// Based on
// https://github.com/h2o/h2o/blob/master/lib/handler/mruby.c.  It is
// very hard to write these kind of code because mruby has almost no
// documentation aobut compiling or generating code, at least at the
// time of this writing.
RProc *compile(mrb_state *mrb, const char *filename) {
  if (filename == nullptr) {
    return nullptr;
  }

  auto infile = fopen(filename, "rb");
  if (infile == nullptr) {
    return nullptr;
  }
  auto infile_d = defer(fclose, infile);

  auto mrbc = mrbc_context_new(mrb);
  if (mrbc == nullptr) {
    LOG(ERROR) << "mrb_context_new failed";
    return nullptr;
  }
  auto mrbc_d = defer(mrbc_context_free, mrb, mrbc);

  auto parser = mrb_parse_file(mrb, infile, nullptr);
  if (parser == nullptr) {
    LOG(ERROR) << "mrb_parse_nstring failed";
    return nullptr;
  }
  auto parser_d = defer(mrb_parser_free, parser);

  if (parser->nerr != 0) {
    LOG(ERROR) << "mruby parser detected parse error";
    return nullptr;
  }

  auto proc = mrb_generate_code(mrb, parser);
  if (proc == nullptr) {
    LOG(ERROR) << "mrb_generate_code failed";
    return nullptr;
  }

  return proc;
}

std::unique_ptr<MRubyContext> create_mruby_context() {
  auto mrb = mrb_open();
  if (mrb == nullptr) {
    LOG(ERROR) << "mrb_open failed";
    return nullptr;
  }

  init_module(mrb);

  auto req_file = get_config()->on_request_mruby_file.get();
  auto res_file = get_config()->on_response_mruby_file.get();

  auto req_proc = compile(mrb, req_file);

  if (req_file && !req_proc) {
    LOG(ERROR) << "Could not compile mruby code " << req_file;
    mrb_close(mrb);
    return nullptr;
  }

  auto res_proc = compile(mrb, res_file);

  if (res_file && !res_proc) {
    LOG(ERROR) << "Could not compile mruby code " << res_file;
    mrb_close(mrb);
    return nullptr;
  }

  return make_unique<MRubyContext>(mrb, req_proc, res_proc);
}

} // namespace mruby

} // namespace shrpx
