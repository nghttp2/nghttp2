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
#include "shrpx_mruby_module_env.h"

#include <mruby/variable.h>
#include <mruby/string.h>
#include <mruby/hash.h>

#include "shrpx_downstream.h"
#include "shrpx_upstream.h"
#include "shrpx_client_handler.h"
#include "shrpx_mruby.h"
#include "shrpx_mruby_module.h"
#include "shrpx_log.h"
#include "shrpx_tls.h"

namespace shrpx {

namespace mruby {

namespace {
mrb_value env_init(mrb_state *mrb, mrb_value self) { return self; }
} // namespace

namespace {
mrb_value env_get_req(mrb_state *mrb, mrb_value self) {
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "req"));
}
} // namespace

namespace {
mrb_value env_get_resp(mrb_state *mrb, mrb_value self) {
  return mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "resp"));
}
} // namespace

namespace {
mrb_value env_get_ctx(mrb_state *mrb, mrb_value self) {
  auto data = reinterpret_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;

  auto dsym = intern_ptr(mrb, downstream);

  auto ctx = mrb_iv_get(mrb, self, dsym);
  if (mrb_nil_p(ctx)) {
    ctx = mrb_hash_new(mrb);
    mrb_iv_set(mrb, self, dsym, ctx);
  }

  return ctx;
}
} // namespace

namespace {
mrb_value env_get_phase(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);

  return mrb_fixnum_value(data->phase);
}
} // namespace

namespace {
mrb_value env_get_remote_addr(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();

  auto &ipaddr = handler->get_ipaddr();

  return mrb_str_new(mrb, ipaddr.c_str(), ipaddr.size());
}
} // namespace

namespace {
mrb_value env_get_server_port(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto faddr = handler->get_upstream_addr();

  return mrb_fixnum_value(faddr->port);
}
} // namespace

namespace {
mrb_value env_get_server_addr(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto faddr = handler->get_upstream_addr();

  return mrb_str_new(mrb, faddr->host.c_str(), faddr->host.size());
}
} // namespace

namespace {
mrb_value env_get_tls_used(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();

  return handler->get_ssl() ? mrb_true_value() : mrb_false_value();
}
} // namespace

namespace {
mrb_value env_get_tls_sni(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto sni = handler->get_tls_sni();

  return mrb_str_new(mrb, sni.c_str(), sni.size());
}
} // namespace

namespace {
mrb_value env_get_tls_client_fingerprint(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto ssl = handler->get_ssl();

  if (!ssl) {
    return mrb_str_new_static(mrb, "", 0);
  }

  auto x = SSL_get_peer_certificate(ssl);
  if (!x) {
    return mrb_str_new_static(mrb, "", 0);
  }

  // Fingerprint is SHA-256, so we need 32 bytes buffer.
  std::array<uint8_t, 32> buf;
  auto slen = tls::get_x509_fingerprint(buf.data(), buf.size(), x);
  X509_free(x);
  if (slen == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "could not compute client fingerprint");
  }

  // TODO Use template version of format_hex
  auto &balloc = downstream->get_block_allocator();
  auto f = util::format_hex(balloc,
                            StringRef{std::begin(buf), std::begin(buf) + slen});
  return mrb_str_new(mrb, f.c_str(), f.size());
}
} // namespace

namespace {
mrb_value env_get_tls_client_subject_name(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto ssl = handler->get_ssl();

  if (!ssl) {
    return mrb_str_new_static(mrb, "", 0);
  }

  auto x = SSL_get_peer_certificate(ssl);
  if (!x) {
    return mrb_str_new_static(mrb, "", 0);
  }

  auto &balloc = downstream->get_block_allocator();
  auto name = tls::get_x509_subject_name(balloc, x);
  X509_free(x);
  return mrb_str_new(mrb, name.c_str(), name.size());
}
} // namespace

namespace {
mrb_value env_get_tls_cipher(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto ssl = handler->get_ssl();

  if (!ssl) {
    return mrb_str_new_static(mrb, "", 0);
  }

  return mrb_str_new_cstr(mrb, SSL_get_cipher_name(ssl));
}
} // namespace

namespace {
mrb_value env_get_tls_protocol(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto ssl = handler->get_ssl();

  if (!ssl) {
    return mrb_str_new_static(mrb, "", 0);
  }

  return mrb_str_new_cstr(mrb, nghttp2::tls::get_tls_protocol(ssl));
}
} // namespace

namespace {
mrb_value env_get_tls_session_id(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto ssl = handler->get_ssl();

  if (!ssl) {
    return mrb_str_new_static(mrb, "", 0);
  }

  auto session = SSL_get_session(ssl);
  if (!session) {
    return mrb_str_new_static(mrb, "", 0);
  }

  unsigned int session_id_length = 0;
  auto session_id = SSL_SESSION_get_id(session, &session_id_length);

  // TODO Use template version of util::format_hex.
  auto &balloc = downstream->get_block_allocator();
  auto id = util::format_hex(balloc, StringRef{session_id, session_id_length});
  return mrb_str_new(mrb, id.c_str(), id.size());
}
} // namespace

namespace {
mrb_value env_get_tls_session_reused(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto ssl = handler->get_ssl();

  if (!ssl) {
    return mrb_false_value();
  }

  return SSL_session_reused(ssl) ? mrb_true_value() : mrb_false_value();
}
} // namespace

namespace {
mrb_value env_get_alpn(mrb_state *mrb, mrb_value self) {
  auto data = static_cast<MRubyAssocData *>(mrb->ud);
  auto downstream = data->downstream;
  auto upstream = downstream->get_upstream();
  auto handler = upstream->get_client_handler();
  auto alpn = handler->get_alpn();
  return mrb_str_new(mrb, alpn.c_str(), alpn.size());
}
} // namespace

void init_env_class(mrb_state *mrb, RClass *module) {
  auto env_class =
      mrb_define_class_under(mrb, module, "Env", mrb->object_class);

  mrb_define_method(mrb, env_class, "initialize", env_init, MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "req", env_get_req, MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "resp", env_get_resp, MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "ctx", env_get_ctx, MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "phase", env_get_phase, MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "remote_addr", env_get_remote_addr,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "server_addr", env_get_server_addr,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "server_port", env_get_server_port,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "tls_used", env_get_tls_used,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "tls_sni", env_get_tls_sni,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "tls_client_fingerprint",
                    env_get_tls_client_fingerprint, MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "tls_client_subject_name",
                    env_get_tls_client_subject_name, MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "tls_cipher", env_get_tls_cipher,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "tls_protocol", env_get_tls_protocol,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "tls_session_id", env_get_tls_session_id,
                    MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "tls_session_reused",
                    env_get_tls_session_reused, MRB_ARGS_NONE());
  mrb_define_method(mrb, env_class, "alpn", env_get_alpn, MRB_ARGS_NONE());
}

} // namespace mruby

} // namespace shrpx
