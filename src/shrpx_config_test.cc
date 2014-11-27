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
#include "shrpx_config_test.h"

#include <CUnit/CUnit.h>

#include "shrpx_config.h"

namespace shrpx {

void test_shrpx_config_parse_config_str_list(void) {
  auto res = parse_config_str_list("a");
  CU_ASSERT(1 == res.size());
  CU_ASSERT(0 == strcmp("a", res[0]));
  clear_config_str_list(res);

  res = parse_config_str_list("a,");
  CU_ASSERT(2 == res.size());
  CU_ASSERT(0 == strcmp("a", res[0]));
  CU_ASSERT(0 == strcmp("", res[1]));
  clear_config_str_list(res);

  res = parse_config_str_list(",a,,");
  CU_ASSERT(4 == res.size());
  CU_ASSERT(0 == strcmp("", res[0]));
  CU_ASSERT(0 == strcmp("a", res[1]));
  CU_ASSERT(0 == strcmp("", res[2]));
  CU_ASSERT(0 == strcmp("", res[3]));
  clear_config_str_list(res);

  res = parse_config_str_list("");
  CU_ASSERT(1 == res.size());
  CU_ASSERT(0 == strcmp("", res[0]));
  clear_config_str_list(res);

  res = parse_config_str_list("alpha,bravo,charlie");
  CU_ASSERT(3 == res.size());
  CU_ASSERT(0 == strcmp("alpha", res[0]));
  CU_ASSERT(0 == strcmp("bravo", res[1]));
  CU_ASSERT(0 == strcmp("charlie", res[2]));
  clear_config_str_list(res);
}

void test_shrpx_config_parse_header(void) {
  auto p = parse_header("a: b");
  CU_ASSERT("a" == p.first);
  CU_ASSERT("b" == p.second);

  p = parse_header("a:  b");
  CU_ASSERT("a" == p.first);
  CU_ASSERT("b" == p.second);

  p = parse_header(":a: b");
  CU_ASSERT(":a" == p.first);
  CU_ASSERT("b" == p.second);

  p = parse_header("a: :b");
  CU_ASSERT("a" == p.first);
  CU_ASSERT(":b" == p.second);

  p = parse_header(": b");
  CU_ASSERT(p.first.empty());

  p = parse_header("alpha: bravo charlie");
  CU_ASSERT("alpha" == p.first);
  CU_ASSERT("bravo charlie" == p.second);
}

void test_shrpx_config_parse_log_format(void) {
  auto res = parse_log_format("$remote_addr - $remote_user [$time_local] "
                              "\"$request\" $status $body_bytes_sent "
                              "\"$http_referer\" \"$http_user_agent\"");
  CU_ASSERT(14 == res.size());

  CU_ASSERT(SHRPX_LOGF_REMOTE_ADDR == res[0].type);

  CU_ASSERT(SHRPX_LOGF_LITERAL == res[1].type);
  CU_ASSERT(0 == strcmp(" - $remote_user [", res[1].value.get()));

  CU_ASSERT(SHRPX_LOGF_TIME_LOCAL == res[2].type);

  CU_ASSERT(SHRPX_LOGF_LITERAL == res[3].type);
  CU_ASSERT(0 == strcmp("] \"", res[3].value.get()));

  CU_ASSERT(SHRPX_LOGF_REQUEST == res[4].type);

  CU_ASSERT(SHRPX_LOGF_LITERAL == res[5].type);
  CU_ASSERT(0 == strcmp("\" ", res[5].value.get()));

  CU_ASSERT(SHRPX_LOGF_STATUS == res[6].type);

  CU_ASSERT(SHRPX_LOGF_LITERAL == res[7].type);
  CU_ASSERT(0 == strcmp(" ", res[7].value.get()));

  CU_ASSERT(SHRPX_LOGF_BODY_BYTES_SENT == res[8].type);

  CU_ASSERT(SHRPX_LOGF_LITERAL == res[9].type);
  CU_ASSERT(0 == strcmp(" \"", res[9].value.get()));

  CU_ASSERT(SHRPX_LOGF_HTTP == res[10].type);
  CU_ASSERT(0 == strcmp("referer", res[10].value.get()));

  CU_ASSERT(SHRPX_LOGF_LITERAL == res[11].type);
  CU_ASSERT(0 == strcmp("\" \"", res[11].value.get()));

  CU_ASSERT(SHRPX_LOGF_HTTP == res[12].type);
  CU_ASSERT(0 == strcmp("user-agent", res[12].value.get()));

  CU_ASSERT(SHRPX_LOGF_LITERAL == res[13].type);
  CU_ASSERT(0 == strcmp("\"", res[13].value.get()));
}

} // namespace shrpx
