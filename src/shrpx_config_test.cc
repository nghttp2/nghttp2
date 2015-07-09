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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif // HAVE_UNISTD_H

#include <cstdlib>

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

  res = parse_config_str_list(":a::", ':');
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

void test_shrpx_config_read_tls_ticket_key_file(void) {
  char file1[] = "/tmp/nghttpx-unittest.XXXXXX";
  auto fd1 = mkstemp(file1);
  assert(fd1 != -1);
  assert(48 ==
         write(fd1, "0..............12..............34..............5", 48));
  char file2[] = "/tmp/nghttpx-unittest.XXXXXX";
  auto fd2 = mkstemp(file2);
  assert(fd2 != -1);
  assert(48 ==
         write(fd2, "6..............78..............9a..............b", 48));

  close(fd1);
  close(fd2);
  auto ticket_keys = read_tls_ticket_key_file({file1, file2});
  unlink(file1);
  unlink(file2);
  CU_ASSERT(ticket_keys.get() != nullptr);
  CU_ASSERT(2 == ticket_keys->keys.size());
  auto key = &ticket_keys->keys[0];
  CU_ASSERT(0 == memcmp("0..............1", key->name, sizeof(key->name)));
  CU_ASSERT(0 ==
            memcmp("2..............3", key->aes_key, sizeof(key->aes_key)));
  CU_ASSERT(0 ==
            memcmp("4..............5", key->hmac_key, sizeof(key->hmac_key)));

  key = &ticket_keys->keys[1];
  CU_ASSERT(0 == memcmp("6..............7", key->name, sizeof(key->name)));
  CU_ASSERT(0 ==
            memcmp("8..............9", key->aes_key, sizeof(key->aes_key)));
  CU_ASSERT(0 ==
            memcmp("a..............b", key->hmac_key, sizeof(key->hmac_key)));
}

void test_shrpx_config_match_downstream_addr_group(void) {
  auto groups = std::vector<DownstreamAddrGroup>{
      {"nghttp2.org/"},
      {"nghttp2.org/alpha/bravo/"},
      {"nghttp2.org/alpha/charlie"},
      {"nghttp2.org/delta%3A"},
      {"www.nghttp2.org/"},
      {"[::1]/"},
  };

  CU_ASSERT(0 == match_downstream_addr_group("nghttp2.org", "/", groups, 255));

  // port is removed
  CU_ASSERT(0 ==
            match_downstream_addr_group("nghttp2.org:8080", "/", groups, 255));

  // host is case-insensitive
  CU_ASSERT(4 == match_downstream_addr_group("WWW.nghttp2.org", "/alpha",
                                             groups, 255));

  // path part is case-sensitive
  CU_ASSERT(0 == match_downstream_addr_group("nghttp2.org", "/Alpha/bravo",
                                             groups, 255));

  // unreserved characters are decoded before matching
  CU_ASSERT(1 == match_downstream_addr_group("nghttp2.org", "/alpha/%62ravo/",
                                             groups, 255));

  CU_ASSERT(1 == match_downstream_addr_group(
                     "nghttp2.org", "/alpha/%62ravo/charlie", groups, 255));

  CU_ASSERT(2 == match_downstream_addr_group("nghttp2.org", "/alpha/charlie",
                                             groups, 255));

  // pattern which does not end with '/' must match its entirely.  So
  // this matches to group 0, not group 2.
  CU_ASSERT(0 == match_downstream_addr_group("nghttp2.org", "/alpha/charlie/",
                                             groups, 255));

  // percent-encoding is normalized to upper case hex digits.
  CU_ASSERT(3 == match_downstream_addr_group("nghttp2.org", "/delta%3a", groups,
                                             255));

  // path component is normalized before mathcing
  CU_ASSERT(1 == match_downstream_addr_group(
                     "nghttp2.org", "/alpha/charlie/%2e././bravo/delta/..",
                     groups, 255));

  CU_ASSERT(255 ==
            match_downstream_addr_group("example.org", "/", groups, 255));

  CU_ASSERT(255 == match_downstream_addr_group("", "/", groups, 255));

  CU_ASSERT(255 == match_downstream_addr_group("foo/bar", "/", groups, 255));

  // If path is "*", only match with host + "/".
  CU_ASSERT(0 == match_downstream_addr_group("nghttp2.org", "*", groups, 255));

  CU_ASSERT(5 == match_downstream_addr_group("[::1]", "/", groups, 255));
  CU_ASSERT(5 == match_downstream_addr_group("[::1]:8080", "/", groups, 255));
  CU_ASSERT(255 == match_downstream_addr_group("[::1", "/", groups, 255));
  CU_ASSERT(255 == match_downstream_addr_group("[::1]8000", "/", groups, 255));
}

} // namespace shrpx
