/*
 * Spdylay - SPDY Library
 *
 * Copyright (c) 2012 Tatsuhiro Tsujikawa
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
#include "spdylay_map_test.h"

#include <CUnit/CUnit.h>

#include "spdylay_map.h"

void test_spdylay_map()
{
  spdylay_map map;
  int i;
  CU_ASSERT(0 == spdylay_map_init(&map));
  CU_ASSERT(0 == spdylay_map_insert(&map, 1, "foo"));
  CU_ASSERT(strcmp("foo", spdylay_map_find(&map, 1)) == 0);
  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT == spdylay_map_insert(&map, 1, "FOO"));
  CU_ASSERT(strcmp("foo", spdylay_map_find(&map, 1)) == 0);
  CU_ASSERT(0 == spdylay_map_insert(&map, 2, "bar"));
  CU_ASSERT(0 == spdylay_map_insert(&map, 3, "baz"));
  CU_ASSERT(0 == spdylay_map_insert(&map, 4, "shrubbery"));
  CU_ASSERT(strcmp("baz", spdylay_map_find(&map, 3)) == 0);

  spdylay_map_erase(&map, 3);
  CU_ASSERT(NULL == spdylay_map_find(&map, 3));
  spdylay_map_erase(&map, 1);
  CU_ASSERT(NULL == spdylay_map_find(&map, 1));

  spdylay_map_erase(&map, 1);
  CU_ASSERT(NULL == spdylay_map_find(&map, 1));

  CU_ASSERT(strcmp("bar", spdylay_map_find(&map, 2)) == 0);
  CU_ASSERT(strcmp("shrubbery", spdylay_map_find(&map, 4)) == 0);

  spdylay_map_free(&map);
}
