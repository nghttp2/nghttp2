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

typedef struct strentry {
  spdylay_map_entry map_entry;
  const char *str;
} strentry;

static void strentry_init(strentry *entry, key_type key, const char *str)
{
  spdylay_map_entry_init(&entry->map_entry, key);
  entry->str = str;
}

void test_spdylay_map(void)
{
  strentry foo, FOO, bar, baz, shrubbery;
  spdylay_map map;
  spdylay_map_init(&map);

  strentry_init(&foo, 1, "foo");
  strentry_init(&FOO, 1, "FOO");
  strentry_init(&bar, 2, "bar");
  strentry_init(&baz, 3, "baz");
  strentry_init(&shrubbery, 4, "shrubbery");

  CU_ASSERT(0 == spdylay_map_insert(&map, &foo.map_entry));
  CU_ASSERT(strcmp("foo", ((strentry*)spdylay_map_find(&map, 1))->str) == 0);
  CU_ASSERT(1 == spdylay_map_size(&map));

  CU_ASSERT(SPDYLAY_ERR_INVALID_ARGUMENT ==
            spdylay_map_insert(&map, &FOO.map_entry));

  CU_ASSERT(1 == spdylay_map_size(&map));
  CU_ASSERT(strcmp("foo", ((strentry*)spdylay_map_find(&map, 1))->str) == 0);

  CU_ASSERT(0 == spdylay_map_insert(&map, &bar.map_entry));
  CU_ASSERT(2 == spdylay_map_size(&map));

  CU_ASSERT(0 == spdylay_map_insert(&map, &baz.map_entry));
  CU_ASSERT(3 == spdylay_map_size(&map));

  CU_ASSERT(0 == spdylay_map_insert(&map, &shrubbery.map_entry));
  CU_ASSERT(4 == spdylay_map_size(&map));

  CU_ASSERT(strcmp("baz", ((strentry*)spdylay_map_find(&map, 3))->str) == 0);

  spdylay_map_remove(&map, 3);
  CU_ASSERT(3 == spdylay_map_size(&map));
  CU_ASSERT(NULL == spdylay_map_find(&map, 3));

  spdylay_map_remove(&map, 1);
  CU_ASSERT(2 == spdylay_map_size(&map));
  CU_ASSERT(NULL == spdylay_map_find(&map, 1));

  /* Erasing non-existent entry */
  spdylay_map_remove(&map, 1);
  CU_ASSERT(2 == spdylay_map_size(&map));
  CU_ASSERT(NULL == spdylay_map_find(&map, 1));

  CU_ASSERT(strcmp("bar", ((strentry*)spdylay_map_find(&map, 2))->str) == 0);
  CU_ASSERT(strcmp("shrubbery",
                   ((strentry*)spdylay_map_find(&map, 4))->str) == 0);

  spdylay_map_free(&map);
}

static int entry_free(spdylay_map_entry *entry, void *ptr)
{
  free(entry);
  return 0;
}

void test_spdylay_map_each_free(void)
{
  strentry *foo = malloc(sizeof(strentry)),
    *bar = malloc(sizeof(strentry)),
    *baz = malloc(sizeof(strentry)),
    *shrubbery = malloc(sizeof(strentry));
  spdylay_map map;
  spdylay_map_init(&map);

  strentry_init(foo, 1, "foo");
  strentry_init(bar, 2, "bar");
  strentry_init(baz, 3, "baz");
  strentry_init(shrubbery, 4, "shrubbery");

  spdylay_map_insert(&map, &foo->map_entry);
  spdylay_map_insert(&map, &bar->map_entry);
  spdylay_map_insert(&map, &baz->map_entry);
  spdylay_map_insert(&map, &shrubbery->map_entry);

  spdylay_map_each_free(&map, entry_free, NULL);
}
