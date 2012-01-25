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
#ifndef SPDYLAY_MAP_H
#define SPDYLAY_MAP_H

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <spdylay/spdylay.h>
#include "spdylay_int.h"

/* Implementation of ordered map */

typedef uint32_t key_type;
typedef uint32_t pri_type;

typedef struct spdylay_map_entry {
  key_type key;
  void *val;
  struct spdylay_map_entry *left, *right;
  pri_type priority;
} spdylay_map_entry;

typedef struct {
  spdylay_map_entry *root;
  size_t size;
} spdylay_map;

int spdylay_map_init(spdylay_map *map);

void spdylay_map_free(spdylay_map *map);

int spdylay_map_insert(spdylay_map *map, key_type key, void *val);

void* spdylay_map_find(spdylay_map *map, key_type key);

void spdylay_map_erase(spdylay_map *map, key_type key);

size_t spdylay_map_size(spdylay_map *map);

void spdylay_map_each(spdylay_map *map, void (*func)(key_type key, void *val));

#endif /* SPDYLAY_MAP_H */
