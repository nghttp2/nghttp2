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

/*
 * Initializes the map |map|.
 */
void spdylay_map_init(spdylay_map *map);

/*
 * Deallocates any resources allocated for |map|. The stored items are
 * not freed by this function. Use spdylay_map_each() to free each
 * item.
 */
void spdylay_map_free(spdylay_map *map);

/*
 * Inserts the new item |val| with the key |key| to the map |map|.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error code:
 *
 * SPDYLAY_ERR_INVALID_ARGUMENT
 *     The item associated by |key| already exists.
 *
 * SPDYLAY_ERR_NOMEM
 *     Out of memory.
 */
int spdylay_map_insert(spdylay_map *map, key_type key, void *val);

/*
 * Returns the item associated by the key |key|.  If there is no such
 * item, this function returns NULL.
 */
void* spdylay_map_find(spdylay_map *map, key_type key);

/*
 * Erases the item associated by the key |key|.  The erased item is
 * not freed by this function.
 *
 * This function returns 0 if it succeeds, or one of the following
 * negative error codes:
 *
 * SPDYLAY_ERR_INVALID_ARGUMENT
 *     The item associated by |key| does not exist.
 */
void spdylay_map_erase(spdylay_map *map, key_type key);

/*
 * Returns the number of items stored in the map |map|.
 */
size_t spdylay_map_size(spdylay_map *map);

/*
 * Applies the function |func| to each key/item pair in the map |map|
 * with the optional user supplied pointer |ptr|.  This function is
 * useful to free item in the map.
 */
void spdylay_map_each(spdylay_map *map,
                      void (*func)(key_type key, void *val, void *ptr),
                      void *ptr);

#endif /* SPDYLAY_MAP_H */
