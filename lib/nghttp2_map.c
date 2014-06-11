/*
 * nghttp2 - HTTP/2 C Library
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
#include "nghttp2_map.h"

#include <string.h>

#define INITIAL_TABLE_LENGTH 16

int nghttp2_map_init(nghttp2_map *map)
{
  map->tablelen = INITIAL_TABLE_LENGTH;
  map->table = (nghttp2_map_entry **)calloc(map->tablelen, sizeof(nghttp2_map_entry*));
  if(map->table == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  map->size = 0;

  return 0;
}

void nghttp2_map_free(nghttp2_map *map)
{
  free(map->table);
}

void nghttp2_map_each_free(nghttp2_map *map,
                           int (*func)(nghttp2_map_entry *entry, void *ptr),
                           void *ptr)
{
  size_t i;
  for(i = 0; i < map->tablelen; ++i) {
    nghttp2_map_entry *entry;
    for(entry = map->table[i]; entry;) {
      nghttp2_map_entry *next = entry->next;
      func(entry, ptr);
      entry = next;
    }
    map->table[i] = NULL;
  }
}

int nghttp2_map_each(nghttp2_map *map,
                     int (*func)(nghttp2_map_entry *entry, void *ptr),
                     void *ptr)
{
  int rv;
  size_t i;
  for(i = 0; i < map->tablelen; ++i) {
    nghttp2_map_entry *entry;
    for(entry = map->table[i]; entry; entry = entry->next) {
      rv = func(entry, ptr);
      if(rv != 0) {
        return rv;
      }
    }
  }
  return 0;
}

void nghttp2_map_entry_init(nghttp2_map_entry *entry, key_type key)
{
  entry->key = key;
  entry->next = NULL;
}

/* Same hash function in android HashMap source code. */
/* The |mod| must be power of 2 */
static int32_t hash(int32_t h, int32_t mod)
{
  h ^= (h >> 20) ^ (h >> 12);
  h ^= (h >> 7) ^ (h >> 4);
  return h & (mod - 1);
}

static int insert(nghttp2_map_entry **table, size_t tablelen,
                  nghttp2_map_entry *entry)
{
  int32_t h = hash(entry->key, tablelen);
  if(table[h] == NULL) {
    table[h] = entry;
  } else {
    nghttp2_map_entry *p;
    /* We won't allow duplicated key, so check it out. */
    for(p = table[h]; p; p = p->next) {
      if(p->key == entry->key) {
        return NGHTTP2_ERR_INVALID_ARGUMENT;
      }
    }
    entry->next = table[h];
    table[h] = entry;
  }
  return 0;
}

/* new_tablelen must be power of 2 */
static int resize(nghttp2_map *map, size_t new_tablelen)
{
  size_t i;
  nghttp2_map_entry **new_table;
  new_table = (nghttp2_map_entry **)calloc(new_tablelen, sizeof(nghttp2_map_entry*));
  if(new_table == NULL) {
    return NGHTTP2_ERR_NOMEM;
  }

  for(i = 0; i < map->tablelen; ++i) {
    nghttp2_map_entry *entry;
    for(entry = map->table[i]; entry;) {
      nghttp2_map_entry *next = entry->next;
      entry->next = NULL;
      /* This function must succeed */
      insert(new_table, new_tablelen, entry);
      entry = next;
    }
  }
  free(map->table);
  map->tablelen = new_tablelen;
  map->table = new_table;
  return 0;
}

int nghttp2_map_insert(nghttp2_map *map, nghttp2_map_entry *new_entry)
{
  int rv;
  /* Load factor is 0.75 */
  if((map->size + 1) * 4 > map->tablelen * 3) {
    rv = resize(map, map->tablelen * 2);
    if(rv != 0) {
      return rv;
    }
  }
  rv = insert(map->table, map->tablelen, new_entry);
  if(rv != 0) {
    return rv;
  }
  ++map->size;
  return 0;
}

nghttp2_map_entry* nghttp2_map_find(nghttp2_map *map, key_type key)
{
  int32_t h;
  nghttp2_map_entry *entry;
  h = hash(key, map->tablelen);
  for(entry = map->table[h]; entry; entry = entry->next) {
    if(entry->key == key) {
      return entry;
    }
  }
  return NULL;
}

int nghttp2_map_remove(nghttp2_map *map, key_type key)
{
  int32_t h;
  nghttp2_map_entry *entry, *prev;
  h = hash(key, map->tablelen);
  prev = NULL;
  for(entry = map->table[h]; entry; entry = entry->next) {
    if(entry->key == key) {
      if(prev == NULL) {
        map->table[h] = entry->next;
      } else {
        prev->next = entry->next;
      }
      --map->size;
      return 0;
    }
    prev = entry;
  }
  return NGHTTP2_ERR_INVALID_ARGUMENT;
}

size_t nghttp2_map_size(nghttp2_map *map)
{
  return map->size;
}
