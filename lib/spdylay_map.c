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
#include "spdylay_map.h"

void spdylay_map_init(spdylay_map *map)
{
  map->root = NULL;
  map->size = 0;
}

static void spdylay_map_entry_free_recur(spdylay_map_entry *entry,
                                         int (*func)(spdylay_map_entry *entry,
                                                     void *ptr),
                                         void *ptr)
{
  if(entry != NULL) {
    spdylay_map_entry_free_recur(entry->left, func, ptr);
    spdylay_map_entry_free_recur(entry->right, func, ptr);
    func(entry, ptr);
  }
}

void spdylay_map_free(spdylay_map *map)
{
  map->root = NULL;
}

void spdylay_map_each_free(spdylay_map *map,
                           int (*func)(spdylay_map_entry *entry, void *ptr),
                           void *ptr)
{
  spdylay_map_entry_free_recur(map->root, func, ptr);
  map->root = NULL;
}

/*
 * 32 bit Mix Functions by Thomas Wang
 *
 * http://www.concentric.net/~Ttwang/tech/inthash.htm
 */
static uint32_t hash32shift(uint32_t key)
{
  key = ~key + (key << 15); /* key = (key << 15) - key - 1; */
  key = key ^ (key >> 12);
  key = key + (key << 2);
  key = key ^ (key >> 4);
  key = key * 2057; /* key = (key + (key << 3)) + (key << 11); */
  key = key ^ (key >> 16);
  return key;
}

void spdylay_map_entry_init(spdylay_map_entry *entry, key_type key)
{
  entry->key = key;
  entry->left = entry->right = NULL;
  entry->priority = hash32shift(key);
}

static spdylay_map_entry* rotate_left(spdylay_map_entry *entry)
{
  spdylay_map_entry *root = entry->right;
  entry->right = root->left;
  root->left = entry;
  return root;
}

static spdylay_map_entry* rotate_right(spdylay_map_entry* entry)
{
  spdylay_map_entry *root = entry->left;
  entry->left = root->right;
  root->right = entry;
  return root;
}

static spdylay_map_entry* insert_recur(spdylay_map_entry *entry,
                                       spdylay_map_entry *new_entry,
                                       int *error)
{
  if(entry == NULL) {
    entry = new_entry;
  } else if(new_entry->key == entry->key) {
    *error = SPDYLAY_ERR_INVALID_ARGUMENT;
  } else if(new_entry->key < entry->key) {
    entry->left = insert_recur(entry->left, new_entry, error);
  } else {
    entry->right = insert_recur(entry->right, new_entry, error);
  }
  if(entry->left != NULL && entry->priority > entry->left->priority) {
    entry = rotate_right(entry);
  } else if(entry->right != NULL && entry->priority > entry->right->priority) {
    entry = rotate_left(entry);
  }
  return entry;
}

int spdylay_map_insert(spdylay_map *map, spdylay_map_entry *new_entry)
{
  int error = 0;
  map->root = insert_recur(map->root, new_entry, &error);
  if(!error) {
    ++map->size;
  }
  return error;
}

spdylay_map_entry* spdylay_map_find(spdylay_map *map, key_type key)
{
  spdylay_map_entry *entry = map->root;
  while(entry != NULL) {
    if(key < entry->key) {
      entry = entry->left;
    } else if(key > entry->key) {
      entry = entry->right;
    } else {
      return entry;
    }
  }
  return NULL;
}

static spdylay_map_entry* remove_rotate_recur(spdylay_map_entry *entry)
{
  if(entry->left == NULL) {
    spdylay_map_entry *right = entry->right;
    return right;
  } else if(entry->right == NULL) {
    spdylay_map_entry *left = entry->left;
    return left;
  } else if(entry->left->priority < entry->right->priority) {
    entry = rotate_right(entry);
    entry->right = remove_rotate_recur(entry->right);
    return entry;
  } else {
    entry = rotate_left(entry);
    entry->left = remove_rotate_recur(entry->left);
    return entry;
  }
}

static spdylay_map_entry* remove_recur(spdylay_map_entry *entry, key_type key,
                                      int *error)
{
  if(entry == NULL) {
    *error = SPDYLAY_ERR_INVALID_ARGUMENT;
  } else if(key < entry->key) {
    entry->left = remove_recur(entry->left, key, error);
  } else if(key > entry->key) {
    entry->right = remove_recur(entry->right, key, error);
  } else {
    entry = remove_rotate_recur(entry);
  }
  return entry;
}

int spdylay_map_remove(spdylay_map *map, key_type key)
{
  if(map->root != NULL) {
    int error = 0;
    map->root = remove_recur(map->root, key, &error);
    if(!error) {
      --map->size;
    }
    return error;
  }
  return SPDYLAY_ERR_INVALID_ARGUMENT;
}

size_t spdylay_map_size(spdylay_map *map)
{
  return map->size;
}

static int for_each(spdylay_map_entry *entry,
                    int (*func)(spdylay_map_entry *entry, void *ptr),
                    void *ptr)
{
  if(entry) {
    int rv;
    if((rv = for_each(entry->left, func, ptr)) != 0 ||
       (rv = func(entry, ptr)) != 0 ||
       (rv = for_each(entry->right, func, ptr)) != 0) {
      return rv;
    }
  }
  return 0;
}

int spdylay_map_each(spdylay_map *map,
                     int (*func)(spdylay_map_entry *entry, void *ptr),
                     void *ptr)
{
  return for_each(map->root, func, ptr);
}
