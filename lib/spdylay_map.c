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

static void spdylay_map_entry_free(spdylay_map_entry *entry)
{
  if(entry != NULL) {
    free(entry);
  }
}

static void spdylay_map_entry_free_recur(spdylay_map_entry *entry)
{
  if(entry != NULL) {
    spdylay_map_entry_free_recur(entry->left);
    spdylay_map_entry_free_recur(entry->right);
    free(entry);
  }
}

void spdylay_map_free(spdylay_map *map)
{
  spdylay_map_entry_free_recur(map->root);
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

static spdylay_map_entry* spdylay_map_entry_new(key_type key, void *val)
{
  spdylay_map_entry *entry =
    (spdylay_map_entry*)malloc(sizeof(spdylay_map_entry));
  if(entry != NULL) {
    entry->key = key;
    entry->val = val;
    entry->left = entry->right = NULL;
    entry->priority = hash32shift(key);
  }
  return entry;
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
                                       key_type key, void *val,
                                       int *error)
{
  if(entry == NULL) {
    entry = spdylay_map_entry_new(key, val);
    if(entry == NULL) {
      *error = SPDYLAY_ERR_NOMEM;
    }
  } else if(key == entry->key) {
    *error = SPDYLAY_ERR_INVALID_ARGUMENT;
  } else if(key < entry->key) {
    entry->left = insert_recur(entry->left, key, val, error);
  } else {
    entry->right = insert_recur(entry->right, key, val, error);
  }
  if(entry->left != NULL && entry->priority > entry->left->priority) {
    entry = rotate_right(entry);
  } else if(entry->right != NULL && entry->priority > entry->right->priority) {
    entry = rotate_left(entry);
  }
  return entry;
}

int spdylay_map_insert(spdylay_map *map, key_type key, void *val)
{
  int error = 0;
  map->root = insert_recur(map->root, key, val, &error);
  if(!error) {
    ++map->size;
  }
  return error;
}

void* spdylay_map_find(spdylay_map *map, key_type key)
{
  spdylay_map_entry *entry = map->root;
  while(entry != NULL) {
    if(key < entry->key) {
      entry = entry->left;
    } else if(key > entry->key) {
      entry = entry->right;
    } else {
      return entry->val;
    }
  }
  return NULL;
}

static spdylay_map_entry* erase_rotate_recur(spdylay_map_entry *entry)
{
  if(entry->left == NULL) {
    spdylay_map_entry *right = entry->right;
    spdylay_map_entry_free(entry);
    return right;
  } else if(entry->right == NULL) {
    spdylay_map_entry *left = entry->left;
    spdylay_map_entry_free(entry);
    return left;
  } else if(entry->left->priority < entry->right->priority) {
    entry = rotate_right(entry);
    return erase_rotate_recur(entry->right);
  } else {
    entry = rotate_left(entry);
    return erase_rotate_recur(entry->left);
  }
}

static spdylay_map_entry* erase_recur(spdylay_map_entry *entry, key_type key,
                                      int *error)
{
  if(entry == NULL) {
    *error = SPDYLAY_ERR_INVALID_ARGUMENT;
  } else if(key < entry->key) {
    entry->left = erase_recur(entry->left, key, error);
  } else if(key > entry->key) {
    entry->right = erase_recur(entry->right, key, error);
  } else {
    entry = erase_rotate_recur(entry);
  }
  return entry;
}

void spdylay_map_erase(spdylay_map *map, key_type key)
{
  if(map->root != NULL) {
    int error = 0;
    map->root = erase_recur(map->root, key, &error);
    if(!error) {
      --map->size;
    }
  }
}

size_t spdylay_map_size(spdylay_map *map)
{
  return map->size;
}

static void for_each(spdylay_map_entry *entry,
                     void (*func)(key_type key, void *val, void *ptr),
                     void *ptr)
{
  if(entry != NULL) {
    for_each(entry->left, func, ptr);
    func(entry->key, entry->val, ptr);
    for_each(entry->right, func, ptr);
  }
}

void spdylay_map_each(spdylay_map *map,
                      void (*func)(key_type key, void *val, void *ptr),
                      void *ptr)
{
  for_each(map->root, func, ptr);
}
