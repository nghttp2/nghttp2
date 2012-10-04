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

typedef enum {
  SUB_LEFT = 1,
  SUB_RIGHT = 1 << 1,
  SUB_ALL = (1 << 2) - 1
} spdylay_map_subtr;

void spdylay_map_init(spdylay_map *map)
{
  map->root = NULL;
  map->size = 0;
}

void spdylay_map_free(spdylay_map *map)
{
  map->root = NULL;
}

void spdylay_map_each_free(spdylay_map *map,
                           int (*func)(spdylay_map_entry *entry, void *ptr),
                           void *ptr)
{
  spdylay_map_entry *entry = map->root;
  while(entry) {
    if(entry->flags == SUB_ALL) {
      spdylay_map_entry *parent = entry->parent;
      func(entry, ptr);
      entry = parent;
    } else if(entry->flags == SUB_LEFT) {
      entry->flags |= SUB_RIGHT;
      if(entry->right) {
        entry = entry->right;
      }
    } else {
      entry->flags |= SUB_LEFT;
      if(entry->left) {
        entry = entry->left;
      }
    }
  }
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
  entry->parent = entry->left = entry->right = NULL;
  entry->priority = hash32shift(key);
  entry->flags = 0;
}

static spdylay_map_entry* rotate_left(spdylay_map_entry *entry)
{
  spdylay_map_entry *root = entry->right;
  entry->right = root->left;
  root->left = entry;

  root->parent = entry->parent;
  entry->parent = root;
  if(root->parent) {
    if(root->parent->left == entry) {
      root->parent->left = root;
    } else {
      root->parent->right = root;
    }
  }
  if(entry->right) {
    entry->right->parent = entry;
  }
  return root;
}

static spdylay_map_entry* rotate_right(spdylay_map_entry* entry)
{
  spdylay_map_entry *root = entry->left;
  entry->left = root->right;
  root->right = entry;

  root->parent = entry->parent;
  entry->parent = root;
  if(root->parent) {
    if(root->parent->left == entry) {
      root->parent->left = root;
    } else {
      root->parent->right = root;
    }
  }
  if(entry->left) {
    entry->left->parent = entry;
  }
  return root;
}

int spdylay_map_insert(spdylay_map *map, spdylay_map_entry *new_entry)
{
  spdylay_map_entry *entry = map->root, *parent = NULL;
  if(map->root == NULL) {
    map->root = new_entry;
    map->size = 1;
    return 0;
  }
  /* Find position to insert. */
  while(1) {
    if(new_entry->key == entry->key) {
      return SPDYLAY_ERR_INVALID_ARGUMENT;
    } else {
      if(new_entry->key < entry->key) {
        if(entry->left) {
          entry = entry->left;
        } else {
          parent = entry;
          parent->left = new_entry;
          break;
        }
      } else {
        if(entry->right) {
          entry = entry->right;
        } else {
          parent = entry;
          parent->right = new_entry;
          break;
        }
      }
    }
  }
  new_entry->parent = parent;

  /* Rotate tree to satisfy heap property. */
  for(entry = parent; ; entry = entry->parent) {
    if(entry->left && entry->priority > entry->left->priority) {
      entry = rotate_right(entry);
    } else if(entry->right && entry->priority > entry->right->priority) {
      entry = rotate_left(entry);
    } else {
      /* At this point, tree forms heap. */
      break;
    }
    /* If no parent is assigned, then it is a root node. */
    if(!entry->parent) {
      map->root = entry;
      break;
    }
  }
  ++map->size;
  return 0;
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

int spdylay_map_remove(spdylay_map *map, key_type key)
{
  spdylay_map_entry *entry = map->root;

  if(map->root == NULL) {
    return SPDYLAY_ERR_INVALID_ARGUMENT;
  }
  /* Locate entry to delete. */
  while(entry) {
    if(key < entry->key) {
      entry = entry->left;
    } else if(key > entry->key) {
      entry = entry->right;
    } else {
      break;
    }
  }
  if(!entry) {
    /* Not found */
    return SPDYLAY_ERR_INVALID_ARGUMENT;
  }
  /* Rotate and bubble down to satisfy heap property. */
  for(;;) {
    if(!entry->left) {
      if(!entry->parent) {
        map->root = entry->right;
      } else if(entry->parent->left == entry) {
        entry->parent->left = entry->right;
      } else {
        entry->parent->right = entry->right;
      }
      if(entry->right) {
        entry->right->parent = entry->parent;
      }
      break;
    } else if(!entry->right) {
      if(!entry->parent) {
        map->root = entry->left;
      } else if(entry->parent->left == entry) {
        entry->parent->left = entry->left;
      } else {
        entry->parent->right = entry->left;
      }
      if(entry->left) {
        entry->left->parent = entry->parent;
      }
      break;
    } else if(entry->left->priority < entry->right->priority) {
      entry = rotate_right(entry);
      if(!entry->parent) {
        map->root = entry;
      }
      entry = entry->right;
    } else {
      entry = rotate_left(entry);
      if(!entry->parent) {
        map->root = entry;
      }
      entry = entry->left;
    }
  }
  --map->size;
  return 0;
}

size_t spdylay_map_size(spdylay_map *map)
{
  return map->size;
}

int spdylay_map_each(spdylay_map *map,
                     int (*func)(spdylay_map_entry *entry, void *ptr),
                     void *ptr)
{
  spdylay_map_entry *entry = map->root;
  while(entry) {
    if(entry->flags == SUB_ALL) {
      entry->flags = 0;
      entry = entry->parent;
    } else if(entry->flags == SUB_LEFT) {
      int rv;
      rv = func(entry, ptr);
      if(rv != 0) {
        while(entry) {
          entry->flags = 0;
          entry = entry->parent;
        }
        return rv;
      }
      entry->flags |= SUB_RIGHT;
      if(entry->right) {
        entry = entry->right;
      }
    } else {
      entry->flags |= SUB_LEFT;
      if(entry->left) {
        entry = entry->left;
      }
    }
  }
  return 0;
}
