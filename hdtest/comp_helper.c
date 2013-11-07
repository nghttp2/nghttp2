/*
 * nghttp2 - HTTP/2.0 C Library
 *
 * Copyright (c) 2013 Tatsuhiro Tsujikawa
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
#include "comp_helper.h"

static void dump_val(json_t *jent, const char *key, uint8_t *val, size_t len)
{
  if(val == NULL) {
    json_object_set_new(jent, key, json_string("**DEALLOCATED**"));
  } else {
    json_object_set_new(jent, key, json_pack("s#", val, len));
  }
}

json_t* dump_header_table(nghttp2_hd_context *context)
{
  json_t *obj, *entries;
  size_t i;

  obj = json_object();
  entries = json_array();
  for(i = 0; i < context->hd_table.len; ++i) {
    nghttp2_hd_entry *ent = nghttp2_hd_table_get(context, i);
    json_t *outent = json_object();
    json_object_set_new(outent, "index", json_integer(i));
    dump_val(outent, "name", ent->nv.name, ent->nv.namelen);
    dump_val(outent, "value", ent->nv.value, ent->nv.valuelen);
    json_object_set_new(outent, "referenced",
                        json_boolean(ent->flags & NGHTTP2_HD_FLAG_REFSET));
    json_object_set_new(outent, "size",
                        json_integer(ent->nv.namelen + ent->nv.valuelen +
                                     NGHTTP2_HD_ENTRY_OVERHEAD));
    json_array_append_new(entries, outent);
  }
  json_object_set_new(obj, "entries", entries);
  json_object_set_new(obj, "size", json_integer(context->hd_table_bufsize));
  json_object_set_new(obj, "maxSize",
                      json_integer(context->hd_table_bufsize_max));
  if(context->role == NGHTTP2_HD_ROLE_DEFLATE) {
    json_object_set_new(obj, "deflateSize",
                        json_integer(context->deflate_hd_table_bufsize));
    json_object_set_new(obj, "maxDeflateSize",
                        json_integer(context->deflate_hd_table_bufsize_max));
  }
  return obj;
}
