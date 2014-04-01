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
#include "nghttp2_priority_spec.h"

void nghttp2_priority_spec_group_init(nghttp2_priority_spec *pri_spec,
                                      int32_t pri_group_id, int32_t weight)
{
  pri_spec->pri_type = NGHTTP2_PRIORITY_TYPE_GROUP;
  pri_spec->group.pri_group_id = pri_group_id;
  pri_spec->group.weight = weight;
}

void nghttp2_priority_spec_dep_init(nghttp2_priority_spec *pri_spec,
                                    int32_t stream_id, int exclusive)
{
  pri_spec->pri_type = NGHTTP2_PRIORITY_TYPE_DEP;
  pri_spec->dep.stream_id = stream_id;
  pri_spec->dep.exclusive = exclusive != 0;
}
