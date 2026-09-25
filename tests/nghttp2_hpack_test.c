/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
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
#include "nghttp2_hpack_test.h"

#include <stdio.h>

#include "nghttp2_hpack.h"
#include "nghttp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_nghttp2_hpack_encoder),
  munit_void_test(test_nghttp2_hpack_encoder_same_indexed_repr),
  munit_void_test(test_nghttp2_hpack_decoder_indexed),
  munit_void_test(test_nghttp2_hpack_decoder_indname_noinc),
  munit_void_test(test_nghttp2_hpack_decoder_indname_inc),
  munit_void_test(test_nghttp2_hpack_decoder_indname_inc_eviction),
  munit_void_test(test_nghttp2_hpack_decoder_newname_noinc),
  munit_void_test(test_nghttp2_hpack_decoder_newname_inc),
  munit_void_test(test_nghttp2_hpack_decoder_clearall_inc),
  munit_void_test(test_nghttp2_hpack_decoder_zero_length_huffman),
  munit_void_test(test_nghttp2_hpack_decoder_expect_table_size_update),
  munit_void_test(test_nghttp2_hpack_decoder_unexpected_table_size_update),
  munit_void_test(test_nghttp2_hpack_ringbuf_reserve),
  munit_void_test(test_nghttp2_hpack_set_max_dtable_capacity),
  munit_void_test(test_nghttp2_hpack_encode_decode),
  munit_void_test(test_nghttp2_hpack_never_index),
  munit_void_test(test_nghttp2_hpack_bound),
  munit_void_test(test_nghttp2_hpack_decode_length),
  munit_void_test(test_nghttp2_hpack_huffman_encode),
  munit_void_test(test_nghttp2_hpack_huffman_decode),
  munit_test_end(),
};

const MunitSuite hpack_suite = {
  .prefix = "/hpack",
  .tests = tests,
};

static void assert_nv_equal(const nghttp2_nv *a, const nghttp2_hpack_nv *b) {
  assert_size(a->namelen, ==, b->name->len);
  assert_memory_equal(a->namelen, a->name, b->name->base);
  assert_size(a->valuelen, ==, b->value->len);
  assert_memory_equal(a->valuelen, a->value, b->value->base);
  assert_int(a->flags & NGHTTP2_NV_FLAG_NEVER_INDEX, ==,
             b->flags & NGHTTP2_NV_FLAG_NEVER_INDEX);
}

static void check_decode_header(nghttp2_hpack_decoder *dec, nghttp2_buf *buf,
                                const nghttp2_nv *nva, size_t nvlen) {
  nghttp2_ssize nread;
  nghttp2_hpack_nv hnv;
  const nghttp2_nv *nv;
  uint8_t flags;
  size_t i = 0;

  for (;;) {
    nread = nghttp2_hpack_decoder_read(dec, &hnv, &flags, buf->pos,
                                       nghttp2_buf_len(buf), 1);

    assert_ptrdiff(0, <=, nread);

    buf->pos += nread;

    if (flags & NGHTTP2_HPACK_DECODE_FLAG_FINAL) {
      break;
    }

    if (flags & NGHTTP2_HPACK_DECODE_FLAG_EMIT) {
      nv = &nva[i++];

      assert_nv_equal(nv, &hnv);

      nghttp2_rcbuf_decref(hnv.name);
      nghttp2_rcbuf_decref(hnv.value);
    }
  }

  assert_size(i, ==, nvlen);

  nghttp2_buf_reset(buf);
}

void test_nghttp2_hpack_encoder(void) {
  static const nghttp2_nv nva1[] = {
    MAKE_NV(":path", "/my-example/index.html"),
    MAKE_NV(":scheme", "https"),
    MAKE_NV("hello", "world"),
  };
  static const nghttp2_nv nva2[] = {
    MAKE_NV(":path", "/script.js"),
    MAKE_NV(":scheme", "https"),
  };
  static const nghttp2_nv nva3[] = {
    MAKE_NV_NEVER_INDEX("cookie", "k1=v1"),
    MAKE_NV_NEVER_INDEX("cookie", "k2=v2"),
    MAKE_NV("via", "proxy"),
  };
  static const nghttp2_nv nva4[] = {
    MAKE_NV(":path", "/style.css"),
    MAKE_NV_NEVER_INDEX("cookie", "k1=v1"),
    MAKE_NV_NEVER_INDEX("cookie", "k1=v1"),
  };
  static const nghttp2_nv nva5[] = {
    MAKE_NV(":path", "/style.css"),
    MAKE_NV("x-nghttp2", ""),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  int rv;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  /* Encode the first header */
  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva1, nghttp2_arraylen(nva1));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva1, nghttp2_arraylen(nva1));

  /* The second headers */
  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva2, nghttp2_arraylen(nva2));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva2, nghttp2_arraylen(nva2));

  /* The third headers, including same header field name, but value is
     not the same. */
  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva3, nghttp2_arraylen(nva3));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva3, nghttp2_arraylen(nva3));

  /* The fourth headers, including duplicate header fields. */
  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva4, nghttp2_arraylen(nva4));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva4, nghttp2_arraylen(nva4));

  /* The fifth headers includes empty value */
  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva5, nghttp2_arraylen(nva5));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva5, nghttp2_arraylen(nva5));

  /* Cleanup */
  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_encoder_same_indexed_repr(void) {
  static const nghttp2_nv nva1[] = {
    MAKE_NV("host", "alpha"),
    MAKE_NV("host", "alpha"),
  };
  static const nghttp2_nv nva2[] = {
    MAKE_NV("host", "alpha"),
    MAKE_NV("host", "alpha"),
    MAKE_NV("host", "alpha"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  int rv;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  /* Encode 2 same headers.  Emit 1 literal reprs and 1 index repr. */
  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva1, nghttp2_arraylen(nva1));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva1, nghttp2_arraylen(nva1));

  /* Encode 3 same headers.  This time, emits 3 index reprs. */
  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva2, nghttp2_arraylen(nva2));

  assert_int(0, ==, rv);
  assert_size(3, ==, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva2, nghttp2_arraylen(nva2));

  /* Cleanup */
  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_decoder_indexed(void) {
  static const nghttp2_nv nva[] = {
    MAKE_NV(":path", "/"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_decoder dec;
  uint8_t rawbuf[256];
  nghttp2_buf buf;
  nghttp2_hpack_nv nv;
  nghttp2_ssize nread;
  uint8_t flags;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  nghttp2_hpack_decoder_init(&dec, mem);

  *buf.last++ = 0x84U;

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  /* index = 0 is error */
  nghttp2_buf_reset(&buf);

  *buf.last++ = 0x80U;

  nread = nghttp2_hpack_decoder_read(&dec, &nv, &flags, buf.pos,
                                     nghttp2_buf_len(&buf), /*fin = */ 1);

  assert_ptrdiff(NGHTTP2_ERR_HPACK_FATAL, ==, nread);

  nghttp2_hpack_decoder_free(&dec);
}

void test_nghttp2_hpack_decoder_indname_noinc(void) {
  static const nghttp2_nv nva[] = {
    /* Huffman */
    MAKE_NV("user-agent", "nghttp2"),
    /* Expecting no huffman */
    MAKE_NV("user-agent", "x"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  size_t i;
  int rv;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  for (i = 0; i < nghttp2_arraylen(nva); ++i) {
    rv = nghttp2_hpack_encoder_write_indname(&enc, &buf, 57, &nva[i],
                                             NGHTTP2_HPACK_WITHOUT_INDEXING);
    assert_int(0, ==, rv);
    assert_size(0, <, nghttp2_buf_len(&buf));

    check_decode_header(&dec, &buf, &nva[i], 1);

    assert_size(0, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  }

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_decoder_indname_inc(void) {
  static const nghttp2_nv nva[] = {
    MAKE_NV("user-agent", "nghttp2"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  int rv;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  rv = nghttp2_hpack_encoder_write_indname(&enc, &buf, 57, &nva[0],
                                           NGHTTP2_HPACK_WITH_INDEXING);

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(1, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  assert_nv_equal(
    &nva[0], *(nghttp2_hpack_nv **)nghttp2_ringbuf_get(&dec.ctx.dtable, 0));

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_decoder_indname_inc_eviction(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  uint8_t value[1025];
  nghttp2_nv nv;
  nghttp2_nv nva[] = {
    MAKE_NV("accept-charset", ""),
    MAKE_NV("accept-encoding", ""),
    MAKE_NV("accept-language", ""),
    MAKE_NV("accept-ranges", ""),
  };
  size_t i;
  int rv;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  memset(value, '0', sizeof(value));
  value[sizeof(value) - 1] = '\0';
  nv = (nghttp2_nv){
    .value = value,
    .valuelen = sizeof(value) - 1,
    .flags = NGHTTP2_NV_FLAG_NONE,
  };

  for (i = 0; i < nghttp2_arraylen(nva); ++i) {
    nva[i].value = nv.value;
    nva[i].valuelen = nv.valuelen;
  };

  rv = nghttp2_hpack_encoder_write_indname(&enc, &buf, 14, &nv,
                                           NGHTTP2_HPACK_WITH_INDEXING);
  assert_int(0, ==, rv);

  rv = nghttp2_hpack_encoder_write_indname(&enc, &buf, 15, &nv,
                                           NGHTTP2_HPACK_WITH_INDEXING);

  assert_int(0, ==, rv);

  rv = nghttp2_hpack_encoder_write_indname(&enc, &buf, 16, &nv,
                                           NGHTTP2_HPACK_WITH_INDEXING);

  assert_int(0, ==, rv);

  rv = nghttp2_hpack_encoder_write_indname(&enc, &buf, 17, &nv,
                                           NGHTTP2_HPACK_WITH_INDEXING);

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(3, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_decoder_newname_noinc(void) {
  static const nghttp2_nv nva[] = {
    /* Expecting huffman for both */
    MAKE_NV("my-long-content-length", "nghttp2"),
    /* Expecting no huffman for both */
    MAKE_NV("x", "y"),
    /* Huffman for key only */
    MAKE_NV("my-long-content-length", "y"),
    /* Huffman for value only */
    MAKE_NV("x", "nghttp2"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  size_t i;
  int rv;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  for (i = 0; i < nghttp2_arraylen(nva); ++i) {
    rv = nghttp2_hpack_encoder_write_newname(&enc, &buf, &nva[i],
                                             NGHTTP2_HPACK_WITHOUT_INDEXING);

    assert_int(0, ==, rv);
    assert_size(0, <, nghttp2_buf_len(&buf));

    check_decode_header(&dec, &buf, &nva[i], 1);

    assert_size(0, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  }

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_decoder_newname_inc(void) {
  static const nghttp2_nv nva[] = {
    MAKE_NV("x-rel", "nghttp2"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  int rv;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  rv = nghttp2_hpack_encoder_write_newname(&enc, &buf, &nva[0],
                                           NGHTTP2_HPACK_WITH_INDEXING);

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(1, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  assert_nv_equal(
    &nva[0], *(nghttp2_hpack_nv **)nghttp2_ringbuf_get(&dec.ctx.dtable, 0));

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_decoder_clearall_inc(void) {
  static const char hd_name[] = "alpha";
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  nghttp2_nv nv;
  uint8_t value[4061];
  int rv;

  /* Total 4097 bytes space required to hold this entry */
  memset(value, '0', sizeof(value));
  value[sizeof(value) - 1] = '\0';

  nv = (nghttp2_nv){
    .name = (uint8_t *)hd_name,
    .value = value,
    .namelen = nghttp2_strlen_lit(hd_name),
    .valuelen = sizeof(value) - 1,
    .flags = NGHTTP2_NV_FLAG_NONE,
  };

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  rv = nghttp2_hpack_encoder_write_newname(&enc, &buf, &nv,
                                           NGHTTP2_HPACK_WITH_INDEXING);

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, &nv, 1);

  assert_size(0, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));

  /* Do it again */
  rv = nghttp2_hpack_encoder_write_newname(&enc, &buf, &nv,
                                           NGHTTP2_HPACK_WITH_INDEXING);

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, &nv, 1);

  assert_size(0, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));

  /* This time, 4096 bytes space required, which is just fits in the
     header table */
  nv.valuelen = sizeof(value) - 2;

  rv = nghttp2_hpack_encoder_write_newname(&enc, &buf, &nv,
                                           NGHTTP2_HPACK_WITH_INDEXING);

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, &nv, 1);

  assert_size(1, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_decoder_zero_length_huffman(void) {
  static const nghttp2_nv nva[] = {
    MAKE_NV("x", ""),
  };
  /* Literal header with indexing - new name */
  static const uint8_t data[] = {0x40, 0x01, 0x78 /* 'x' */, 0x80};
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;

  nghttp2_buf_wrap_init(&buf, (uint8_t *)data, sizeof(data));
  buf.last += sizeof(data);

  nghttp2_hpack_decoder_init(&dec, mem);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  nghttp2_hpack_decoder_free(&dec);
}

void test_nghttp2_hpack_decoder_expect_table_size_update(void) {
  static const nghttp2_nv nva[] = {
    MAKE_NV(":method", "GET"),
  };
  /* Indexed Header: :method: GET */
  static const uint8_t data[] = {0x82};
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  nghttp2_ssize nread;
  nghttp2_hpack_nv nv;
  uint8_t flags;

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  /* This will make encoder require table size update in the next
     inflation. */
  nghttp2_hpack_decoder_init(&dec, mem);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 4095);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 4096);

  nread = nghttp2_hpack_decoder_read(&dec, &nv, &flags, data, sizeof(data),
                                     /* fin = */ 1);

  assert_ptrdiff(NGHTTP2_ERR_HPACK_FATAL, ==, nread);

  nghttp2_hpack_decoder_free(&dec);

  /* This does not require for encoder to emit table size update since
   * size is not changed. */
  nghttp2_hpack_decoder_init(&dec, mem);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 4096);

  nghttp2_buf_wrap_init(&buf, (uint8_t *)data, sizeof(data));
  buf.last += sizeof(data);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  nghttp2_hpack_decoder_free(&dec);

  /* This does not require for encoder to emit table size update since
     new size is larger than current size. */
  nghttp2_hpack_decoder_init(&dec, mem);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 4097);

  nghttp2_buf_wrap_init(&buf, (uint8_t *)data, sizeof(data));
  buf.last += sizeof(data);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  nghttp2_hpack_decoder_free(&dec);

  /* Received table size is strictly larger than minimum table size */
  nghttp2_hpack_decoder_init(&dec, mem);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 111);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 4096);

  nghttp2_buf_init(&buf);
  nghttp2_hpack_encoder_write_table_size(&enc, &buf, 112);

  nread = nghttp2_hpack_decoder_read(&dec, &nv, &flags, buf.pos,
                                     nghttp2_buf_len(&buf),
                                     /* fin = */ 1);

  assert_ptrdiff(NGHTTP2_ERR_HPACK_FATAL, ==, nread);

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);

  /* Receiving 2 table size updates, min and last value */
  nghttp2_hpack_decoder_init(&dec, mem);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 111);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 4096);

  nghttp2_buf_init(&buf);
  nghttp2_hpack_encoder_write_table_size(&enc, &buf, 111);
  nghttp2_hpack_encoder_write_table_size(&enc, &buf, 4096);

  check_decode_header(&dec, &buf, NULL, 0);

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);

  /* 2nd update is larger than last value */
  nghttp2_hpack_decoder_init(&dec, mem);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 111);
  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 4095);

  nghttp2_buf_init(&buf);
  nghttp2_hpack_encoder_write_table_size(&enc, &buf, 111);
  nghttp2_hpack_encoder_write_table_size(&enc, &buf, 4096);

  nread = nghttp2_hpack_decoder_read(&dec, &nv, &flags, buf.pos,
                                     nghttp2_buf_len(&buf),
                                     /* fin = */ 1);

  assert_ptrdiff(NGHTTP2_ERR_HPACK_FATAL, ==, nread);

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);

  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_decoder_unexpected_table_size_update(void) {
  /* Indexed Header: :method: GET, followed by table size update.
     This violates RFC 7541. */
  static const uint8_t data[] = {0x82, 0x20};
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_decoder dec;
  uint8_t flags;
  nghttp2_ssize nread;
  nghttp2_hpack_nv nv;
  nghttp2_buf buf;

  nghttp2_buf_wrap_init(&buf, (uint8_t *)data, sizeof(data));
  buf.last += sizeof(data);

  nghttp2_hpack_decoder_init(&dec, mem);

  nread = nghttp2_hpack_decoder_read(&dec, &nv, &flags, buf.pos,
                                     nghttp2_buf_len(&buf),
                                     /* fin = */ 0);

  assert_ptrdiff(0, <, nread);
  assert_true(flags & NGHTTP2_HPACK_DECODE_FLAG_EMIT);

  buf.pos += nread;

  nread = nghttp2_hpack_decoder_read(&dec, &nv, &flags, buf.pos,
                                     nghttp2_buf_len(&buf),
                                     /* fin = */ 0);

  assert_ptrdiff(NGHTTP2_ERR_HPACK_FATAL, ==, nread);

  nghttp2_hpack_decoder_free(&dec);
}

void test_nghttp2_hpack_ringbuf_reserve(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_nv nv;
  nghttp2_buf buf;
  uint32_t i;
  int rv;

  nghttp2_buf_init(&buf);

  nv = (nghttp2_nv){
    .name = (uint8_t *)"a",
    .value = nghttp2_mem_calloc(mem, 4 + 1, 1),
    .namelen = 1,
    .valuelen = 4,
    .flags = NGHTTP2_NV_FLAG_NONE,
  };

  nghttp2_hpack_encoder_init(&enc, 8000, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 8000);
  nghttp2_hpack_encoder_set_max_dtable_capacity(&enc, 8000);

  for (i = 0; i < 150; ++i) {
    memcpy((uint8_t *)nv.value, &i, sizeof(i));
    rv = nghttp2_hpack_encoder_write(&enc, &buf, &nv, 1);

    assert_int(0, ==, rv);
    assert_size(0, <, nghttp2_buf_len(&buf));

    check_decode_header(&dec, &buf, &nv, 1);
  }

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);

  nghttp2_mem_free(mem, (uint8_t *)nv.value);
}

void test_nghttp2_hpack_set_max_dtable_capacity(void) {
  static const nghttp2_nv nva[] = {
    MAKE_NV("alpha", "bravo"),
    MAKE_NV("charlie", "delta"),
  };
  static const nghttp2_nv nva2[] = {
    MAKE_NV(":path", "/"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  nghttp2_ssize nread;
  nghttp2_hpack_nv nv;
  int rv;
  uint8_t flags;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  /* encoder changes notifies 8000 max header table size */
  rv = nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 8000);

  assert_int(0, ==, rv);

  nghttp2_hpack_encoder_set_max_dtable_capacity(&enc, 8000);

  assert_size(4096, ==, enc.ctx.max_dtable_capacity);
  assert_size(4096, ==, dec.ctx.max_dtable_capacity);
  assert_size(8000, ==, dec.ctx.hard_max_dtable_capacity);

  /* This will emit encoding context update with header table size
     4096 */
  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva, nghttp2_arraylen(nva));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));
  assert_size(2, ==, nghttp2_ringbuf_len(&enc.ctx.dtable));
  assert_size(4096, ==, enc.ctx.max_dtable_capacity);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(2, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  assert_size(4096, ==, dec.ctx.max_dtable_capacity);
  assert_size(8000, ==, dec.ctx.hard_max_dtable_capacity);

  /* encoder changes header table size to 1024 */
  rv = nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 1024);

  assert_int(0, ==, rv);

  nghttp2_hpack_encoder_set_max_dtable_capacity(&enc, 1024);

  assert_size(1024, ==, enc.ctx.max_dtable_capacity);
  assert_size(1024, ==, dec.ctx.max_dtable_capacity);
  assert_size(1024, ==, dec.ctx.hard_max_dtable_capacity);

  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva, nghttp2_arraylen(nva));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));
  assert_size(2, ==, nghttp2_ringbuf_len(&enc.ctx.dtable));
  assert_size(1024, ==, enc.ctx.max_dtable_capacity);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(2, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  assert_size(1024, ==, dec.ctx.max_dtable_capacity);
  assert_size(1024, ==, dec.ctx.hard_max_dtable_capacity);

  /* inflater changes header table size to 0 */
  rv = nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 0);

  assert_int(0, ==, rv);

  nghttp2_hpack_encoder_set_max_dtable_capacity(&enc, 0);

  assert_size(0, ==, nghttp2_ringbuf_len(&enc.ctx.dtable));
  assert_size(0, ==, enc.ctx.max_dtable_capacity);
  assert_size(0, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  assert_size(0, ==, dec.ctx.max_dtable_capacity);
  assert_size(0, ==, dec.ctx.hard_max_dtable_capacity);

  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva, nghttp2_arraylen(nva));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));
  assert_size(0, ==, nghttp2_ringbuf_len(&enc.ctx.dtable));
  assert_size(0, ==, enc.ctx.max_dtable_capacity);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(0, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  assert_size(0, ==, dec.ctx.max_dtable_capacity);
  assert_size(0, ==, dec.ctx.hard_max_dtable_capacity);

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);

  /* Check table buffer is expanded */
  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, 8192, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  /* First decoder changes header table size to 8000 */
  rv = nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 8000);

  assert_int(0, ==, rv);

  nghttp2_hpack_encoder_set_max_dtable_capacity(&enc, 8000);

  assert_size(8000, ==, enc.ctx.max_dtable_capacity);
  assert_size(4096, ==, dec.ctx.max_dtable_capacity);
  assert_size(8000, ==, dec.ctx.hard_max_dtable_capacity);

  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva, nghttp2_arraylen(nva));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));
  assert_size(2, ==, nghttp2_ringbuf_len(&enc.ctx.dtable));
  assert_size(8000, ==, enc.ctx.max_dtable_capacity);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(2, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  assert_size(8000, ==, dec.ctx.max_dtable_capacity);
  assert_size(8000, ==, dec.ctx.hard_max_dtable_capacity);

  rv = nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 16383);

  assert_int(0, ==, rv);

  nghttp2_hpack_encoder_set_max_dtable_capacity(&enc, 16383);

  assert_size(8192, ==, enc.ctx.max_dtable_capacity);
  assert_size(8000, ==, dec.ctx.max_dtable_capacity);
  assert_size(16383, ==, dec.ctx.hard_max_dtable_capacity);

  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva, nghttp2_arraylen(nva));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));
  assert_size(2, ==, nghttp2_ringbuf_len(&enc.ctx.dtable));
  assert_size(8192, ==, enc.ctx.max_dtable_capacity);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(2, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  assert_size(8192, ==, dec.ctx.max_dtable_capacity);
  assert_size(16383, ==, dec.ctx.hard_max_dtable_capacity);

  /* Lastly, check the error condition */

  rv = nghttp2_hpack_encoder_write_table_size(&enc, &buf, 25600);

  assert_int(0, ==, rv);

  nread = nghttp2_hpack_decoder_read(&dec, &nv, &flags, buf.pos,
                                     nghttp2_buf_len(&buf), /* fin = */ 0);

  assert_ptrdiff(NGHTTP2_ERR_HPACK_FATAL, ==, nread);

  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);

  /* Check that encoder can handle the case where its allowable buffer
     size is less than default size, 4096 */
  nghttp2_buf_reset(&buf);
  nghttp2_hpack_encoder_init(&enc, 1024, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  assert_size(1024, ==, enc.ctx.max_dtable_capacity);
  assert_size(1024, ==, enc.ctx.hard_max_dtable_capacity);

  /* This emits context update with buffer size 1024 */
  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva, nghttp2_arraylen(nva));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));
  assert_size(2, ==, nghttp2_ringbuf_len(&enc.ctx.dtable));
  assert_size(1024, ==, enc.ctx.max_dtable_capacity);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(2, ==, nghttp2_ringbuf_len(&dec.ctx.dtable));
  assert_size(1024, ==, dec.ctx.max_dtable_capacity);
  assert_size(4096, ==, dec.ctx.hard_max_dtable_capacity);

  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);

  /* Check that table size UINT32_MAX can be received */
  nghttp2_hpack_encoder_init(&enc, UINT32_MAX, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  rv = nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, UINT32_MAX);

  assert_int(0, ==, rv);

  nghttp2_hpack_encoder_set_max_dtable_capacity(&enc, UINT32_MAX);

  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva, nghttp2_arraylen(nva));

  assert_int(0, ==, rv);
  assert_size(UINT32_MAX, ==, enc.ctx.max_dtable_capacity);

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  assert_size(UINT32_MAX, ==, dec.ctx.max_dtable_capacity);
  assert_size(UINT32_MAX, ==, dec.ctx.hard_max_dtable_capacity);

  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);

  /* Check that context update emitted twice */
  nghttp2_hpack_encoder_init(&enc, 4096, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  rv = nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 0);

  assert_int(0, ==, rv);

  rv = nghttp2_hpack_decoder_set_max_dtable_capacity(&dec, 3000);

  assert_int(0, ==, rv);

  nghttp2_hpack_encoder_set_max_dtable_capacity(&enc, 0);
  nghttp2_hpack_encoder_set_max_dtable_capacity(&enc, 3000);

  assert_int(0, ==, rv);
  assert_size(0, ==, enc.min_dtable_capacity);
  assert_size(3000, ==, enc.ctx.max_dtable_capacity);

  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva2, nghttp2_arraylen(nva2));

  assert_int(0, ==, rv);
  assert_size(3, <, nghttp2_buf_len(&buf));
  assert_size(3000, ==, enc.ctx.max_dtable_capacity);
  assert_size(UINT32_MAX, ==, enc.min_dtable_capacity);

  check_decode_header(&dec, &buf, nva2, nghttp2_arraylen(nva2));

  assert_size(3000, ==, dec.ctx.max_dtable_capacity);
  assert_size(3000, ==, dec.ctx.hard_max_dtable_capacity);

  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);

  nghttp2_buf_free(&buf, mem);
}

static void check_encode_decode(nghttp2_hpack_encoder *enc,
                                nghttp2_hpack_decoder *dec,
                                const nghttp2_nv *nva, size_t nvlen,
                                const nghttp2_mem *mem) {
  nghttp2_buf buf;
  int rv;

  nghttp2_buf_init(&buf);

  rv = nghttp2_hpack_encoder_write(enc, &buf, nva, nvlen);

  assert_int(0, ==, rv);

  check_decode_header(dec, &buf, nva, nvlen);

  nghttp2_buf_free(&buf, mem);
}

void test_nghttp2_hpack_encode_decode(void) {
  static const nghttp2_nv nv1[] = {
    MAKE_NV(":status", "200 OK"),
    MAKE_NV("access-control-allow-origin", "*"),
    MAKE_NV("cache-control", "private, max-age=0, must-revalidate"),
    MAKE_NV("content-length", "76073"),
    MAKE_NV("content-type", "text/html"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("server", "Apache"),
    MAKE_NV("vary", "foobar"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "MISS from alphabravo"),
    MAKE_NV("x-cache-action", "MISS"),
    MAKE_NV("x-cache-age", "0"),
    MAKE_NV("x-cache-lookup", "MISS from alphabravo:3128"),
    MAKE_NV("x-lb-nocache", "true"),
  };
  static const nghttp2_nv nv2[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=56682045"),
    MAKE_NV("content-type", "text/css"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Thu, 14 May 2015 07:22:57 GMT"),
    MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:15 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128")};
  static const nghttp2_nv nv3[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=56682072"),
    MAKE_NV("content-type", "text/css"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Thu, 14 May 2015 07:23:24 GMT"),
    MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:13 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  static const nghttp2_nv nv4[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=56682022"),
    MAKE_NV("content-type", "text/css"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Thu, 14 May 2015 07:22:34 GMT"),
    MAKE_NV("last-modified", "Tue, 14 May 2013 07:22:14 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  static const nghttp2_nv nv5[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=4461139"),
    MAKE_NV("content-type", "application/x-javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Mon, 16 Sep 2013 21:34:31 GMT"),
    MAKE_NV("last-modified", "Thu, 05 May 2011 09:15:59 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  static const nghttp2_nv nv6[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=18645951"),
    MAKE_NV("content-type", "application/x-javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Fri, 28 Feb 2014 01:48:03 GMT"),
    MAKE_NV("last-modified", "Tue, 12 Jul 2011 16:02:59 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  static const nghttp2_nv nv7[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=31536000"),
    MAKE_NV("content-type", "application/javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("etag", "\"6807-4dc5b54e0dcc0\""),
    MAKE_NV("expires", "Wed, 21 May 2014 08:32:17 GMT"),
    MAKE_NV("last-modified", "Fri, 10 May 2013 11:18:51 GMT"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  static const nghttp2_nv nv8[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=31536000"),
    MAKE_NV("content-type", "application/javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("etag", "\"41c6-4de7d28585b00\""),
    MAKE_NV("expires", "Thu, 12 Jun 2014 10:00:58 GMT"),
    MAKE_NV("last-modified", "Thu, 06 Jun 2013 14:30:36 GMT"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  static const nghttp2_nv nv9[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=31536000"),
    MAKE_NV("content-type", "application/javascript"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("etag", "\"19d6e-4dc5b35a541c0\""),
    MAKE_NV("expires", "Wed, 21 May 2014 08:32:18 GMT"),
    MAKE_NV("last-modified", "Fri, 10 May 2013 11:10:07 GMT"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  static const nghttp2_nv nv10[] = {
    MAKE_NV(":status", "304 Not Modified"),
    MAKE_NV("age", "0"),
    MAKE_NV("cache-control", "max-age=56682045"),
    MAKE_NV("content-type", "text/css"),
    MAKE_NV("date", "Sat, 27 Jul 2013 06:22:12 GMT"),
    MAKE_NV("expires", "Thu, 14 May 2015 07:22:57 GMT"),
    MAKE_NV("last-modified", "Tue, 14 May 2013 07:21:53 GMT"),
    MAKE_NV("vary", "Accept-Encoding"),
    MAKE_NV("via", "1.1 alphabravo (squid/3.x.x), 1.1 nghttpx"),
    MAKE_NV("x-cache", "HIT from alphabravo"),
    MAKE_NV("x-cache-lookup", "HIT from alphabravo:3128"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  check_encode_decode(&enc, &dec, nv1, nghttp2_arraylen(nv1), mem);
  check_encode_decode(&enc, &dec, nv2, nghttp2_arraylen(nv2), mem);
  check_encode_decode(&enc, &dec, nv3, nghttp2_arraylen(nv3), mem);
  check_encode_decode(&enc, &dec, nv4, nghttp2_arraylen(nv4), mem);
  check_encode_decode(&enc, &dec, nv5, nghttp2_arraylen(nv5), mem);
  check_encode_decode(&enc, &dec, nv6, nghttp2_arraylen(nv6), mem);
  check_encode_decode(&enc, &dec, nv7, nghttp2_arraylen(nv7), mem);
  check_encode_decode(&enc, &dec, nv8, nghttp2_arraylen(nv8), mem);
  check_encode_decode(&enc, &dec, nv9, nghttp2_arraylen(nv9), mem);
  check_encode_decode(&enc, &dec, nv10, nghttp2_arraylen(nv10), mem);

  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_never_index(void) {
  /* 1st :method: GET can be indexable, last one is not */
  static const nghttp2_nv nva[] = {
    MAKE_NV(":method", "GET"),
    MAKE_NV_NEVER_INDEX(":method", "POST"),
    MAKE_NV_NEVER_INDEX(":path", "/foo"),
    MAKE_NV_NEVER_INDEX("version", "HTTP/1.1"),
    MAKE_NV_NEVER_INDEX(":method", "GET"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_hpack_decoder dec;
  nghttp2_buf buf;
  int rv;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);
  nghttp2_hpack_decoder_init(&dec, mem);

  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva, nghttp2_arraylen(nva));

  assert_int(0, ==, rv);
  assert_size(0, <, nghttp2_buf_len(&buf));

  check_decode_header(&dec, &buf, nva, nghttp2_arraylen(nva));

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_decoder_free(&dec);
  nghttp2_hpack_encoder_free(&enc);
}

void test_nghttp2_hpack_bound(void) {
  static const nghttp2_nv nva[] = {
    MAKE_NV(":method", "GET"),
    MAKE_NV("alpha", "bravo"),
  };
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_hpack_encoder enc;
  nghttp2_buf buf;
  size_t bound, bound2;
  int rv;

  nghttp2_buf_init(&buf);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_DTABLE_CAPACITY, mem);

  bound = nghttp2_hpack_bound(nva, nghttp2_arraylen(nva));

  assert_size(12 + 6 * 2 * 2 + nva[0].namelen + nva[0].valuelen +
                nva[1].namelen + nva[1].valuelen,
              ==, bound);

  rv = nghttp2_hpack_encoder_write(&enc, &buf, nva, nghttp2_arraylen(nva));

  assert_int(0, ==, rv);
  assert_size(nghttp2_buf_len(&buf), <, bound);

  bound2 = nghttp2_hpack_bound(nva, nghttp2_arraylen(nva));

  assert_size(bound, ==, bound2);

  nghttp2_buf_free(&buf, mem);
  nghttp2_hpack_encoder_free(&enc);
}

static size_t encode_length(uint8_t *buf, uint64_t n, size_t prefix) {
  size_t k = (size_t)((1 << prefix) - 1);
  size_t len = 0;

  *buf = (uint8_t)(*buf & ~k);

  if (n >= k) {
    *buf = (uint8_t)(*buf | k);
    ++buf;
    n -= k;
    ++len;
  } else {
    *buf = (uint8_t)(*buf | n);
    ++buf;

    return 1;
  }

  do {
    ++len;

    if (n >= 128) {
      *buf = (uint8_t)((1 << 7) | (n & 0x7F));
      ++buf;
      n >>= 7;
    } else {
      *buf++ = (uint8_t)n;
      break;
    }
  } while (n);

  return len;
}

void test_nghttp2_hpack_decode_length(void) {
  uint32_t out;
  size_t shift;
  int fin;
  uint8_t buf[16];
  uint8_t *bufp;
  size_t len;
  nghttp2_ssize nread;
  size_t i;

  memset(buf, 0, sizeof(buf));
  len = encode_length(buf, UINT32_MAX, 7);

  nread =
    nghttp2_hpack_decode_length(&out, &shift, &fin, 0, 0, buf, buf + len, 7);

  assert_ptrdiff((nghttp2_ssize)len, ==, nread);
  assert_true(fin);
  assert_uint32(UINT32_MAX, ==, out);

  /* Make sure that we can decode integer if we feed 1 byte at a
     time */
  out = 0;
  shift = 0;
  fin = 0;
  bufp = buf;

  for (i = 0; i < len; ++i, ++bufp) {
    nread = nghttp2_hpack_decode_length(&out, &shift, &fin, out, shift, bufp,
                                        bufp + 1, 7);

    assert_ptrdiff(1, ==, nread);

    if (fin) {
      break;
    }
  }

  assert_size(len - 1, ==, i);
  assert_true(fin);
  assert_size(UINT32_MAX, ==, out);

  /* Check overflow case */
  memset(buf, 0, sizeof(buf));
  len = encode_length(buf, 1ll << 32, 7);

  nread =
    nghttp2_hpack_decode_length(&out, &shift, &fin, 0, 0, buf, buf + len, 7);

  assert_ptrdiff(-1, ==, nread);

  /* Check the case that shift goes beyond 32 bits */
  buf[0] = 255;
  buf[1] = 128;
  buf[2] = 128;
  buf[3] = 128;
  buf[4] = 128;
  buf[5] = 128;
  buf[6] = 1;

  nread =
    nghttp2_hpack_decode_length(&out, &shift, &fin, 0, 0, buf, buf + 7, 8);

  assert_ptrdiff(-1, ==, nread);
}

void test_nghttp2_hpack_huffman_encode(void) {
  static const uint8_t t1[] = {22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
                               10, 9,  8,  7,  6,  5,  4,  3,  2,  1,  0};
  nghttp2_hpack_huffman_decode_context ctx;
  uint8_t out[256];
  uint8_t rawbuf[256];
  nghttp2_buf buf;
  nghttp2_ssize nwrite;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  buf.last = nghttp2_hpack_huffman_encode(buf.last, t1, sizeof(t1));

  assert_size(0, <, nghttp2_buf_len(&buf));

  nghttp2_hpack_huffman_decode_context_init(&ctx);

  nwrite =
    nghttp2_hpack_huffman_decode(&ctx, out, buf.pos, nghttp2_buf_len(&buf), 1);

  assert_ptrdiff(0, <, nwrite);
  assert_memn_equal(t1, sizeof(t1), out, (size_t)nwrite);
}

void test_nghttp2_hpack_huffman_decode(void) {
  static const uint8_t e[] = {0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  nghttp2_hpack_huffman_decode_context ctx;
  uint8_t out[256];
  nghttp2_ssize nwrite;

  nghttp2_hpack_huffman_decode_context_init(&ctx);

  nwrite = nghttp2_hpack_huffman_decode(&ctx, out, e, 1, 1);

  assert_ptrdiff(1, ==, nwrite);
  assert_memn_equal("a", 1, out, (size_t)nwrite);

  /* Premature sequence must elicit decoding error */
  nghttp2_hpack_huffman_decode_context_init(&ctx);

  nwrite = nghttp2_hpack_huffman_decode(&ctx, out, e, 2, 1);

  assert_ptrdiff(NGHTTP2_ERR_HPACK_FATAL, ==, nwrite);

  /* Fully decoding EOS is error */
  nghttp2_hpack_huffman_decode_context_init(&ctx);

  nwrite = nghttp2_hpack_huffman_decode(&ctx, out, e, 2, 6);

  assert_ptrdiff(NGHTTP2_ERR_HPACK_FATAL, ==, nwrite);

  /* Check failure state */
  nghttp2_hpack_huffman_decode_context_init(&ctx);

  nwrite = nghttp2_hpack_huffman_decode(&ctx, out, e, 5, 0);

  assert_ptrdiff(0, <, nwrite);
  assert_true(nghttp2_hpack_huffman_decode_failure_state(&ctx));
}
