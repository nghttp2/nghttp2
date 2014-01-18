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
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include <jansson.h>

#include "nghttp2_hd.h"
#include "nghttp2_frame.h"

#include "comp_helper.h"

typedef struct {
  size_t table_size;
  int dump_header_table;
} inflate_config;

static inflate_config config;

static uint8_t to_ud(char c)
{
  if(c >= 'A' && c <= 'Z') {
    return c - 'A' + 10;
  } else if(c >= 'a' && c <= 'z') {
    return c - 'a' + 10;
  } else {
    return c - '0';
  }
}

static void decode_hex(uint8_t *dest, const char *src, size_t len)
{
  size_t i;
  for(i = 0; i < len; i += 2) {
    *dest++ = to_ud(src[i]) << 4 | to_ud(src[i + 1]);
  }
}

static void to_json(nghttp2_hd_context *inflater,
                    json_t *headers, json_t *wire, int seq)
{
  json_t *obj;

  obj = json_object();
  json_object_set_new(obj, "seq", json_integer(seq));
  json_object_set(obj, "wire", wire);
  json_object_set(obj, "headers", headers);
  json_object_set_new(obj, "header_table_size",
                      json_integer(inflater->hd_table_bufsize_max));
  if(config.dump_header_table) {
    json_object_set_new(obj, "header_table", dump_header_table(inflater));
  }
  json_dumpf(obj, stdout, JSON_INDENT(2) | JSON_PRESERVE_ORDER);
  json_decref(obj);
  printf("\n");
}

static int inflate_hd(json_t *obj, nghttp2_hd_context *inflater, int seq)
{
  json_t *wire, *table_size, *headers;
  size_t inputlen;
  uint8_t *buf, *p;
  size_t buflen;
  ssize_t rv;
  nghttp2_nv nv;
  int final;

  wire = json_object_get(obj, "wire");
  if(wire == NULL) {
    fprintf(stderr, "'wire' key is missing at %d\n", seq);
    return -1;
  }
  table_size = json_object_get(obj, "header_table_size");
  if(table_size) {
    if(!json_is_integer(table_size)) {
      fprintf(stderr,
              "The value of 'header_table_size key' is not integer at %d\n",
              seq);
      return -1;
    }
    rv = nghttp2_hd_change_table_size(inflater,
                                      json_integer_value(table_size));
    if(rv != 0) {
      fprintf(stderr,
              "nghttp2_hd_change_table_size() failed with error %s at %d\n",
              nghttp2_strerror(rv), seq);
      return -1;
    }
  }
  inputlen = strlen(json_string_value(wire));
  if(inputlen & 1) {
    fprintf(stderr, "Badly formatted output value at %d\n", seq);
    exit(EXIT_FAILURE);
  }
  buflen = inputlen / 2;
  buf = malloc(buflen);
  decode_hex(buf, json_string_value(wire), inputlen);

  headers = json_array();

  p = buf;
  for(;;) {
    rv = nghttp2_hd_inflate_hd(inflater, &nv, &final, p, buflen);
    if(rv < 0) {
      fprintf(stderr, "inflate failed with error code %zd at %d\n", rv, seq);
      exit(EXIT_FAILURE);
    }
    p += rv;
    buflen -= rv;
    if(final) {
      break;
    }
    json_array_append_new(headers, dump_header(nv.name, nv.namelen,
                                               nv.value, nv.valuelen));
  }
  assert(buflen == 0);
  nghttp2_hd_inflate_end_headers(inflater);
  to_json(inflater, headers, wire, seq);
  json_decref(headers);
  free(buf);
  return 0;
}

static int perform(void)
{
  nghttp2_hd_context inflater;
  size_t i;
  json_t *json, *cases;
  json_error_t error;
  size_t len;
  nghttp2_hd_side side;

  json = json_loadf(stdin, 0, &error);
  if(json == NULL) {
    fprintf(stderr, "JSON loading failed\n");
    exit(EXIT_FAILURE);
  }
  if(strcmp("request", json_string_value(json_object_get(json, "context")))
     == 0) {
    side = NGHTTP2_HD_SIDE_REQUEST;
  } else {
    side = NGHTTP2_HD_SIDE_RESPONSE;
  }
  cases = json_object_get(json, "cases");
  if(cases == NULL) {
    fprintf(stderr, "Missing 'cases' key in root object\n");
    exit(EXIT_FAILURE);
  }
  if(!json_is_array(cases)) {
    fprintf(stderr, "'cases' must be JSON array\n");
    exit(EXIT_FAILURE);
  }
  nghttp2_hd_inflate_init(&inflater, side);
  nghttp2_hd_change_table_size(&inflater, config.table_size);

  output_json_header(side);
  len = json_array_size(cases);
  for(i = 0; i < len; ++i) {
    json_t *obj = json_array_get(cases, i);
    if(!json_is_object(obj)) {
      fprintf(stderr, "Unexpected JSON type at %zu. It should be object.\n",
              i);
      continue;
    }
    if(inflate_hd(obj, &inflater, i) != 0) {
      continue;
    }
    if(i + 1 < len) {
      printf(",\n");
    }
  }
  output_json_footer();
  nghttp2_hd_inflate_free(&inflater);
  json_decref(json);
  return 0;
}

static void print_help(void)
{
  printf("HPACK HTTP/2.0 header decoder\n"
         "Usage: inflatehd [OPTIONS] < INPUT\n"
         "\n"
         "Reads JSON data from stdin and outputs inflated name/value pairs\n"
         "in JSON.\n"
         "\n"
         "The root JSON object must contain \"context\" key, which indicates\n"
         "which compression context is used. If it is \"request\", request\n"
         "compression context is used. Otherwise, response compression\n"
         "context is used. The value of \"cases\" key contains the sequence\n"
         "of compressed header block. They share the same compression\n"
         "context and are processed in the order they appear. Each item in\n"
         "the sequence is a JSON object and it must have at least \"wire\"\n"
         "key. Its value is a string containing compressed header block in\n"
         "hex string.\n"
         "\n"
         "Example:\n"
         "{\n"
         "  \"context\": \"request\",\n"
         "  \"cases\":\n"
         "  [\n"
         "    { \"wire\": \"0284f77778ff\" },\n"
         "    { \"wire\": \"0185fafd3c3c7f81\" }\n"
         "  ]\n"
         "}\n"
         "\n"
         "The output of this program can be used as input for deflatehd.\n"
         "\n"
         "OPTIONS:\n"
         "    -s, --table-size=<N>\n"
         "                      Set dynamic table size. In the HPACK\n"
         "                      specification, this value is denoted by\n"
         "                      SETTINGS_HEADER_TABLE_SIZE.\n"
         "                      Default: 4096\n"
         "    -d, --dump-header-table\n"
         "                      Output dynamic header table.\n");
}

static struct option long_options[] = {
  {"table-size", required_argument, NULL, 's'},
  {"dump-header-table", no_argument, NULL, 'd'},
  {NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
  char *end;
  config.table_size = NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE;
  config.dump_header_table = 0;
  while(1) {
    int option_index = 0;
    int c = getopt_long(argc, argv, "dhs:", long_options, &option_index);
    if(c == -1) {
      break;
    }
    switch(c) {
    case 'h':
      print_help();
      exit(EXIT_SUCCESS);
    case 's':
      /* --table-size */
      errno = 0;
      config.table_size = strtoul(optarg, &end, 10);
      if(errno == ERANGE || *end != '\0') {
        fprintf(stderr, "-s: Bad option value\n");
        exit(EXIT_FAILURE);
      }
      break;
    case 'd':
      /* --dump-header-table */
      config.dump_header_table = 1;
      break;
    case '?':
      exit(EXIT_FAILURE);
    default:
      break;
    }
  }
  perform();
  return 0;
}
