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
  size_t deflate_table_size;
  nghttp2_hd_side side;
  int http1text;
  int dump_header_table;
  int no_refset;
} deflate_config;

static deflate_config config;

static size_t input_sum;
static size_t output_sum;

static char to_hex_digit(uint8_t n)
{
  if(n > 9) {
    return n - 10 + 'a';
  }
  return n + '0';
}

static void to_hex(char *dest, const uint8_t *src, size_t len)
{
  size_t i;
  for(i = 0; i < len; ++i) {
    *dest++ = to_hex_digit(src[i] >> 4);
    *dest++ = to_hex_digit(src[i] & 0xf);
  }
}

static void output_to_json(nghttp2_hd_deflater *deflater,
                           const uint8_t *buf, size_t len, size_t inputlen,
                           nghttp2_nv *nva, size_t nvlen,
                           int seq)
{
  json_t *obj;
  char *hex = NULL;

  if(len > 0) {
    hex = malloc(len * 2);
  }
  obj = json_object();
  json_object_set_new(obj, "seq", json_integer(seq));
  json_object_set_new(obj, "input_length", json_integer(inputlen));
  json_object_set_new(obj, "output_length", json_integer(len));
  json_object_set_new(obj, "percentage_of_original_size",
                      json_real((double)len / inputlen * 100));
  to_hex(hex, buf, len);
  if(len == 0) {
    json_object_set_new(obj, "wire", json_string(""));
  } else {
    json_object_set_new(obj, "wire", json_pack("s#", hex, len * 2));
  }
  json_object_set_new(obj, "headers", dump_headers(nva, nvlen));
  json_object_set_new(obj, "header_table_size",
                      json_integer(config.table_size));
  if(config.dump_header_table) {
    json_object_set_new(obj, "header_table",
                        dump_header_table(&deflater->ctx));
  }
  json_dumpf(obj, stdout, JSON_PRESERVE_ORDER | JSON_INDENT(2));
  printf("\n");
  json_decref(obj);
  free(hex);
}

static void deflate_hd(nghttp2_hd_deflater *deflater,
                       nghttp2_nv *nva, size_t nvlen, size_t inputlen, int seq)
{
  ssize_t rv;
  uint8_t *buf = NULL;
  size_t buflen = 0;
  rv = nghttp2_hd_deflate_hd(deflater, &buf, &buflen, 0, nva, nvlen);
  if(rv < 0) {
    fprintf(stderr, "deflate failed with error code %zd at %d\n", rv, seq);
    exit(EXIT_FAILURE);
  }
  input_sum += inputlen;
  output_sum += rv;
  output_to_json(deflater, buf, rv, inputlen, nva, nvlen, seq);
  free(buf);
}

static int deflate_hd_json(json_t *obj, nghttp2_hd_deflater *deflater, int seq)
{
  json_t *js;
  nghttp2_nv nva[128];
  size_t len;
  size_t i;
  size_t inputlen = 0;

  js = json_object_get(obj, "headers");
  if(js == NULL) {
    fprintf(stderr, "'headers' key is missing at %d\n", seq);
    return -1;
  }
  if(!json_is_array(js)) {
    fprintf(stderr,
            "The value of 'headers' key must be an array at %d\n", seq);
    return -1;
  }
  len = json_array_size(js);
  if(len > sizeof(nva)/sizeof(nva[0])) {
    fprintf(stderr, "Too many headers (> %zu) at %d\n",
            sizeof(nva)/sizeof(nva[0]), seq);
    return -1;
  }
  for(i = 0; i < len; ++i) {
    json_t *nv_pair = json_array_get(js, i);
    const char *name;
    json_t *value;
    if(!json_is_object(nv_pair) || json_object_size(nv_pair) != 1) {
      fprintf(stderr, "bad formatted name/value pair object at %d\n", seq);
      return -1;
    }
    json_object_foreach(nv_pair, name, value) {
      nva[i].name = (uint8_t*)name;
      nva[i].namelen = strlen(name);

      if(!json_is_string(value)) {
        fprintf(stderr, "value is not string at %d\n", seq);
        return -1;
      }
      nva[i].value = (uint8_t*)json_string_value(value);
      nva[i].valuelen = strlen(json_string_value(value));
    }
    inputlen += nva[i].namelen + nva[i].valuelen;
  }
  deflate_hd(deflater, nva, len, inputlen, seq);
  return 0;
}

static void init_deflater(nghttp2_hd_deflater *deflater, nghttp2_hd_side side)
{
  nghttp2_hd_deflate_init2(deflater, side, config.deflate_table_size);
  nghttp2_hd_deflate_set_no_refset(deflater, config.no_refset);
  nghttp2_hd_change_table_size(&deflater->ctx, config.table_size);
}

static void deinit_deflater(nghttp2_hd_deflater *deflater)
{
  nghttp2_hd_deflate_free(deflater);
}

static int perform(void)
{
  size_t i;
  json_t *json, *cases;
  json_error_t error;
  size_t len;
  nghttp2_hd_deflater deflater;
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
  init_deflater(&deflater, side);
  output_json_header(side);
  len = json_array_size(cases);
  for(i = 0; i < len; ++i) {
    json_t *obj = json_array_get(cases, i);
    if(!json_is_object(obj)) {
      fprintf(stderr, "Unexpected JSON type at %zu. It should be object.\n",
              i);
      continue;
    }
    if(deflate_hd_json(obj, &deflater, i) != 0) {
      continue;
    }
    if(i + 1 < len) {
      printf(",\n");
    }
  }
  output_json_footer();
  deinit_deflater(&deflater);
  json_decref(json);
  return 0;
}

static int perform_from_http1text(void)
{
  char line[1 << 14];
  nghttp2_nv nva[256];
  int seq = 0;
  nghttp2_hd_deflater deflater;
  init_deflater(&deflater, config.side);
  output_json_header(config.side);
  for(;;) {
    size_t nvlen = 0;
    int end = 0;
    size_t inputlen = 0;
    size_t i;
    for(;;) {
      nghttp2_nv *nv;
      char *rv = fgets(line, sizeof(line), stdin);
      char *val, *val_end;
      if(rv == NULL) {
        end = 1;
        break;
      } else if(line[0] == '\n') {
        break;
      }
      assert(nvlen < sizeof(nva)/sizeof(nva[0]));
      nv = &nva[nvlen];
      val = strchr(line+1, ':');
      if(val == NULL) {
        fprintf(stderr, "Bad HTTP/1 header field format at %d.\n", seq);
        exit(EXIT_FAILURE);
      }
      *val = '\0';
      ++val;
      for(; *val && (*val == ' ' || *val == '\t'); ++val);
      for(val_end = val; *val_end && (*val_end != '\r' && *val_end != '\n');
          ++val_end);
      *val_end = '\0';
      /* printf("[%s] : [%s]\n", line, val); */
      nv->namelen = strlen(line);
      nv->valuelen = strlen(val);
      nv->name = (uint8_t*)strdup(line);
      nv->value = (uint8_t*)strdup(val);
      ++nvlen;
      inputlen += nv->namelen + nv->valuelen;
    }

    if(!end) {
      if(seq > 0) {
        printf(",\n");
      }
      deflate_hd(&deflater, nva, nvlen, inputlen, seq);
    }

    for(i = 0; i < nvlen; ++i) {
      free(nva[i].name);
      free(nva[i].value);
    }
    if(end) break;
    ++seq;
  }
  output_json_footer();
  deinit_deflater(&deflater);
  return 0;
}

static void print_help(void)
{
  printf("HPACK HTTP/2.0 header encoder\n"
         "Usage: deflatehd [OPTIONS] < INPUT\n"
         "\n"
         "Reads JSON data or HTTP/1-style header fields from stdin and\n"
         "outputs deflated header block in JSON array.\n"
         "\n"
         "For the JSON input, the root JSON object must contain \"context\"\n"
         "key, which indicates which compression context is used. If it is\n"
         "\"request\", request compression context is used. Otherwise,\n"
         "response compression context is used. The value of \"cases\" key\n"
         "contains the sequence of input header set. They share the same\n"
         "compression context and are processed in the order they appear.\n"
         "Each item in the sequence is a JSON object and it must have at\n"
         "least \"headers\" key. Its value is an array of a JSON object\n"
         "containing exactly one name/value pair.\n"
         "\n"
         "Example:\n"
         "{\n"
         "  \"context\": \"request\",\n"
         "  \"cases\":\n"
         "  [\n"
         "    {\n"
         "      \"headers\": [\n"
         "        { \":method\": \"GET\" },\n"
         "        { \":path\": \"/\" }\n"
         "      ]\n"
         "    },\n"
         "    {\n"
         "      \"headers\": [\n"
         "        { \":method\": \"POST\" },\n"
         "        { \":path\": \"/\" }\n"
         "      ]\n"
         "    }\n"
         "  ]\n"
         "}\n"
         "\n"
         "With -t option, the program can accept more familiar HTTP/1 style\n"
         "header field block. Each header set must be followed by one empty\n"
         "line:\n"
         "\n"
         "Example:\n"
         ":method: GET\n"
         ":scheme: https\n"
         ":path: /\n"
         "\n"
         ":method: POST\n"
         "user-agent: nghttp2\n"
         "\n"
         "The output of this program can be used as input for inflatehd.\n"
         "\n"
         "OPTIONS:\n"
         "    -r, --response    Use response compression context instead of\n"
         "                      request if -t is used. For JSON input, it is\n"
         "                      determined by inspecting \"context\" key in\n"
         "                      root JSON object.\n"
         "    -t, --http1text   Use HTTP/1 style header field text as input.\n"
         "                      Each header set is delimited by single empty\n"
         "                      line.\n"
         "    -s, --table-size=<N>\n"
         "                      Set dynamic table size. In the HPACK\n"
         "                      specification, this value is denoted by\n"
         "                      SETTINGS_HEADER_TABLE_SIZE.\n"
         "                      Default: 4096\n"
         "    -S, --deflate-table-size=<N>\n"
         "                      Use first N bytes of dynamic header table\n"
         "                      buffer.\n"
         "                      Default: 4096\n"
         "    -d, --dump-header-table\n"
         "                      Output dynamic header table.\n"
         "    -c, --no-refset   Don't use reference set.\n");
}

static struct option long_options[] = {
  {"response", no_argument, NULL, 'r'},
  {"http1text", no_argument, NULL, 't'},
  {"table-size", required_argument, NULL, 's'},
  {"deflate-table-size", required_argument, NULL, 'S'},
  {"dump-header-table", no_argument, NULL, 'd'},
  {"no-refset", no_argument, NULL, 'c'},
  {NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
  char *end;

  config.side = NGHTTP2_HD_SIDE_REQUEST;
  config.table_size = NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE;
  config.deflate_table_size = NGHTTP2_HD_DEFAULT_MAX_DEFLATE_BUFFER_SIZE;
  config.http1text = 0;
  config.dump_header_table = 0;
  config.no_refset = 0;
  while(1) {
    int option_index = 0;
    int c = getopt_long(argc, argv, "S:cdhrs:t", long_options, &option_index);
    if(c == -1) {
      break;
    }
    switch(c) {
    case 'r':
      /* --response */
      config.side = NGHTTP2_HD_SIDE_RESPONSE;
      break;
    case 'h':
      print_help();
      exit(EXIT_SUCCESS);
    case 't':
      /* --http1text */
      config.http1text = 1;
      break;
    case 's':
      /* --table-size */
      errno = 0;
      config.table_size = strtoul(optarg, &end, 10);
      if(errno == ERANGE || *end != '\0') {
        fprintf(stderr, "-s: Bad option value\n");
        exit(EXIT_FAILURE);
      }
      break;
    case 'S':
      /* --deflate-table-size */
      errno = 0;
      config.deflate_table_size = strtoul(optarg, &end, 10);
      if(errno == ERANGE || *end != '\0') {
        fprintf(stderr, "-S: Bad option value\n");
        exit(EXIT_FAILURE);
      }
      break;
    case 'd':
      /* --dump-header-table */
      config.dump_header_table = 1;
      break;
    case 'c':
      /* --no-refset */
      config.no_refset = 1;
      break;
    case '?':
      exit(EXIT_FAILURE);
    default:
      break;
    }
  }
  if(config.http1text) {
    perform_from_http1text();
  } else {
    perform();
  }
  fprintf(stderr, "Overall: input=%zu output=%zu ratio=%.02f\n",
          input_sum, output_sum, (double)output_sum / input_sum);
  return 0;
}
