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
  nghttp2_hd_side side;
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

static void nva_to_json(nghttp2_hd_context *inflater,
                        const nghttp2_nv *nva, size_t nvlen, int seq)
{
  size_t i;
  json_t *obj;
  json_t *headers;
  obj = json_object();
  json_object_set_new(obj, "seq", json_integer(seq));
  headers = json_array();
  json_object_set_new(obj, "headers", headers);
  for(i = 0; i < nvlen; ++i) {
    json_t *nv_pair = json_array();
    const nghttp2_nv *nv = &nva[i];
    json_array_append_new(nv_pair, json_pack("s#", nv->name, nv->namelen));
    json_array_append_new(nv_pair, json_pack("s#", nv->value, nv->valuelen));
    json_array_append_new(headers, nv_pair);
  }
  if(config.dump_header_table) {
    json_object_set_new(obj, "headerTable", dump_header_table(inflater));
  }
  json_dumpf(obj, stdout, JSON_INDENT(2) | JSON_PRESERVE_ORDER);
  json_decref(obj);
  printf("\n");
}

static int inflate_hd(json_t *obj, nghttp2_hd_context *inflater, int seq)
{
  json_t *js;
  size_t inputlen;
  uint8_t buf[16*1024];
  ssize_t resnvlen;
  nghttp2_nv *resnva;

  js = json_object_get(obj, "output");
  if(js == NULL) {
    fprintf(stderr, "output key is missing at %d\n", seq);
    return -1;
  }
  inputlen = strlen(json_string_value(js));
  if(inputlen & 1) {
    fprintf(stderr, "Badly formatted output value at %d\n", seq);
    exit(EXIT_FAILURE);
  }
  if(inputlen / 2 > sizeof(buf)) {
    fprintf(stderr, "Too big input length %zu at %d\n", inputlen / 2, seq);
    exit(EXIT_FAILURE);
  }
  decode_hex(buf, json_string_value(js), inputlen);

  resnvlen = nghttp2_hd_inflate_hd(inflater, &resnva, buf, inputlen / 2);
  if(resnvlen < 0) {
    fprintf(stderr, "inflate failed with error code %zd at %d\n",
            resnvlen, seq);
    exit(EXIT_FAILURE);
  }
  nva_to_json(inflater, resnva, resnvlen, seq);
  nghttp2_hd_end_headers(inflater);
  nghttp2_nv_array_del(resnva);
  return 0;
}

static int perform()
{
  nghttp2_hd_context inflater;
  size_t i;
  json_t *json;
  json_error_t error;
  size_t len;

  json = json_loadf(stdin, 0, &error);
  if(json == NULL) {
    fprintf(stderr, "JSON loading failed\n");
    exit(EXIT_FAILURE);
  }
  nghttp2_hd_inflate_init(&inflater, config.side);
  nghttp2_hd_change_table_size(&inflater, config.table_size);
  printf("[\n");
  len = json_array_size(json);
  for(i = 0; i < len; ++i) {
    json_t *obj = json_array_get(json, i);
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
  printf("]\n");
  nghttp2_hd_inflate_free(&inflater);
  json_decref(json);
  return 0;
}

static void print_help(void)
{
  printf("HPACK-draft-04 header decompressor\n"
         "Usage: inflatehd [OPTIONS] < INPUT\n"
         "\n"
         "Reads JSON array from stdin and outputs inflated name/value pairs\n"
         "in JSON array.\n"
         "The element of input array must be a JSON object. Each object must\n"
         "have at least following key:\n"
         "\n"
         "    output: deflated header block in hex-string.\n"
         "\n"
         "Example:\n"
         "[\n"
         "    { \"output\": \"0284f77778ff\" },\n"
         "    { \"output\": \"0185fafd3c3c7f81\" }\n"
         "]\n"
         "\n"
         "The output of this program can be used as input for deflatehd.\n"
         "\n"
         "OPTIONS:\n"
         "    -r, --response    Use response compression context instead of\n"
         "                      request.\n"
         "    -s, --table-size=<N>\n"
         "                      Set dynamic table size. In the HPACK\n"
         "                      specification, this value is denoted by\n"
         "                      SETTINGS_HEADER_TABLE_SIZE.\n"
         "                      Default: 4096\n"
         "    -d, --dump-header-table\n"
         "                      Output dynamic header table.\n");
}

static struct option long_options[] = {
  {"response", no_argument, NULL, 'r'},
  {"table-size", required_argument, NULL, 's'},
  {"dump-header-table", no_argument, NULL, 'd'},
  {NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
  char *end;
  config.side = NGHTTP2_HD_SIDE_REQUEST;
  config.table_size = NGHTTP2_HD_DEFAULT_MAX_BUFFER_SIZE;
  config.dump_header_table = 0;
  while(1) {
    int option_index = 0;
    int c = getopt_long(argc, argv, "dhrs:", long_options, &option_index);
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
    case 's':
      /* --table-size */
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
