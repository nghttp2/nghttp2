#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>

#include <jansson.h>

#include "nghttp2_hd.h"
#include "nghttp2_frame.h"

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

static void nva_to_json(const nghttp2_nv *nva, size_t nvlen, int seq)
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
  nva_to_json(resnva, resnvlen, seq);
  nghttp2_hd_end_headers(inflater);
  nghttp2_nv_array_del(resnva);
  return 0;
}

static int perform(nghttp2_hd_side side)
{
  nghttp2_hd_context inflater;
  int i = 0;
  json_t *json;
  json_error_t error;
  size_t len;

  json = json_loadf(stdin, 0, &error);
  if(json == NULL) {
    return -1;
  }
  nghttp2_hd_inflate_init(&inflater, side);
  printf("[\n");
  len = json_array_size(json);
  for(i = 0; i < len; ++i) {
    json_t *obj = json_array_get(json, i);
    if(!json_is_object(obj)) {
      fprintf(stderr, "Unexpected JSON type at %d. It should be object.\n", i);
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

static void print_help()
{
  printf("Usage: inflatehd [-r] < INPUT\n\n"
         "Reads JSON array from stdin and outputs inflated name/value pairs\n"
         "in JSON array.\n"
         "The element of input array must be a JSON object. Each object must\n"
         "have following key:\n"
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
         "                      request.\n");
}

static struct option long_options[] = {
  {"response", no_argument, NULL, 'r'},
  {NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
  nghttp2_hd_side side = NGHTTP2_HD_SIDE_REQUEST;
  while(1) {
    int option_index = 0;
    int c = getopt_long(argc, argv, "hr", long_options, &option_index);
    if(c == -1) {
      break;
    }
    switch(c) {
    case 'r':
      /* --response */
      side = NGHTTP2_HD_SIDE_RESPONSE;
      break;
    case 'h':
      print_help();
      exit(EXIT_SUCCESS);
    case '?':
      exit(EXIT_FAILURE);
    default:
      break;
    }
  }
  perform(side);
  return 0;
}
