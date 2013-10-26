#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>

#include <jansson.h>

#include "nghttp2_hd.h"
#include "nghttp2_frame.h"

static void to_hex(char *dest, const uint8_t *src, size_t len)
{
  size_t i;
  for(i = 0; i < len; ++i) {
    sprintf(dest, "%02x", src[i]);
    dest += 2;
  }
}

static void output_to_json(const uint8_t *buf, size_t len, size_t inputlen,
                           int seq)
{
  json_t *obj;
  char hex[16*1024];

  if(len * 2 > sizeof(hex)) {
    fprintf(stderr, "Output too large at %d\n", seq);
    exit(EXIT_FAILURE);
  }
  obj = json_object();
  json_object_set_new(obj, "seq", json_integer(seq));
  json_object_set_new(obj, "inputLen", json_integer(inputlen));
  json_object_set_new(obj, "outputLength", json_integer(len));
  json_object_set_new(obj, "PercentageOfOriginalSize",
                      json_real((double)len / inputlen * 100));
  to_hex(hex, buf, len);
  json_object_set_new(obj, "output", json_pack("s#", hex, len * 2));
  json_dumpf(obj, stdout, JSON_PRESERVE_ORDER);
  printf("\n");
  json_decref(obj);
}

static void deflate_hd(nghttp2_hd_context *deflater,
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
  output_to_json(buf, rv, inputlen, seq);
  nghttp2_hd_end_headers(deflater);
  free(buf);
}

static int deflate_hd_json(json_t *obj, nghttp2_hd_context *deflater, int seq)
{
  json_t *js;
  nghttp2_nv nva[128];
  size_t len;
  size_t i;
  size_t inputlen = 0;

  js = json_object_get(obj, "headers");
  if(js == NULL) {
    fprintf(stderr, "headers key is missing at %d\n", seq);
    return -1;
  }
  if(!json_is_array(js)) {
    fprintf(stderr, "headers value must be an array at %d\n", seq);
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
    json_t *s;
    if(!json_is_array(nv_pair) || json_array_size(nv_pair) != 2) {
      fprintf(stderr, "bad formatted name/value pair array at %d\n", seq);
      return -1;
    }
    s = json_array_get(nv_pair, 0);
    if(!json_is_string(s)) {
      fprintf(stderr, "bad formatted name/value pair array at %d\n", seq);
      return -1;
    }
    nva[i].name = (uint8_t*)json_string_value(s);
    nva[i].namelen = strlen(json_string_value(s));

    s = json_array_get(nv_pair, 1);
    if(!json_is_string(s)) {
      fprintf(stderr, "bad formatted name/value pair array at %d\n", seq);
      return -1;
    }
    nva[i].value = (uint8_t*)json_string_value(s);
    nva[i].valuelen = strlen(json_string_value(s));
    inputlen += nva[i].namelen + nva[i].valuelen;
  }
  deflate_hd(deflater, nva, len, inputlen, seq);
  return 0;
}

static int perform(nghttp2_hd_side side)
{
  nghttp2_hd_context deflater;
  size_t i;
  json_t *json;
  json_error_t error;
  size_t len;
  json = json_loadf(stdin, 0, &error);
  if(json == NULL) {
    fprintf(stderr, "JSON loading failed\n");
    exit(EXIT_FAILURE);
  }
  nghttp2_hd_deflate_init(&deflater, side);
  printf("[\n");
  len = json_array_size(json);
  for(i = 0; i < len; ++i) {
    json_t *obj = json_array_get(json, i);
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
  printf("]\n");
  nghttp2_hd_deflate_free(&deflater);
  json_decref(json);
  return 0;
}

static int perform_from_http1text(nghttp2_hd_side side)
{
  char line[1 << 14];
  nghttp2_nv nva[256];
  nghttp2_hd_context deflater;
  int seq = 0;
  nghttp2_hd_deflate_init(&deflater, side);
  printf("[\n");
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
    nghttp2_nv_array_sort(nva, nvlen);

    deflate_hd(&deflater, nva, nvlen, inputlen, seq);

    for(i = 0; i < nvlen; ++i) {
      free(nva[i].name);
      free(nva[i].value);
    }
    if(end) break;
    printf(",\n");
    ++seq;
  }
  printf("]\n");
  nghttp2_hd_deflate_free(&deflater);
  return 0;
}

static void print_help(void)
{
  printf("HPACK-draft-04 header compressor\n"
         "Usage: deflatehd [-r] < INPUT\n"
         "\n"
         "Reads JSON array or HTTP/1-style header fields from stdin and\n"
         "outputs deflated header block in JSON array.\n"
         "\n"
         "For the JSON input, the element of input array must be a JSON\n"
         "object. Each object must have at least following key:\n"
         "\n"
         "    headers: a JSON array of name/value pairs. The each element is\n"
         "             a JSON array of 2 strings. The index 0 must\n"
         "             contain header name and the index 1 must contain\n"
         "             header value.\n"
         "\n"
         "Example:\n"
         "[\n"
         "  {\n"
         "   \"headers\": [\n"
         "      [ \":method\", \"GET\" ],\n"
         "      [ \":path\", \"/\" ]\n"
         "    ]\n"
         "  },\n"
         "  {\n"
         "   \"headers\": [\n"
         "      [ \":method\", \"POST\" ],\n"
         "      [ \":path\", \"/\" ]\n"
         "    ]\n"
         "  }\n"
         "]\n"
         "\n"
         "With -t option, the program can accept more familiar HTTP/1 style\n"
         "header field block. Each header set is delimited by empty line:\n"
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
         "                      request.\n"
         "    -t, --http1text   Use HTTP/1 style header field text as input.\n"
         "                      Each header set is delimited by single empty\n"
         "                      line.\n");
}

static struct option long_options[] = {
  {"response", no_argument, NULL, 'r'},
  {"http1text", no_argument, NULL, 't'},
  {NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
  nghttp2_hd_side side = NGHTTP2_HD_SIDE_REQUEST;
  int http1text = 0;
  while(1) {
    int option_index = 0;
    int c = getopt_long(argc, argv, "hrt", long_options, &option_index);
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
    case 't':
      http1text = 1;
      break;
    case '?':
      exit(EXIT_FAILURE);
    default:
      break;
    }
  }
  if(http1text) {
    perform_from_http1text(side);
  } else {
    perform(side);
  }
  return 0;
}
