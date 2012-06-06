#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "htparse.h"

static int
_on_msg_start(htparser * p) {
    printf("START {\n");
    return 0;
}

static int
_on_msg_end(htparser * p) {
    printf("}\n");
    return 0;
}

static int
_path(htparser * p, const char * data, size_t len) {
    printf("\tpath = '%.*s'\n", (int)len, data);
    return 0;
}

static int
_method(htparser * p, const char * data, size_t len) {
    printf("\tmethod = '%.*s'\n", (int)len, data);
    return 0;
}

static int
_uri(htparser * p, const char * data, size_t len) {
    printf("\turi = '%.*s'\n", (int)len, data);
    return 0;
}

static int
_args(htparser * p, const char * data, size_t len) {
    printf("\targs = '%.*s'\n", (int)len, data);
    return 0;
}

static int
_hdrs_end(htparser * p) {
    printf("\t}\n");
    return 0;
}

static int
_hdrs_start(htparser * p) {
    printf("\thdrs {\n");
    return 0;
}

static int
_hdr_key(htparser * p, const char * data, size_t len) {
    printf("\t\thdr_key = '%.*s'\n", (int)len, data);
    return 0;
}

static int
_hdr_val(htparser * p, const char * data, size_t len) {
    printf("\t\thdr_val = '%.*s'\n", (int)len, data);
    return 0;
}

static int
_read_body(htparser * p, const char * data, size_t len) {
    printf("\t'%.*s'\n", (int)len, data);
    return 0;
}

static int
_on_new_chunk(htparser * p) {
    printf("\t--chunk payload (%zu)--\n", htparser_get_content_length(p));
    /* printf("..chunk..\n"); */
    return 0;
}

static void
_test(htparser * p, htparse_hooks * hooks, const char * l, htp_type type) {
    printf("---- test ----\n");
    printf("%zu, %s\n", strlen(l), l);

    htparser_init(p, type);
    printf("%zu == %zu\n", htparser_run(p, hooks, l, strlen(l)), strlen(l));

    if (htparser_get_error(p)) {
        printf("ERROR: %s\n", htparser_get_strerror(p));
    }

    printf("\n");
}

static void
_test_fragments(htparser * p, htparse_hooks * hooks, const char ** fragments,
                htp_type type) {
    int i = 0;

    printf("---- test fragment ----\n");
    htparser_init(p, type);

    while (1) {
        const char * l = fragments[i++];

        if (l == NULL) {
            break;
        }

        htparser_run(p, hooks, l, strlen(l));

        if (htparser_get_error(p)) {
            printf("ERROR: %s\n", htparser_get_strerror(p));
        }
    }

    printf("\n");
}

static const char * test_fragment_1[] = {
    "GET \0",
    "  /fjdksf\0",
    "jfkdslfds H\0",
    "TTP/1.\0",
    "1\r\0",
    "\n\0",
    "\r\0",
    "\n\0",
    NULL
};

static const char * test_fragment_2[] = {
    "POST /\0",
    "h?a=b HTTP/1.0\r\n\0",
    "Content-Len\0",
    "gth\0",
    ": 1\0",
    "0\r\n\0",
    "\r\n\0",
    "12345\0",
    "67890\0",
    NULL
};

static const char * test_chunk_fragment_1[] = {
    "POST /stupid HTTP/1.1\r\n",
    "Transfer-Encoding: chunked\r\n",
    "\r\n",
    "25\r\n",
    "This is the data in the first chunk\r\n",
    "\r\n",
    "1C\r\n",
    "and this is the second one\r\n",
    "\r\n",
    "3\r\n",
    "con\r\n",
    "8\r\n",
    "sequence\r\n",
    "0\r\n",
    "\r\n",
    NULL
};

static const char * test_chunk_fragment_2[] = {
    "POST /stupid HTTP/1.1\r\n",
    "Transfer-Encoding: chunked\r\n",
    "\r\n",
    "25\r\n",
    "This is the data in the first chunk\r\n",
    "\r\n",
    "1C\r\n",
    "and this is the second one\r\n",
    "\r\n",
    "3\r\n",
    "c",
    "on\r\n",
    "8\r\n",
    "sequence\r\n",
    "0\r\n",
    "\r\n",
    "GET /foo?bar/baz? HTTP/1.0\r\n",
    "Host: stupid.com\r\n",
    "\r\n",
    NULL
};
int
main(int argc, char ** argv) {
    htparser    * p     = htparser_new();
    htparse_hooks hooks = {
        .on_msg_begin       = _on_msg_start,
        .method             = _method,
        .scheme             = NULL,
        .host               = NULL,
        .port               = NULL,
        .path               = _path,
        .args               = _args,
        .uri                = _uri,
        .on_hdrs_begin      = _hdrs_start,
        .hdr_key            = _hdr_key,
        .hdr_val            = _hdr_val,
        .on_hdrs_complete   = _hdrs_end,
        .on_new_chunk       = _on_new_chunk,
        .on_chunk_complete  = NULL,
        .on_chunks_complete = NULL,
        .body               = _read_body,
        .on_msg_complete    = _on_msg_end
    };

    const char  * test_1 = "GET / HTTP/1.0\r\n\r\n";
    const char  * test_2 = "GET /hi?a=b&c=d HTTP/1.1\r\n\r\n";
    const char  * test_3 = "GET /hi/die/?a=b&c=d HTTP/1.1\r\n\r\n";
    const char  * test_4 = "POST /fjdls HTTP/1.0\r\n"
                           "Content-Length: 4\r\n"
                           "\r\n"
                           "abcd";
    const char * test_7 = "POST /derp HTTP/1.1\r\n"
                          "Transfer-Encoding: chunked\r\n\r\n"
                          "1e\r\nall your base are belong to us\r\n"
                          "0\r\n"
                          "\r\n\0";
    const char * test_8 = "GET /DIE HTTP/1.1\r\n"
                          "HERP: DE\r\n"
                          "\tRP\r\nthings:stuff\r\n\r\n";
    const char * test_9 = "GET /big_content_len HTTP/1.1\r\n"
                          "Content-Length: 18446744073709551615\r\n\r\n";

    const char * test_fail   = "GET /JF HfD]\r\n\r\n";
    const char * test_resp_1 = "HTTP/1.0 200 OK\r\n"
                               "Stuff: junk\r\n\r\n";

    _test(p, &hooks, test_resp_1, htp_type_response);
    _test(p, &hooks, test_1, htp_type_request);
    _test(p, &hooks, test_2, htp_type_request);
    _test(p, &hooks, test_3, htp_type_request);
    _test(p, &hooks, test_4, htp_type_request);
    _test(p, &hooks, test_7, htp_type_request);
    _test(p, &hooks, test_8, htp_type_request);
    _test(p, &hooks, test_9, htp_type_request);
    _test(p, &hooks, test_fail, htp_type_request);

    _test_fragments(p, &hooks, test_fragment_1, htp_type_request);
    _test_fragments(p, &hooks, test_fragment_2, htp_type_request);
    _test_fragments(p, &hooks, test_chunk_fragment_1, htp_type_request);
    _test_fragments(p, &hooks, test_chunk_fragment_2, htp_type_request);

    return 0;
} /* main */

