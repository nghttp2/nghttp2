#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include "htparse.h"

#ifdef PARSER_DEBUG
#define __QUOTE(x)                  # x
#define  _QUOTE(x)                  __QUOTE(x)
#define htparse_debug_strlen(x)     strlen(x)

#define htparse_log_debug(fmt, ...) do {                                                             \
        time_t      t  = time(NULL);                                                                 \
        struct tm * dm = localtime(&t);                                                              \
                                                                                                     \
        fprintf(stdout, "[%02d:%02d:%02d] htparse.c:[" _QUOTE(__LINE__) "]\t                %-26s: " \
                fmt "\n", dm->tm_hour, dm->tm_min, dm->tm_sec, __func__, ## __VA_ARGS__);            \
        fflush(stdout);                                                                              \
} while (0)

#else
#define htparse_debug_strlen(x)     0
#define htparse_log_debug(fmt, ...) do {} while (0)
#endif

#if '\n' != '\x0a' || 'A' != 65
#error "You have somehow found a non-ASCII host. We can't build here."
#endif

#define PARSER_STACK_MAX 8192
#define LF               (unsigned char)10
#define CR               (unsigned char)13
#define CRLF             "\x0d\x0a"

typedef enum eval_hdr_val eval_hdr_val;
typedef enum parser_flags parser_flags;
typedef enum parser_state parser_state;

enum eval_hdr_val {
    eval_hdr_val_none = 0,
    eval_hdr_val_connection,
    eval_hdr_val_proxy_connection,
    eval_hdr_val_content_length,
    eval_hdr_val_transfer_encoding
};

enum parser_flags {
    parser_flag_chunked               = 1 << 0,
    parser_flag_connection_keep_alive = 1 << 1,
    parser_flag_connection_close      = 1 << 2,
    parser_flag_trailing              = 1 << 3,
};

enum parser_state {
    s_start = 0,
    s_method,
    s_spaces_before_uri,
    s_schema,
    s_schema_slash,
    s_schema_slash_slash,
    s_host,
    s_port,
    s_after_slash_in_uri,
    s_check_uri,
    s_uri,
    s_http_09,
    s_http_H,
    s_http_HT,
    s_http_HTT,
    s_http_HTTP,
    s_first_major_digit,
    s_major_digit,
    s_first_minor_digit,
    s_minor_digit,
    s_spaces_after_digit,
    s_almost_done,
    s_done,
    s_hdrline_start,
    s_hdrline_hdr_almost_done,
    s_hdrline_hdr_done,
    s_hdrline_hdr_key,
    s_hdrline_hdr_space_before_val,
    s_hdrline_hdr_val,
    s_hdrline_almost_done,
    s_hdrline_done,
    s_body_read,
    s_chunk_size_start,
    s_chunk_size,
    s_chunk_size_almost_done,
    s_chunk_data,
    s_chunk_data_almost_done,
    s_chunk_data_done,
    s_status,
    s_space_after_status,
    s_status_text
};

struct htparser {
    htpparse_error error;
    parser_state   state;
    parser_flags   flags;
    eval_hdr_val   heval;

    htp_type   type;
    htp_scheme scheme;
    htp_method method;

    unsigned char major;
    unsigned char minor;
    uint64_t      content_len;
    uint64_t      bytes_read;
    uint64_t      total_bytes_read;
    unsigned int  status;       /* only for responses */
    unsigned int  status_count; /* only for responses */

    char         buf[PARSER_STACK_MAX];
    unsigned int buf_idx;

    char * scheme_offset;
    char * host_offset;
    char * port_offset;
    char * path_offset;
    char * args_offset;

    void * userdata;
};

static uint32_t     usual[] = {
    0xffffdbfe,
    0x7fff37d6,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff
};

static int8_t       unhex[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

static const char * errstr_map[] = {
    "htparse_error_none",
    "htparse_error_too_big",
    "htparse_error_invalid_method",
    "htparse_error_invalid_requestline",
    "htparse_error_invalid_schema",
    "htparse_error_invalid_protocol",
    "htparse_error_invalid_version",
    "htparse_error_invalid_header",
    "htparse_error_invalid_chunk_size",
    "htparse_error_invalid_chunk",
    "htparse_error_invalid_state",
    "htparse_error_user",
    "htparse_error_unknown"
};

static const char * method_strmap[] = {
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "MKCOL",
    "COPY",
    "MOVE",
    "OPTIONS",
    "PROPFIND",
    "PROPATCH",
    "LOCK",
    "UNLOCK",
    "TRACE"
};

static inline uint32_t to_uint32(char *m) {
    return (m[3] << 24) | (m[2] << 16) | (m[1] << 8) | m[0];
}

#define _MIN_READ(a, b) ((a) < (b) ? (a) : (b))

#define _str3_cmp(m, c0, c1, c2, c3) \
    to_uint32(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define _str3Ocmp(m, c0, c1, c2, c3) \
    to_uint32(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define _str4cmp(m, c0, c1, c2, c3) \
    to_uint32(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)

#define _str5cmp(m, c0, c1, c2, c3, c4)                          \
    to_uint32(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)     \
    && m[4] == c4

#define _str6cmp(m, c0, c1, c2, c3, c4, c5)                      \
    to_uint32(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0)     \
    && (to_uint32(m+4) & 0xffff) == ((c5 << 8) | c4)

#define _str7_cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)             \
    to_uint32(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0) \
    && to_uint32(m+4) == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define _str8cmp(m, c0, c1, c2, c3, c4, c5, c6, c7)              \
    to_uint32(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0) \
    && to_uint32(m) == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4)

#define _str9cmp(m, c0, c1, c2, c3, c4, c5, c6, c7, c8)                 \
    to_uint32(m) == ((c3 << 24) | (c2 << 16) | (c1 << 8) | c0) \
    && to_uint32(m) == ((c7 << 24) | (c6 << 16) | (c5 << 8) | c4) \
    && m[8] == c8

#define __HTPARSE_GENHOOK(__n)                                                    \
    static inline int hook_ ## __n ## _run(htparser * p, htparse_hooks * hooks) { \
        htparse_log_debug("enter");                                               \
        if (hooks && (hooks)->__n) {                                              \
            return (hooks)->__n(p);                                               \
        }                                                                         \
                                                                                  \
        return 0;                                                                 \
    }

#define __HTPARSE_GENDHOOK(__n)                                                                             \
    static inline int hook_ ## __n ## _run(htparser * p, htparse_hooks * hooks, const char * s, size_t l) { \
        htparse_log_debug("enter");                                                                         \
        if (hooks && (hooks)->__n) {                                                                        \
            return (hooks)->__n(p, s, l);                                                                   \
        }                                                                                                   \
                                                                                                            \
        return 0;                                                                                           \
    }

__HTPARSE_GENHOOK(on_msg_begin);
__HTPARSE_GENHOOK(on_hdrs_begin);
__HTPARSE_GENHOOK(on_hdrs_complete);
__HTPARSE_GENHOOK(on_new_chunk);
__HTPARSE_GENHOOK(on_chunk_complete);
__HTPARSE_GENHOOK(on_chunks_complete);
__HTPARSE_GENHOOK(on_msg_complete);

__HTPARSE_GENDHOOK(method);
__HTPARSE_GENDHOOK(scheme);
__HTPARSE_GENDHOOK(host);
__HTPARSE_GENDHOOK(port);
__HTPARSE_GENDHOOK(path);
__HTPARSE_GENDHOOK(args);
__HTPARSE_GENDHOOK(uri);
__HTPARSE_GENDHOOK(hdr_key);
__HTPARSE_GENDHOOK(hdr_val);
__HTPARSE_GENDHOOK(body);


static inline uint64_t
str_to_uint64(char * str, size_t n, int * err) {
    uint64_t value;

    if (n > 20) {
        /* 18446744073709551615 is 20 bytes */
        *err = 1;
        return 0;
    }

    for (value = 0; n--; str++) {
        uint64_t check;

        if (*str < '0' || *str > '9') {
            *err = 1;
            return 0;
        }

        check = value * 10 + (*str - '0');

        if ((value && check <= value) || check > UINT64_MAX) {
            *err = 1;
            return 0;
        }

        value = check;
    }

    return value;
}

static inline ssize_t
_str_to_ssize_t(char * str, size_t n) {
    ssize_t value;

    if (n == 0) {
        return -1;
    }

    for (value = 0; n--; str++) {
        if (*str < '0' || *str > '9') {
            return -1;
        }

        value = value * 10 + (*str - '0');

#if 0
        if (value > INTMAX_MAX) {
            return -1;
        }
#endif
    }

    return value;
}

htpparse_error
htparser_get_error(htparser * p) {
    return p->error;
}

const char *
htparser_get_strerror(htparser * p) {
    htpparse_error e = htparser_get_error(p);

    if (e > htparse_error_generic) {
        return "htparse_no_such_error";
    }

    return errstr_map[e];
}

unsigned int
htparser_get_status(htparser * p) {
    return p->status;
}

int
htparser_should_keep_alive(htparser * p) {
    if (p->major > 0 && p->minor > 0) {
        if (p->flags & parser_flag_connection_close) {
            return 0;
        } else {
            return 1;
        }
    } else {
        if (p->flags & parser_flag_connection_keep_alive) {
            return 1;
        } else {
            return 0;
        }
    }

    return 0;
}

htp_scheme
htparser_get_scheme(htparser * p) {
    return p->scheme;
}

htp_method
htparser_get_method(htparser * p) {
    return p->method;
}

const char *
htparser_get_methodstr(htparser * p) {
    if (p->method >= htp_method_UNKNOWN) {
        return NULL;
    }

    return method_strmap[p->method];
}

void
htparser_set_major(htparser * p, unsigned char major) {
    p->major = major;
}

void
htparser_set_minor(htparser * p, unsigned char minor) {
    p->minor = minor;
}

unsigned char
htparser_get_major(htparser * p) {
    return p->major;
}

unsigned char
htparser_get_minor(htparser * p) {
    return p->minor;
}

void *
htparser_get_userdata(htparser * p) {
    return p->userdata;
}

void
htparser_set_userdata(htparser * p, void * ud) {
    p->userdata = ud;
}

uint64_t
htparser_get_content_length(htparser * p) {
    return p->content_len;
}

uint64_t
htparser_get_bytes_read(htparser * p) {
    return p->bytes_read;
}

uint64_t
htparser_get_total_bytes_read(htparser * p) {
    return p->total_bytes_read;
}

void
htparser_init(htparser * p, htp_type type) {
    memset(p, 0, sizeof(htparser));
    p->error = htparse_error_none;
    p->type  = type;
}

htparser *
htparser_new(void) {
    return malloc(sizeof(htparser));
}

size_t
htparser_run(htparser * p, htparse_hooks * hooks, const char * data, size_t len) {
    unsigned char ch;
    char          c;
    size_t        i;

    htparse_log_debug("enter");
    htparse_log_debug("p == %p", p);

    p->error      = htparse_error_none;
    p->bytes_read = 0;

    for (i = 0; i < len; i++) {
        int res;
        int err;

        ch = data[i];

        htparse_log_debug("[%p] data[%d] = %c (%x)", p, i, isprint(ch) ? ch : ' ', ch);

        if (p->buf_idx >= sizeof(p->buf)) {
            p->error = htparse_error_too_big;
            return i + 1;
        }

        p->total_bytes_read += 1;
        p->bytes_read       += 1;

        switch (p->state) {
            case s_start:
                htparse_log_debug("[%p] s_start", p);

                p->flags = 0;

                if (ch == CR || ch == LF) {
                    break;
                }

                if ((ch < 'A' || ch > 'Z') && ch != '_') {
                    p->error = htparse_error_inval_reqline;
                    return i + 1;
                }

                res = hook_on_msg_begin_run(p, hooks);

                p->buf[p->buf_idx++] = ch;
                p->buf[p->buf_idx]   = '\0';

                if (p->type == htp_type_request) {
                    p->state = s_method;
                } else if (p->type == htp_type_response && ch == 'H') {
                    p->state = s_http_H;
                } else {
                    p->error = htparse_error_inval_reqline;
                    return i + 1;
                }

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_method:
                htparse_log_debug("[%p] s_method", p);

                if (ch == ' ') {
                    char * m = p->buf;

                    switch (p->buf_idx) {
                        case 3:
                            if (_str3_cmp(m, 'G', 'E', 'T', '\0')) {
                                p->method = htp_method_GET;
                                break;
                            }

                            if (_str3_cmp(m, 'P', 'U', 'T', '\0')) {
                                p->method = htp_method_PUT;
                                break;
                            }

                            break;
                        case 4:
                            if (m[1] == 'O') {
                                if (_str3Ocmp(m, 'P', 'O', 'S', 'T')) {
                                    p->method = htp_method_POST;
                                    break;
                                }

                                if (_str3Ocmp(m, 'C', 'O', 'P', 'Y')) {
                                    p->method = htp_method_COPY;
                                    break;
                                }

                                if (_str3Ocmp(m, 'M', 'O', 'V', 'E')) {
                                    p->method = htp_method_MOVE;
                                    break;
                                }

                                if (_str3Ocmp(m, 'L', 'O', 'C', 'K')) {
                                    p->method = htp_method_LOCK;
                                    break;
                                }
                            } else {
                                if (_str4cmp(m, 'H', 'E', 'A', 'D')) {
                                    p->method = htp_method_HEAD;
                                    break;
                                }
                            }
                            break;
                        case 5:
                            if (_str5cmp(m, 'M', 'K', 'C', 'O', 'L')) {
                                p->method = htp_method_MKCOL;
                                break;
                            }

                            if (_str5cmp(m, 'T', 'R', 'A', 'C', 'E')) {
                                p->method = htp_method_TRACE;
                                break;
                            }
                            break;
                        case 6:
                            if (_str6cmp(m, 'D', 'E', 'L', 'E', 'T', 'E')) {
                                p->method = htp_method_DELETE;
                                break;
                            }

                            if (_str6cmp(m, 'U', 'N', 'L', 'O', 'C', 'K')) {
                                p->method = htp_method_UNLOCK;
                                break;
                            }
                            break;
                        case 7:
                            if (_str7_cmp(m, 'O', 'P', 'T', 'I', 'O', 'N', 'S', '\0')) {
                                p->method = htp_method_OPTIONS;
                            }

                            break;
                        case 8:
                            if (_str8cmp(m, 'P', 'R', 'O', 'P', 'F', 'I', 'N', 'D')) {
                                p->method = htp_method_PROPFIND;
                            }

                            break;

                        case 9:
                            if (_str9cmp(m, 'P', 'R', 'O', 'P', 'P', 'A', 'T', 'C', 'H')) {
                                p->method = htp_method_PROPPATCH;
                            }
                            break;
                    } /* switch */

                    res        = hook_method_run(p, hooks, p->buf, p->buf_idx);
                    p->buf_idx = 0;
                    p->state   = s_spaces_before_uri;

                    if (res) {
                        p->error = htparse_error_user;
                        return i + 1;
                    }

                    break;
                }

                if ((ch < 'A' || ch > 'Z') && ch != '_') {
                    p->error = htparse_error_inval_method;
                    return i + 1;
                }

                p->buf[p->buf_idx++] = ch;
                p->buf[p->buf_idx]   = '\0';

                break;
            case s_spaces_before_uri:
                htparse_log_debug("[%p] s_spaces_before_uri", p);

                switch (ch) {
                    case ' ':
                        break;
                    case '/':
                        p->path_offset       = &p->buf[p->buf_idx];

                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        p->state = s_after_slash_in_uri;
                        break;
                    default:
                        c        = (unsigned char)(ch | 0x20);

                        if (c >= 'a' && c <= 'z') {
                            p->scheme_offset     = &p->buf[p->buf_idx];
                            p->buf[p->buf_idx++] = ch;
                            p->buf[p->buf_idx]   = '\0';
                            p->state = s_schema;
                            break;
                        }

                        p->error = htparse_error_inval_reqline;
                        return i + 1;
                } /* switch */

                break;
            case s_schema:
                htparse_log_debug("[%p] s_schema", p);

                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'z') {
                    p->buf[p->buf_idx++] = ch;
                    p->buf[p->buf_idx]   = '\0';
                    break;
                }

                switch (ch) {
                    case ':':
                        p->scheme = htp_scheme_unknown;

                        switch (p->buf_idx) {
                            case 3:
                                if (_str3_cmp(p->scheme_offset, 'f', 't', 'p', ' ')) {
                                    p->scheme = htp_scheme_ftp;
                                    break;
                                }

                                if (_str3_cmp(p->scheme_offset, 'n', 'f', 's', ' ')) {
                                    p->scheme = htp_scheme_nfs;
                                    break;
                                }

                                break;
                            case 4:
                                if (_str4cmp(p->scheme_offset, 'h', 't', 't', 'p')) {
                                    p->scheme = htp_scheme_http;
                                    break;
                                }
                                break;
                            case 5:
                                if (_str5cmp(p->scheme_offset, 'h', 't', 't', 'p', 's')) {
                                    p->scheme = htp_scheme_https;
                                    break;
                                }
                                break;
                        } /* switch */

                        res                  = hook_scheme_run(p, hooks, p->scheme_offset, p->buf_idx);

#if 0
                        p->buf_idx           = 0;
                        p->buf[0]            = '\0';
#endif
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';

                        p->state             = s_schema_slash;

                        if (res) {
                            p->error = htparse_error_user;
                            return i + 1;
                        }

                        break;
                    default:
                        p->error = htparse_error_inval_schema;
                        return i + 1;
                } /* switch */

                break;
            case s_schema_slash:
                htparse_log_debug("[%p] s_schema_slash", p);

                switch (ch) {
                    case '/':
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';

                        p->state = s_schema_slash_slash;
                        break;
                    default:
                        p->error = htparse_error_inval_schema;
                        return i + 1;
                }
                break;
            case s_schema_slash_slash:
                htparse_log_debug("[%p] s_schema_slash_slash", p);

                switch (ch) {
                    case '/':
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        p->host_offset       = &p->buf[p->buf_idx];

                        p->state = s_host;
                        break;
                    default:
                        p->error = htparse_error_inval_schema;
                        return i + 1;
                }
                break;
            case s_host:
                c = (unsigned char)(ch | 0x20);

                if (c >= 'a' && c <= 'z') {
                    p->buf[p->buf_idx++] = ch;
                    p->buf[p->buf_idx]   = '\0';
                    break;
                }

                if ((ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                    p->buf[p->buf_idx++] = ch;
                    p->buf[p->buf_idx]   = '\0';
                    break;
                }

                res = hook_host_run(p, hooks, p->host_offset, (&p->buf[p->buf_idx] - p->host_offset));

                switch (ch) {
                    case ':':
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';

                        p->port_offset       = &p->buf[p->buf_idx];
                        p->state = s_port;
                        break;
                    case '/':
                        p->path_offset       = &p->buf[p->buf_idx];

                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';

                        p->state = s_after_slash_in_uri;
                        break;
                    case ' ':
                        /* p->buf should contain the whole uri */
                        p->state = s_http_09;
                        break;
                    default:
                        p->error = htparse_error_inval_schema;
                        return i + 1;
                } /* switch */

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_port:
                res = 0;

                if (ch >= '0' && ch <= '9') {
                    p->buf[p->buf_idx++] = ch;
                    p->buf[p->buf_idx]   = '\0';
                    break;
                }

                res = hook_port_run(p, hooks, p->buf, p->buf_idx);

                switch (ch) {
                    case '/':
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        p->path_offset       = &p->buf[p->buf_idx - 1];

                        p->state   = s_after_slash_in_uri;
                        break;
                    case ' ':
                        p->state   = s_http_09;
                        p->buf_idx = 0;
                        break;
                    default:
                        p->error   = htparse_error_inval_reqline;
                        return i + 1;
                }

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_after_slash_in_uri:
                htparse_log_debug("[%p] s_after_slash_in_uri", p);

                res = 0;

                if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                    p->buf[p->buf_idx++] = ch;
                    p->buf[p->buf_idx]   = '\0';
                    p->state = s_check_uri;
                    break;
                }

                switch (ch) {
                    case ' ':
                    {
                        int r1 = hook_path_run(p, hooks, p->path_offset, p->buf_idx);
                        int r2 = hook_uri_run(p, hooks, p->buf, p->buf_idx);

                        p->state   = s_http_09;
                        p->buf_idx = 0;

                        if (r1 || r2) {
                            res = 1;
                        }
                    }

                    break;
                    case CR:
                        p->minor = 9;
                        p->state = s_almost_done;
                        break;
                    case LF:
                        p->minor = 9;
                        p->state = s_hdrline_start;
                        break;
                    case '.':
                    case '%':
                    case '/':
                    case '#':
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        p->state             = s_uri;
                        break;
                    case '?':
                        res                  = hook_path_run(p, hooks, p->buf, p->buf_idx);

                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        p->args_offset       = &p->buf[p->buf_idx];
                        p->state             = s_uri;

                        break;
                    default:
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';

                        p->state             = s_check_uri;
                        break;
                } /* switch */

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_check_uri:
                htparse_log_debug("[%p] s_check_uri", p);

                res = 0;

                if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                    p->buf[p->buf_idx++] = ch;
                    p->buf[p->buf_idx]   = '\0';
                    break;
                }

                switch (ch) {
                    case ' ':
                    {
                        int r1 = 0;
                        int r2 = 0;

                        if (p->args_offset) {
                            r1 = hook_args_run(p, hooks, p->args_offset, p->buf_idx);
                        } else {
                            r1 = hook_path_run(p, hooks, p->buf, p->buf_idx);
                        }

                        r2         = hook_uri_run(p, hooks, p->buf, p->buf_idx);
                        p->buf_idx = 0;
                        p->state   = s_http_09;

                        if (r1 || r2) {
                            res = 1;
                        }
                    }
                    break;
                    case '/':
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        p->state = s_after_slash_in_uri;
                        break;
                    case CR:
                        p->minor = 9;
                        p->buf_idx           = 0;
                        p->state = s_almost_done;
                        break;
                    case LF:
                        p->minor = 9;
                        p->buf_idx           = 0;

                        p->state = s_hdrline_start;
                        break;
                    default:
                        if (ch == '?') {
                            res = hook_path_run(p, hooks, p->path_offset, (&p->buf[p->buf_idx] - p->path_offset));
                            p->args_offset = &p->buf[p->buf_idx];
                        }

                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';

                        p->state = s_uri;

                        break;
                } /* switch */

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_uri:
                htparse_log_debug("[%p] s_uri", p);

                res = 0;

                if (usual[ch >> 5] & (1 << (ch & 0x1f))) {
                    p->buf[p->buf_idx++] = ch;
                    p->buf[p->buf_idx]   = '\0';
                    break;
                }

                switch (ch) {
                    case ' ':
                    {
                        int r1 = 0;
                        int r2 = 0;

                        if (p->args_offset) {
                            r1 = hook_args_run(p, hooks, p->args_offset,
                                               (&p->buf[p->buf_idx] - p->args_offset));
                        } else {
                            r1 = hook_path_run(p, hooks, p->path_offset,
                                               (&p->buf[p->buf_idx] - p->path_offset));
                        }

                        r2 = hook_uri_run(p, hooks, p->path_offset,
                                          (&p->buf[p->buf_idx] - p->path_offset));

                        p->buf_idx = 0;
                        p->state   = s_http_09;

                        if (r1 || r2) {
                            res = 1;
                        }
                    }
                    break;
                    case CR:
                        p->minor             = 9;
                        p->buf_idx           = 0;
                        p->state             = s_almost_done;
                        break;
                    case LF:
                        p->minor             = 9;
                        p->buf_idx           = 0;
                        p->state             = s_hdrline_start;
                        break;
                    default:
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        break;
                } /* switch */

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_http_09:
                htparse_log_debug("[%p] s_http_09", p);

                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        p->minor   = 9;
                        p->buf_idx = 0;
                        p->state   = s_almost_done;
                        break;
                    case LF:
                        p->minor   = 9;
                        p->buf_idx = 0;
                        p->state   = s_hdrline_start;
                        break;
                    case 'H':
                        p->buf_idx = 0;
                        p->state   = s_http_H;
                        break;
                    default:
                        p->error   = htparse_error_inval_proto;
                        return i + 1;
                } /* switch */

                break;
            case s_http_H:
                htparse_log_debug("[%p] s_http_H", p);

                switch (ch) {
                    case 'T':
                        p->state = s_http_HT;
                        break;
                    default:
                        p->error = htparse_error_inval_proto;
                        return i + 1;
                }
                break;
            case s_http_HT:
                switch (ch) {
                    case 'T':
                        p->state = s_http_HTT;
                        break;
                    default:
                        p->error = htparse_error_inval_proto;
                        return i + 1;
                }
                break;
            case s_http_HTT:
                switch (ch) {
                    case 'P':
                        p->state = s_http_HTTP;
                        break;
                    default:
                        p->error = htparse_error_inval_proto;
                        return i + 1;
                }
                break;
            case s_http_HTTP:
                switch (ch) {
                    case '/':
                        p->state = s_first_major_digit;
                        break;
                    default:
                        p->error = htparse_error_inval_proto;
                        return i + 1;
                }
                break;
            case s_first_major_digit:
                if (ch < '1' || ch > '9') {
                    p->error = htparse_error_inval_ver;
                    return i + 1;
                }

                p->major = ch - '0';
                p->state = s_major_digit;
                break;
            case s_major_digit:
                if (ch == '.') {
                    p->state = s_first_minor_digit;
                    break;
                }

                if (ch < '0' || ch > '9') {
                    p->error = htparse_error_inval_ver;
                    return i + 1;
                }

                p->major = p->major * 10 + ch - '0';
                break;
            case s_first_minor_digit:
                if (ch < '0' || ch > '9') {
                    p->error = htparse_error_inval_ver;
                    return i + 1;
                }

                p->minor = ch - '0';
                p->state = s_minor_digit;
                break;
            case s_minor_digit:
                switch (ch) {
                    case ' ':
                        if (p->type == htp_type_request) {
                            p->state = s_spaces_after_digit;
                        } else if (p->type == htp_type_response) {
                            p->status = 0;
                            p->state = s_status;
                        }

                        break;
                    case CR:
                        p->state = s_almost_done;
                        break;
                    case LF:
                        p->state = s_hdrline_start;
                        break;
                    default:
                        if (ch < '0' || ch > '9') {
                            p->error = htparse_error_inval_ver;
                            return i + 1;
                        }

                        p->minor = p->minor * 10 + ch - '0';
                        break;
                } /* switch */
                break;
            case s_status:
                /* http response status code */
                if (ch == ' ') {
		    if (p->status) {
			p->state = s_status_text;
		    }
                    break;
                }

                if (ch < '0' || ch > '9') {
                    p->error = htparse_error_status;
                    return i + 1;
                }

                p->status = p->status * 10 + ch - '0';

                if (++p->status_count == 3) {
                    p->state = s_space_after_status;
                }

                break;
            case s_space_after_status:
                switch (ch) {
                    case ' ':
                        p->state = s_status_text;
                        break;
                    case CR:
                        p->state = s_almost_done;
                        break;
                    case LF:
                        p->state = s_hdrline_start;
                        break;
                    default:
                        p->error = htparse_error_generic;
                        return i + 1;
                }
                break;
            case s_status_text:
                switch (ch) {
                    case CR:
                        p->state = s_almost_done;
                        break;
                    case LF:
                        p->state = s_hdrline_start;
                        break;
                    default:
                        break;
                }
                break;
            case s_spaces_after_digit:
                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                        p->state = s_almost_done;
                        break;
                    case LF:
                        p->state = s_hdrline_start;
                        break;
                    default:
                        p->error = htparse_error_inval_ver;
                        return i + 1;
                }
                break;

            case s_almost_done:
                switch (ch) {
                    case LF:
                        if (p->type == htp_type_response && p->status >= 100 && p->status < 200) {
                            p->status       = 0;
                            p->status_count = 0;
                            p->state        = s_start;
                            break;
                        }

                        p->state = s_done;
                        res      = hook_on_hdrs_begin_run(p, hooks);
                        break;
                    default:
                        p->error = htparse_error_inval_reqline;
                        return i + 1;
                }
                break;
            case s_done:
                switch (ch) {
                    case CR:
                        p->state = s_hdrline_almost_done;
                        break;
                    case LF:
                        return i + 1;
                    default:
                        goto hdrline_start;
                }
                break;
hdrline_start:
            case s_hdrline_start:
                htparse_log_debug("[%p] s_hdrline_start", p);

                p->buf_idx = 0;

                switch (ch) {
                    case CR:
                        p->state             = s_hdrline_hdr_almost_done;
                        break;
                    case LF:
                        p->state             = s_hdrline_hdr_done;
                        break;
                    default:
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';

                        p->state             = s_hdrline_hdr_key;
                        break;
                }

                break;
            case s_hdrline_hdr_key:
                htparse_log_debug("[%p] s_hdrline_hdr_key", p);

                res = 0;
                switch (ch) {
                    case ':':
                        res      = hook_hdr_key_run(p, hooks, p->buf, p->buf_idx);

                        /* figure out if the value of this header is valueable */
                        p->heval = eval_hdr_val_none;

                        switch (p->buf_idx + 1) {
                            case 11:
                                if (!strcasecmp(p->buf, "connection")) {
                                    p->heval = eval_hdr_val_connection;
                                }
                                break;
                            case 15:
                                if (!strcasecmp(p->buf, "content-length")) {
                                    p->heval = eval_hdr_val_content_length;
                                }
                                break;
                            case 17:
                                if (!strcasecmp(p->buf, "proxy-connection")) {
                                    p->heval = eval_hdr_val_proxy_connection;
                                }
                                break;
                            case 18:
                                if (!strcasecmp(p->buf, "transfer-encoding")) {
                                    p->heval = eval_hdr_val_transfer_encoding;
                                }
                                break;
                        } /* switch */

                        p->buf_idx           = 0;
                        p->state             = s_hdrline_hdr_space_before_val;

                        break;
                    case CR:
                        p->state             = s_hdrline_hdr_almost_done;
                        break;
                    case LF:
                        p->state             = s_hdrline_hdr_done;
                        break;
                    default:
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        break;
                } /* switch */

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_hdrline_hdr_space_before_val:
                htparse_log_debug("[%p] s_hdrline_hdr_space_before_val", p);

                switch (ch) {
                    case ' ':
                        break;
                    case CR:
                    case LF:
                        /* empty header value, is this legal? */
                        p->error             = htparse_error_inval_hdr;
                        return i + 1;
                    default:
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        p->state             = s_hdrline_hdr_val;
                        break;
                }
                break;
            case s_hdrline_hdr_val:
                htparse_log_debug("[%p] s_hdrline_hdr_val", p);
                err = 0;
                res = 0;

                switch (ch) {
                    case CR:
                        res = hook_hdr_val_run(p, hooks, p->buf, p->buf_idx);

                        switch (p->heval) {
                            case eval_hdr_val_none:
                                break;
                            case eval_hdr_val_content_length:
                                p->content_len      = str_to_uint64(p->buf, p->buf_idx, &err);

                                if (err == 1) {
                                    p->error = htparse_error_too_big;
                                    return i + 1;
                                }

                                break;
                            case eval_hdr_val_connection:
                                switch (p->buf[0]) {
                                    case 'K':
                                    case 'k':
                                        if (_str9cmp((p->buf + 1),
                                                     'e', 'e', 'p', '-', 'A', 'l', 'i', 'v', 'e')) {
                                            p->flags |= parser_flag_connection_keep_alive;
                                        }
                                        break;
                                    case 'c':
                                        if (_str5cmp(p->buf, 'c', 'l', 'o', 's', 'e')) {
                                            p->flags |= parser_flag_connection_close;
                                        }
                                        break;
                                }
                                break;
                            case eval_hdr_val_transfer_encoding:
                                if (_str7_cmp(p->buf, 'c', 'h', 'u', 'n', 'k', 'e', 'd', '\0')) {
                                    p->flags |= parser_flag_chunked;
                                }

                                break;
                            default:
                                break;
                        } /* switch */

                        p->state             = s_hdrline_hdr_almost_done;
                        p->buf_idx           = 0;

                        break;
                    case LF:
                        p->state             = s_hdrline_hdr_done;
                        break;
                    default:
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';
                        break;
                } /* switch */

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_hdrline_hdr_almost_done:
                htparse_log_debug("[%p] s_hdrline_hdr_almost_done", p);

                res = 0;
                switch (ch) {
                    case LF:
                        if (p->flags & parser_flag_trailing) {
                            res      = hook_on_msg_complete_run(p, hooks);
                            p->state = s_start;
                            break;
                        }

                        p->state = s_hdrline_hdr_done;
                        break;
                    default:
                        p->error = htparse_error_inval_hdr;
                        return i + 1;
                }

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_hdrline_hdr_done:
                htparse_log_debug("[%p] s_hdrline_hdr_done", p);

                switch (ch) {
                    case CR:
                        p->state = s_hdrline_almost_done;
                        break;
                    case LF:
                        /* got LFLF? is this valid? */
                        return i + 1;
                    default:
                        p->buf_idx           = 0;
                        p->buf[p->buf_idx++] = ch;
                        p->buf[p->buf_idx]   = '\0';

                        p->state = s_hdrline_hdr_key;
                        break;
                }
                break;
            case s_hdrline_almost_done:
                htparse_log_debug("[%p] s_hdrline_almost_done", p);

                res = 0;

                switch (ch) {
                    case LF:
                        p->buf_idx = 0;
                        htparse_log_debug("[%p] HERE", p);

                        res        = hook_on_hdrs_complete_run(p, hooks);

                        if (!res) {
                            if (p->flags & parser_flag_trailing) {
                                res      = hook_on_msg_complete_run(p, hooks);
                                p->state = s_start;
                            } else if (p->flags & parser_flag_chunked) {
                                p->state = s_chunk_size_start;
                            } else if (p->content_len > 0) {
                                p->state = s_body_read;
                            } else if (p->content_len == 0) {
                                res      = hook_on_msg_complete_run(p, hooks);
                                p->state = s_start;
                            }
                        } else {
                            p->state = s_hdrline_done;
                        }

                        if (res) {
                            p->error = htparse_error_user;
                            return i + 1;
                        }
                        break;
                    default:
                        p->error = htparse_error_inval_hdr;
                        return i + 1;
                } /* switch */

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;
            case s_hdrline_done:
                htparse_log_debug("[%p] s_hdrline_done", p);
                res = 0;
                if (p->flags & parser_flag_trailing) {
                    res      = hook_on_msg_complete_run(p, hooks);
                    p->state = s_start;
                    break;
                } else if (p->flags & parser_flag_chunked) {
                    p->state = s_chunk_size_start;
                    i--;
                } else if (p->content_len > 0) {
                    p->state = s_body_read;
                    i--;
                } else if (p->content_len == 0) {
                    res      = hook_on_msg_complete_run(p, hooks);
                    p->state = s_start;
                }
                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }
                break;

            case s_chunk_size_start:
                c = unhex[(unsigned char)ch];

                if (c == -1) {
                    p->error = htparse_error_inval_chunk_sz;
                    return i + 1;
                }

                p->content_len = c;
                p->state       = s_chunk_size;
                break;
            case s_chunk_size:
                if (ch == CR) {
                    p->state = s_chunk_size_almost_done;
                    break;
                }

                c = unhex[(unsigned char)ch];

                if (c == -1) {
                    p->error = htparse_error_inval_chunk_sz;
                    return i + 1;
                }

                p->content_len *= 16;
                p->content_len += c;
                break;

            case s_chunk_size_almost_done:
                res = 0;

                if (ch != LF) {
                    p->error = htparse_error_inval_chunk_sz;
                    return i + 1;
                }

                if (p->content_len == 0) {
                    res       = hook_on_chunks_complete_run(p, hooks);

                    p->flags |= parser_flag_trailing;
                    p->state  = s_hdrline_start;
                } else {
                    res      = hook_on_new_chunk_run(p, hooks);

                    p->state = s_chunk_data;
                }

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_chunk_data:
                res = 0;
                {
                    const char * pp      = &data[i];
                    const char * pe      = (const char *)(data + len);
                    size_t       to_read = _MIN_READ((uint64_t)(pe - pp),
                                                     p->content_len);

                    if (to_read > 0) {
                        res = hook_body_run(p, hooks, pp, to_read);

                        i  += to_read - 1;
                    }

                    if (to_read == p->content_len) {
                        p->state = s_chunk_data_almost_done;
                    }

                    p->content_len -= to_read;
                }

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_chunk_data_almost_done:
                if (ch != CR) {
                    p->error = htparse_error_inval_chunk;
                    return i + 1;
                }

                p->state = s_chunk_data_done;
                break;

            case s_chunk_data_done:
                if (ch != LF) {
                    p->error = htparse_error_inval_chunk;
                    return i + 1;
                }

                p->state = s_chunk_size_start;

                if (hook_on_chunk_complete_run(p, hooks)) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;

            case s_body_read:
                res = 0;

                {
                    const char * pp      = &data[i];
                    const char * pe      = (const char *)(data + len);
                    size_t       to_read = _MIN_READ((uint64_t)(pe - pp),
                                                     p->content_len);

                    htparse_log_debug("[%p] s_body_read %zu", p, to_read);

                    if (to_read > 0) {
                        res = hook_body_run(p, hooks, pp, to_read);

                        i  += to_read - 1;
                        p->content_len -= to_read;

                        if (p->content_len == 0) {
                            res      = hook_on_msg_complete_run(p, hooks);

                            p->state = s_start;
                        }
                    } else {
                        res      = hook_on_msg_complete_run(p, hooks);
                        p->state = s_start;
                    }
                }

                if (res) {
                    p->error = htparse_error_user;
                    return i + 1;
                }

                break;

            default:
                htparse_log_debug("[%p] This is a silly state....", p);
                p->error = htparse_error_inval_state;
                return i + 1;
        } /* switch */
    }

    return i;
}         /* htparser_run */

