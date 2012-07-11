#ifndef __HTPARSE_H__
#define __HTPARSE_H__

struct htparser;

enum htp_type {
    htp_type_request = 0,
    htp_type_response
};

enum htp_scheme {
    htp_scheme_none = 0,
    htp_scheme_ftp,
    htp_scheme_http,
    htp_scheme_https,
    htp_scheme_nfs,
    htp_scheme_unknown
};

enum htp_method {
    htp_method_GET = 0,
    htp_method_HEAD,
    htp_method_POST,
    htp_method_PUT,
    htp_method_DELETE,
    htp_method_MKCOL,
    htp_method_COPY,
    htp_method_MOVE,
    htp_method_OPTIONS,
    htp_method_PROPFIND,
    htp_method_PROPPATCH,
    htp_method_LOCK,
    htp_method_UNLOCK,
    htp_method_TRACE,
    htp_method_CONNECT,
    htp_method_UNKNOWN
};

enum htpparse_error {
    htparse_error_none = 0,
    htparse_error_too_big,
    htparse_error_inval_method,
    htparse_error_inval_reqline,
    htparse_error_inval_schema,
    htparse_error_inval_proto,
    htparse_error_inval_ver,
    htparse_error_inval_hdr,
    htparse_error_inval_chunk_sz,
    htparse_error_inval_chunk,
    htparse_error_inval_state,
    htparse_error_user,
    htparse_error_status,
    htparse_error_generic
};

typedef struct htparser      htparser;
typedef struct htparse_hooks htparse_hooks;

typedef enum htp_scheme      htp_scheme;
typedef enum htp_method      htp_method;
typedef enum htp_type        htp_type;
typedef enum htpparse_error  htpparse_error;

typedef int (*htparse_hook)(htparser *);
typedef int (*htparse_data_hook)(htparser *, const char *, size_t);


struct htparse_hooks {
    htparse_hook      on_msg_begin;
    htparse_data_hook method;
    htparse_data_hook scheme;              /* called if scheme is found */
    htparse_data_hook host;                /* called if a host was in the request scheme */
    htparse_data_hook port;                /* called if a port was in the request scheme */
    htparse_data_hook path;                /* only the path of the uri */
    htparse_data_hook args;                /* only the arguments of the uri */
    htparse_data_hook uri;                 /* the entire uri including path/args */
    htparse_hook      on_hdrs_begin;
    htparse_data_hook hdr_key;
    htparse_data_hook hdr_val;
    htparse_data_hook hostname;
    htparse_hook      on_hdrs_complete;
    htparse_hook      on_new_chunk;        /* called after parsed chunk octet */
    htparse_hook      on_chunk_complete;   /* called after single parsed chunk */
    htparse_hook      on_chunks_complete;  /* called after all parsed chunks processed */
    htparse_data_hook body;
    htparse_hook      on_msg_complete;
};


size_t         htparser_run(htparser *, htparse_hooks *, const char *, size_t);
int            htparser_should_keep_alive(htparser * p);
htp_scheme     htparser_get_scheme(htparser *);
htp_method     htparser_get_method(htparser *);
const char   * htparser_get_methodstr(htparser *);
void           htparser_set_major(htparser *, unsigned char);
void           htparser_set_minor(htparser *, unsigned char);
unsigned char  htparser_get_major(htparser *);
unsigned char  htparser_get_minor(htparser *);
unsigned char  htparser_get_multipart(htparser *);
unsigned int   htparser_get_status(htparser *);
uint64_t       htparser_get_content_length(htparser *);
uint64_t       htparser_get_bytes_read(htparser *);
uint64_t       htparser_get_total_bytes_read(htparser *);
htpparse_error htparser_get_error(htparser *);
const char   * htparser_get_strerror(htparser *);
void         * htparser_get_userdata(htparser *);
void           htparser_set_userdata(htparser *, void *);
void           htparser_init(htparser *, htp_type);
htparser     * htparser_new(void);

#endif

