Tutorial: HPACK API
===================

In this tutorial, we describe basic use of HPACK API in nghttp2
library.  We briefly describe APIs for deflating and inflating header
fields.  The example of using these APIs are presented as complete
source code `deflate.c`_.

Deflating (encoding) headers
----------------------------

First we need to initialize :type:`nghttp2_hd_deflater` object using
`nghttp2_hd_deflate_new()` function::

    int nghttp2_hd_deflate_new(nghttp2_hd_deflater **deflater_ptr,
                               size_t deflate_hd_table_bufsize_max);

This function allocates :type:`nghttp2_hd_deflater` object and
initializes it and assigns its pointer to ``*deflater_ptr`` passed by
parameter.  The *deflate_hd_table_bufsize_max* is the upper bound of
header table size the deflater will use.  This will limit the memory
usage in deflater object for dynamic header table.  If you doubt, just
specify 4096 here, which is the default upper bound of dynamic header
table buffer size.

To encode header fields, `nghttp2_hd_deflate_hd()` function::

    ssize_t nghttp2_hd_deflate_hd(nghttp2_hd_deflater *deflater,
                                  uint8_t *buf, size_t buflen,
                                  const nghttp2_nv *nva, size_t nvlen);

The *deflater* is the deflater object initialized by
`nghttp2_hd_deflate_new()` function described above.  The *buf* is a
pointer to buffer to store encoded byte string.  The *buflen* is
capacity of *buf*.  The *nva* is a pointer to :type:`nghttp2_nv`,
which is an array of header fields to deflate.  The *nvlen* is the
number of header fields which *nva* contains.

It is important to initialize and assign all members of
:type:`nghttp2_nv`.  If a header field should not be inserted in
dynamic header table for a security reason, set
:macro:`NGHTTP2_NV_FLAG_NO_INDEX` flag in :member:`nghttp2_nv.flags`.

`nghttp2_hd_deflate_hd()` processes all headers given in *nva*.  The
*nva* must include all request or response header fields to be sent in
one HEADERS (or optionally following (multiple) CONTINUATION
frame(s)).  The *buf* must have enough space to store the encoded
result.  Otherwise, the function will fail.  To estimate the upper
bound of encoded result, use `nghttp2_hd_deflate_bound()` function::

    size_t nghttp2_hd_deflate_bound(nghttp2_hd_deflater *deflater,
                                    const nghttp2_nv *nva, size_t nvlen);

Pass this function with the same paramters *deflater*, *nva* and
*nvlen* which will be passed to `nghttp2_hd_deflate_hd()`.

The subsequent call of `nghttp2_hd_deflate_hd()` will use current
encoder state and perform differential encoding which is the
fundamental compression gain for HPACK.

Once `nghttp2_hd_deflate_hd()` fails, it cannot be undone and its
further call with the same deflater object shall fail.  So it is very
important to use `nghttp2_hd_deflate_bound()` to know the required
size of buffer.

To delete :type:`nghttp2_hd_deflater` object, use `nghttp2_hd_deflate_del()`
function.

.. note::

   Generally, the order of header fields passed to
   `nghttp2_hd_deflate_hd()` function is not preserved.  It is known
   that the relative ordering of header fields which do not share the
   same name is insignificant.  But some header fields sharing the
   same name require the explicit ordering.  To preserve this
   ordering, those header values are concatenated into single header
   field value using NULL (0x00) as delimiter.  This is transparent to
   HPACK API.  Therefore, the application should examine the inflated
   header values and split into multiple header field values by NULL.

Inflating (decoding) headers
----------------------------

We use :type:`nghttp2_hd_inflater` object to inflate compressed header
data.  To initialize the object, use `nghttp2_hd_inflate_new()`::

    int nghttp2_hd_inflate_new(nghttp2_hd_inflater **inflater_ptr);

To inflate header data, use `nghttp2_hd_inflate_hd()` function::

    ssize_t nghttp2_hd_inflate_hd(nghttp2_hd_inflater *inflater,
                                  nghttp2_nv *nv_out, int *inflate_flags,
                                  uint8_t *in, size_t inlen, int in_final);

The *inflater* is the inflater object initialized above.  The *nv_out*
is a pointer to :type:`nghttp2_nv` to store the result.  The *in* is a
pointer to input data and *inlen* is its length.  The caller is not
required to specify whole deflated header data to *in* at once.  It
can call this function multiple times for portion of the data in
streaming way.  If *in_final* is nonzero, it tells the function that
the passed data is the final sequence of deflated header data.  The
*inflate_flags* is output parameter and successful call of this
function stores a set of flags in it.  It will be described later.

This function returns when each header field is inflated.  When this
happens, the function sets :macro:`NGHTTP2_HD_INFLATE_EMIT` flag to
*inflate_flag* parameter and header field is stored in *nv_out*.  The
return value indicates the number of data read from *in* to processed
so far.  It may be less than *inlen*.  The caller should call the
function repeatedly until all data are processed by adjusting *in* and
*inlen* with the processed bytes.

If *in_final* is nonzero and all given data was processed, the
function sets :macro:`NGHTTP2_HD_INFLATE_FINAL` flag to
*inflate_flag*.  If the caller sees this flag set, call
`nghttp2_hd_inflate_end_headers()` function.

If *in_final* is zero and :macro:`NGHTTP2_HD_INFLATE_EMIT` flag is not
set, it indicates that all given data was processed.  The caller is
required to pass subsequent data.

It is important to note that the function may produce one or more
header fields even if *inlen* is 0 when *in_final* is nonzero, due to
differential encoding.

The example use of `nghttp2_hd_inflate_hd()` is shown in
`inflate_header_block()` function in `deflate.c`_.

To delete :type:`nghttp2_hd_inflater` object, use `nghttp2_hd_inflate_del()`
function.
