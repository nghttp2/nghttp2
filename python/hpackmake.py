#!/usr/bin/env python
#
# This script reads input headers from json file given in the
# command-line (each file must be written in the format described in
# https://github.com/Jxck/hpack-test-case but we require only
# 'headers' data). Then it encodes input header set and write the
# encoded header block in the same format. The output files are
# created under 'out' directory in the current directory. It must
# exist, otherwise the script will fail. The output filename is the
# same as the input filename.
#
import sys, base64, json, os.path, os, argparse, errno
from binascii import b2a_hex
import nghttp2

def testsuite(testdata, filename, outdir, table_size):
    if testdata['context'] == 'request':
        side = nghttp2.HD_SIDE_REQUEST
    else:
        side = nghttp2.HD_SIDE_RESPONSE

    res = {
        'draft':5, 'context': testdata['context'],
        'description': '''\
Encoded by nghttp2. The basic encoding strategy is described in \
http://lists.w3.org/Archives/Public/ietf-http-wg/2013JulSep/1135.html \
We use huffman encoding only if it produces strictly shorter byte string than \
original. We make some headers not indexing at all, but this does not always \
result in less bits on the wire.'''
    }
    cases = []
    deflater = nghttp2.HDDeflater(side)
    deflater.change_table_size(table_size)
    for casenum, item  in enumerate(testdata['cases']):
        outitem = {
            'header_table_size': table_size,
            'headers': item['headers']
        }
        casenum += 1
        hdrs = [(list(x.keys())[0].encode('utf-8'),
                 list(x.values())[0].encode('utf-8')) \
                for x in item['headers']]
        outitem['wire'] = b2a_hex(deflater.deflate(hdrs)).decode('utf-8')
        cases.append(outitem)
    res['cases'] = cases
    jsonstr = json.dumps(res, indent=2)
    with open(os.path.join(outdir, filename), 'w') as f:
        f.write(jsonstr)

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='HPACK test case generator')
    ap.add_argument('-d', '--dir', help='output directory', default='out')
    ap.add_argument('-s', '--table-size', help='max header table size',
                    type=int, default=4096)
    ap.add_argument('file', nargs='*', help='input file')
    args = ap.parse_args()
    try:
        os.mkdir(args.dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise e
    for filename in args.file:
        sys.stderr.write('{}\n'.format(filename))
        with open(filename) as f:
            input = f.read()
        testsuite(json.loads(input), os.path.basename(filename),
                  args.dir, args.table_size)
