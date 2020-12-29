#!/usr/bin/env python3
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

def testsuite(testdata, filename, outdir, table_size, deflate_table_size,
              simulate_table_size_change):
    res = {
        'description': '''\
Encoded by nghttp2. The basic encoding strategy is described in \
http://lists.w3.org/Archives/Public/ietf-http-wg/2013JulSep/1135.html \
We use huffman encoding only if it produces strictly shorter byte string than \
original. We make some headers not indexing at all, but this does not always \
result in less bits on the wire.'''
    }
    cases = []
    deflater = nghttp2.HDDeflater(deflate_table_size)

    if table_size != nghttp2.DEFAULT_HEADER_TABLE_SIZE:
        deflater.change_table_size(table_size)

    num_item = len(testdata['cases'])

    change_points = {}
    if simulate_table_size_change and num_item > 1:
        change_points[num_item * 2 // 3] = table_size * 2 // 3
        change_points[num_item // 3] = table_size // 3

    for casenum, item  in enumerate(testdata['cases']):
        outitem = {
            'seqno': casenum,
            'headers': item['headers']
        }

        if casenum in change_points:
            new_table_size = change_points[casenum]
            deflater.change_table_size(new_table_size)
            outitem['header_table_size'] = new_table_size

        casenum += 1
        hdrs = [(list(x.keys())[0].encode('utf-8'),
                 list(x.values())[0].encode('utf-8')) \
                for x in item['headers']]
        outitem['wire'] = b2a_hex(deflater.deflate(hdrs)).decode('utf-8')
        cases.append(outitem)

    if cases and table_size != nghttp2.DEFAULT_HEADER_TABLE_SIZE:
        cases[0]['header_table_size'] = table_size

    res['cases'] = cases
    jsonstr = json.dumps(res, indent=2)
    with open(os.path.join(outdir, filename), 'w') as f:
        f.write(jsonstr)

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='HPACK test case generator')
    ap.add_argument('-d', '--dir', help='output directory', default='out')
    ap.add_argument('-s', '--table-size', help='max header table size',
                    type=int, default=nghttp2.DEFAULT_HEADER_TABLE_SIZE)
    ap.add_argument('-S', '--deflate-table-size',
                    help='max header table size for deflater',
                    type=int, default=nghttp2.DEFLATE_MAX_HEADER_TABLE_SIZE)
    ap.add_argument('-c', '--simulate-table-size-change',
                    help='simulate table size change scenario',
                    action='store_true')

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
                  args.dir, args.table_size, args.deflate_table_size,
                  args.simulate_table_size_change)
