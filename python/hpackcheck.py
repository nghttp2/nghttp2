#!/usr/bin/env python3
#
# This script reads json files given in the command-line (each file
# must be written in the format described in
# https://github.com/Jxck/hpack-test-case). And then it decompresses
# the sequence of encoded header blocks (which is the value of 'wire'
# key) and checks that decompressed header set is equal to the input
# header set (which is the value of 'headers' key). If there is
# mismatch, exception will be raised.
#
import sys, json
from binascii import a2b_hex
import nghttp2

def testsuite(testdata):
    inflater = nghttp2.HDInflater()

    for casenum, item  in enumerate(testdata['cases']):
        if 'header_table_size' in item:
            hd_table_size = int(item['header_table_size'])
            inflater.change_table_size(hd_table_size)
        compressed = a2b_hex(item['wire'])
        # sys.stderr.write('#{} WIRE:\n{}\n'.format(casenum+1, item['wire']))
        # TODO decompressed headers are not necessarily UTF-8 strings
        hdrs = [(k.decode('utf-8'), v.decode('utf-8')) \
                for k, v in inflater.inflate(compressed)]

        expected_hdrs = [(list(x.keys())[0],
                          list(x.values())[0]) for x in item['headers']]
        if hdrs != expected_hdrs:
            if 'seqno' in item:
                seqno = item['seqno']
            else:
                seqno = casenum

            sys.stderr.write('FAIL seqno#{}\n'.format(seqno))
            sys.stderr.write('expected:\n')
            for k, v in expected_hdrs:
                sys.stderr.write('{}: {}\n'.format(k, v))
            sys.stderr.write(', but got:\n')
            for k, v in hdrs:
                sys.stderr.write('{}: {}\n'.format(k, v))
            raise Exception('test failure')
    sys.stderr.write('PASS\n')

if __name__ == '__main__':
    for filename in sys.argv[1:]:
        sys.stderr.write('{}: '.format(filename))
        with open(filename) as f:
            input = f.read()

        testdata = json.loads(input)

        testsuite(json.loads(input))
