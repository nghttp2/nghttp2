#!/usr/bin/env python
#
# This script takes directories which contain the hpack-test-case json
# files, and calculates the compression ratio in each file and outputs
# the result in table formatted in rst.
#
# The each directory contains the result of various HPACK compressor.
#
# The table is laid out so that we can see that how input header set
# in one json file is compressed in each compressor.
#
# For hpack-test-case, see https://github.com/Jxck/hpack-test-case
#
import sys, json, os, re

class Stat:

    def __init__(self, complen, srclen):
        self.complen = complen
        self.srclen = srclen

def compute_stat(jsdata):
    complen = 0
    srclen = 0
    for item in jsdata['cases']:
        complen += len(item['wire']) // 2
        srclen += \
                  sum([len(list(x.keys())[0]) + len(list(x.values())[0]) \
                       for x in item['headers']])
    return Stat(complen, srclen)

def format_result(r):
    return '{:.02f} ({}/{}) '.format(r.complen/r.srclen, r.complen, r.srclen)

if __name__ == '__main__':
    entries = [(os.path.basename(re.sub(r'/+$', '', p)), p) \
               for p in sys.argv[1:]]
    maxnamelen = 0
    maxstorynamelen = 0
    res = {}

    stories = set()
    for name, ent in entries:
        files = [p for p in os.listdir(ent) if p.endswith('.json')]
        res[name] = {}
        maxnamelen = max(maxnamelen, len(name))
        for fn in files:
            stories.add(fn)
            maxstorynamelen = max(maxstorynamelen, len(fn))
            with open(os.path.join(ent, fn)) as f:
                input = f.read()
            rv = compute_stat(json.loads(input))
            res[name][fn] = rv
            maxnamelen = max(maxnamelen, len(format_result(rv)))
    stories = list(stories)
    stories.sort()

    storynameformat = '{{:{}}} '.format(maxstorynamelen)
    nameformat = '{{:{}}} '.format(maxnamelen)


    sys.stdout.write('''\
hpack-test-case compression ratio
=================================

The each cell has ``X (Y/Z)`` format:

X
  Y / Z
Y
  number of bytes after compression
Z
  number of bytes before compression

''')

    def write_border():
        sys.stdout.write('='*maxstorynamelen)
        sys.stdout.write(' ')
        for _ in entries:
            sys.stdout.write('='*maxnamelen)
            sys.stdout.write(' ')
        sys.stdout.write('\n')

    write_border()

    sys.stdout.write(storynameformat.format('story'))
    for name, _ in entries:
        sys.stdout.write(nameformat.format(name))
    sys.stdout.write('\n')

    write_border()

    for story in stories:
        sys.stdout.write(storynameformat.format(story))
        srclen = -1
        for name, _ in entries:
            stats = res[name]
            if story not in stats:
                sys.stdout.write(nameformat.format('N/A'))
                continue
            if srclen == -1:
                srclen = stats[story].srclen
            elif srclen != stats[story].srclen:
                raise Exception('Bad srclen')
            sys.stdout.write(nameformat.format(format_result(stats[story])))
        sys.stdout.write('\n')

    write_border()
