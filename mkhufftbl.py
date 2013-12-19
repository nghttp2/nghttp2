#!/usr/bin/env python
import re
import sys

class Node:
    def __init__(self, depth):
        self.depth = depth
        self.children = {}

def to_bin(s):
    res = []
    for i in range(0, len(s), 8):
        x = s[i:i+8]
        x += '0'*(8 - len(x))
        a = 0
        for j in range(8):
            a *= 2
            a += ord(x[j]) - ord('0')
        res.append(a) #chr(a))
    return res

nodes = []

def insert(node, sym, binpat, nbits, pidx):
    if pidx == len(binpat) - 1:
        #assert(binpat[pidx] not in node.children)
        mx = (8 - (nbits & 0x7)) & 0x7;
        #print "last", bin(binpat[pidx]), mx
        for i in range(1 << mx):
            node.children[binpat[pidx] + i] = sym
    else:
        if binpat[pidx] not in node.children:
            node.children[binpat[pidx]] = -len(nodes)
            nextnode = Node(pidx + 1)
            nodes.append(nextnode)
        else:
            nextnode = nodes[-node.children[binpat[pidx]]]
        insert(nextnode, sym, binpat, nbits, pidx + 1)

symbol_tbl = [(None, 0) for i in range(257)]
tables = {}

root = Node(0)
nodes.append(root)

for line in sys.stdin:
    m = re.match(r'.*\(\s*(\d+)\) ([|01]+) \[(\d+)\]\s+(\S+).*', line)
    if m:
        #print m.group(1), m.group(2), m.group(3)
        if len(m.group(4)) > 8:
            raise Error('Code is more than 4 bytes long')
        sym = int(m.group(1))
        pat = re.sub(r'\|', '', m.group(2))
        nbits = int(m.group(3))
        assert(len(pat) == nbits)
        binpat = to_bin(pat)
        assert(len(binpat) == (nbits+7)/8)
        symbol_tbl[sym] = (binpat, nbits, m.group(4))
        #print "Inserting", sym
        insert(root, sym, binpat, nbits, 0)

print '''\
typedef struct {
  uint32_t nbits;
  uint32_t code;
} nghttp2_huff_sym;
'''

print '''\
nghttp2_huff_sym huff_sym_table[] = {'''
for i in range(257):
    pat = list(symbol_tbl[i][0])
    pat += [0]*(4 - len(pat))
    print '''\
  {{ {}, 0x{}u }}{}\
'''.format(symbol_tbl[i][1], symbol_tbl[i][2], ',' if i < 256 else '')
print '};'
print ''

print '''int16_t huff_decode_table[][256] = {'''
for j in range(len(nodes)):
    node = nodes[j]
    print '/* {} */'.format(j)
    print '{'
    for i in range(256):
        if i in node.children:
            sys.stdout.write('''\
 {}{}'''.format(node.children[i], ',' if i < 255 else ''))
        else:
            sys.stdout.write(''' NGHTTP2_HD_HUFF_NO_ENT,''')
        if (i+1)&0x7 == 0:
            print ''
    sys.stdout.write('}')
    if j == len(nodes) - 1:
        print ''
    else:
        print ','
print '};'
