#!/usr/bin/env python
import re
import sys

class Node:
    def __init__(self, term = None):
        self.term = term
        self.left = None
        self.right = None
        self.trans = []
        self.id = None
        self.accept = False

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

def insert(node, sym, bits):
    if len(bits) == 0:
        node.term = sym
        return
    else:
        if bits[0] == '0':
            if node.left is None:
                node.left = Node()
            child = node.left
        else:
            if node.right is None:
                node.right = Node()
            child = node.right
        insert(child, sym, bits[1:])

def traverse(node, bits, syms, start_node, root, depth):
    if depth == 4:
        if 256 in syms:
            syms = []
            node = None
        start_node.trans.append((node, bits, syms))
        return

    if node.term is not None:
        node = root

    def go(node, bit):
        nbits = list(bits)
        nbits.append(bit)
        nsyms = list(syms)
        if node.term is not None:
            nsyms.append(node.term)
        traverse(node, nbits, nsyms, start_node, root, depth + 1)

    go(node.left, 0)
    go(node.right, 1)

idseed = 0

def dfs_setid(node, prefix):
    if node.term is not None:
        return
    if len(prefix) <= 7 and [1] * len(prefix) == prefix:
        node.accept = True
    global idseed
    node.id = idseed
    idseed += 1
    dfs_setid(node.left, prefix + [0])
    dfs_setid(node.right, prefix + [1])

def dfs(node, root):
    if node is None:
        return
    traverse(node, [], [], node, root, 0)
    dfs(node.left, root)
    dfs(node.right, root)

NGHTTP2_HUFF_ACCEPTED = 1
NGHTTP2_HUFF_SYM = 1 << 1

def dfs_print(node):
    if node.term is not None:
        return
    print '/* {} */'.format(node.id)
    print '{'
    for nd, bits, syms in node.trans:
        outlen = len(syms)
        flags = 0
        if outlen == 0:
            out = 0
        else:
            assert(outlen == 1)
            out = syms[0]
            flags |= NGHTTP2_HUFF_SYM
        if nd is None:
            id = -1
        else:
            id = nd.id
            if id is None:
                # if nd.id is None, it is a leaf node
                id = 0
                flags |= NGHTTP2_HUFF_ACCEPTED
            elif nd.accept:
                flags |= NGHTTP2_HUFF_ACCEPTED
        print '  {{{}, 0x{:02x}, {}}},'.format(id, flags, out)
    print '},'
    dfs_print(node.left)
    dfs_print(node.right)

symbol_tbl = [(None, 0) for i in range(257)]
tables = {}

root = Node()

for line in sys.stdin:
    m = re.match(r'.*\(\s*(\d+)\) ([|01]+) \[(\d+)\]\s+(\S+).*', line)
    if m:
        #print m.group(1), m.group(2), m.group(3)
        if len(m.group(4)) > 8:
            raise Error('Code is more than 4 bytes long')
        sym = int(m.group(1))
        bits = re.sub(r'\|', '', m.group(2))
        nbits = int(m.group(3))
        assert(len(bits) == nbits)
        binpat = to_bin(bits)
        assert(len(binpat) == (nbits+7)/8)
        symbol_tbl[sym] = (binpat, nbits, m.group(4))
        #print "Inserting", sym
        insert(root, sym, bits)

dfs_setid(root, [])
dfs(root, root)

print '''\
typedef struct {
  uint32_t nbits;
  uint32_t code;
} nghttp2_huff_sym;
'''

print '''\
const nghttp2_huff_sym huff_sym_table[] = {'''
for i in range(257):
    pat = list(symbol_tbl[i][0])
    pat += [0]*(4 - len(pat))
    print '''\
  {{ {}, 0x{}u }}{}\
'''.format(symbol_tbl[i][1], symbol_tbl[i][2], ',' if i < 256 else '')
print '};'
print ''

print '''\
enum {{
  NGHTTP2_HUFF_ACCEPTED = {},
  NGHTTP2_HUFF_SYM = {}
}} nghttp2_huff_decode_flag;
'''.format(NGHTTP2_HUFF_ACCEPTED, NGHTTP2_HUFF_SYM)

print '''\
typedef struct {
  int16_t state;
  uint8_t flags;
  uint8_t sym;
} nghttp2_huff_decode;
'''

print '''\
const nghttp2_huff_decode huff_decode_table[][16] = {'''
dfs_print(root)
print '};'
