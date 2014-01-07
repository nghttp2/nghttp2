#!/usr/bin/env python
import re, sys

def hash(s):
    h = 0
    for c in s:
        h = h * 31 + ord(c)
    return h & ((1 << 32) - 1)

for line in sys.stdin:
    m = re.match(r'(\d+)\s+(\S+)\s+(\S+)?', line)
    val = m.group(3) if m.group(3) else ''
    print '/* {} */ MAKE_NV("{}", "{}", {}u, {}u),'\
        .format(m.group(1),
                m.group(2),
                val,
                hash(m.group(2)),
                hash(val))
