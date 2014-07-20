#!/usr/bin/env python
import re, sys

def hash(s):
    h = 0
    for c in s:
        h = h * 31 + ord(c)
    return h & ((1 << 32) - 1)

entries = []
for line in sys.stdin:
    m = re.match(r'(\d+)\s+(\S+)\s+(\S.*)?', line)
    val = m.group(3).strip() if m.group(3) else ''
    entries.append((hash(m.group(2)), int(m.group(1)), m.group(2), val))

print 'static nghttp2_hd_entry static_table[] = {'
for ent in entries:
    print 'MAKE_ENT("{}", "{}", {}u, {}u),'\
        .format(ent[2], ent[3], ent[0], hash(ent[3]))
print '};'
