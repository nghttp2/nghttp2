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

entries.sort()

print '/* Sorted by hash(name) and its table index */'
print 'static nghttp2_hd_static_entry static_table[] = {'
for ent in entries:
    print 'MAKE_STATIC_ENT({}, "{}", "{}", {}u, {}u),'\
        .format(ent[1] - 1, ent[2], ent[3], ent[0], hash(ent[3]))
print '};'

print ''

print '/* Index to the position in static_table */'
print 'const size_t static_table_index[] = {'
for i in range(len(entries)):
    for j, ent in enumerate(entries):
        if ent[1] - 1 == i:
            sys.stdout.write('{: <2d},'.format(j))
            break
    if (i + 1) % 16 == 0:
        sys.stdout.write('\n')
    else:
        sys.stdout.write(' ')

print '};'
