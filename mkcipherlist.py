#!/usr/bin/env python
import re
import sys
import csv

pat = re.compile(r'\ATLS_(?:ECDHE|DHE)_.*_GCM')

ciphers = []
for hl, name, _, _ in csv.reader(sys.stdin):
    if not pat.match(name):
        continue

    high, low = hl.split(',')

    id = high + low[2:] + 'u'
    ciphers.append((id, name))

print '''\
enum {'''

for id, name in ciphers:
    print '{} = {},'.format(name, id)

print '''\
};
'''

for id, name in ciphers:
    print '''\
case {}:'''.format(name)
