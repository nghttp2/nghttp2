#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This script read cipher suite list csv file [1] and prints out ECDHE
# or DHE with AEAD ciphers only.  The output is used by
# src/shrpx_ssl.cc.
#
# [1] http://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
# [2] http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml

from __future__ import unicode_literals
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
