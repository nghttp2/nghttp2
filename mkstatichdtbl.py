#!/usr/bin/env python
import re, sys

for line in sys.stdin:
    m = re.match(r'(\d+)\s+(\S+)\s+(\S+)?', line)
    print '/* {} */ MAKE_NV("{}", "{}"),'\
        .format(m.group(1),
                m.group(2),
                m.group(3) if m.group(3) else '')
