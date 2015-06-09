#!/usr/bin/env python
from __future__ import unicode_literals
from io import StringIO

from gentokenlookup import gentokenlookup

# copied from http-parser/http_parser.h, and stripped trailing spaces
# and backslashes.
SRC = '''
  XX(0,  DELETE,      DELETE)
  XX(1,  GET,         GET)
  XX(2,  HEAD,        HEAD)
  XX(3,  POST,        POST)
  XX(4,  PUT,         PUT)
  /* pathological */
  XX(5,  CONNECT,     CONNECT)
  XX(6,  OPTIONS,     OPTIONS)
  XX(7,  TRACE,       TRACE)
  /* webdav */
  XX(8,  COPY,        COPY)
  XX(9,  LOCK,        LOCK)
  XX(10, MKCOL,       MKCOL)
  XX(11, MOVE,        MOVE)
  XX(12, PROPFIND,    PROPFIND)
  XX(13, PROPPATCH,   PROPPATCH)
  XX(14, SEARCH,      SEARCH)
  XX(15, UNLOCK,      UNLOCK)
  /* subversion */
  XX(16, REPORT,      REPORT)
  XX(17, MKACTIVITY,  MKACTIVITY)
  XX(18, CHECKOUT,    CHECKOUT)
  XX(19, MERGE,       MERGE)
  /* upnp */
  XX(20, MSEARCH,     M-SEARCH)
  XX(21, NOTIFY,      NOTIFY)
  XX(22, SUBSCRIBE,   SUBSCRIBE)
  XX(23, UNSUBSCRIBE, UNSUBSCRIBE)
  /* RFC-5789 */
  XX(24, PATCH,       PATCH)
  XX(25, PURGE,       PURGE)
  /* CalDAV */
  XX(26, MKCALENDAR,  MKCALENDAR)
'''

if __name__ == '__main__':
    methods = []
    for line in StringIO(SRC):
        line = line.strip()
        if not line.startswith('XX'):
            continue
        _, m, _ = line.split(',', 2)
        methods.append(m.strip())
    gentokenlookup(methods, 'HTTP')
