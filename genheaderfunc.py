#!/usr/bin/env python

HEADERS = [
    ':authority',
    ':method',
    ':path',
    ':scheme',
    ':status',
    ':host', # for spdy
    'expect',
    'host',
    'if-modified-since',
    "te",
    "cookie",
    "http2-settings",
    "server",
    "via",
    "x-forwarded-for",
    "x-forwarded-proto",
    "alt-svc",
    "content-length",
    "location",
    "trailer",
    "link",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "user-agent",
    # disallowed h1 headers
    'connection',
    'keep-alive',
    'proxy-connection',
    'transfer-encoding',
    'upgrade'
]

def to_enum_hd(k):
    res = 'HD_'
    for c in k.upper():
        if c == ':' or c == '-':
            res += '_'
            continue
        res += c
    return res

def build_header(headers):
    res = {}
    for k in headers:
        size = len(k)
        if size not in res:
            res[size] = {}
        ent = res[size]
        c = k[-1]
        if c not in ent:
            ent[c] = []
        ent[c].append(k)

    return res

def gen_enum():
    print '''\
enum {'''
    for k in sorted(HEADERS):
        print '''\
  {},'''.format(to_enum_hd(k))
    print '''\
  HD_MAXIDX,
};'''

def gen_index_header():
    print '''\
int lookup_token(const uint8_t *name, size_t namelen) {
  switch (namelen) {'''
    b = build_header(HEADERS)
    for size in sorted(b.keys()):
        ents = b[size]
        print '''\
  case {}:'''.format(size)
        print '''\
    switch (name[namelen - 1]) {'''
        for c in sorted(ents.keys()):
            headers = sorted(ents[c])
            print '''\
    case '{}':'''.format(c)
            for k in headers:
                print '''\
      if (util::streq("{}", name, {})) {{
        return {};
      }}'''.format(k[:-1], size - 1, to_enum_hd(k))
            print '''\
      break;'''
        print '''\
    }
    break;'''
    print '''\
  }
  return -1;
}'''

if __name__ == '__main__':
    gen_enum()
    print ''
    gen_index_header()
