#!/usr/bin/env python

def to_enum_hd(k, prefix):
    res = prefix + '_'
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

def gen_enum(tokens, prefix):
    print '''\
enum {'''
    for k in sorted(tokens):
        print '''\
  {},'''.format(to_enum_hd(k, prefix))
    print '''\
  {}_MAXIDX,
}};'''.format(prefix)

def gen_index_header(tokens, prefix):
    print '''\
int lookup_token(const uint8_t *name, size_t namelen) {
  switch (namelen) {'''
    b = build_header(tokens)
    for size in sorted(b.keys()):
        ents = b[size]
        print '''\
  case {}:'''.format(size)
        print '''\
    switch (name[{}]) {{'''.format(size - 1)
        for c in sorted(ents.keys()):
            headers = sorted(ents[c])
            print '''\
    case '{}':'''.format(c)
            for k in headers:
                print '''\
      if (util::streq_l("{}", name, {})) {{
        return {};
      }}'''.format(k[:-1], size - 1, to_enum_hd(k, prefix))
            print '''\
      break;'''
        print '''\
    }
    break;'''
    print '''\
  }
  return -1;
}'''

def gentokenlookup(tokens, prefix):
    gen_enum(tokens, prefix)
    print ''
    gen_index_header(tokens, prefix)
