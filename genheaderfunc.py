#!/usr/bin/env python

from gentokenlookup import gentokenlookup

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

if __name__ == '__main__':
    gentokenlookup(HEADERS, 'HD')
