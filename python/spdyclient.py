#!/usr/bin/env python

# The example SPDY client.  You need Python 3.3 or later because we
# use TLS NPN.
#
# Usage: spdyclient.py URL...
#
import sys
import spdylay

class MyStreamHandler(spdylay.BaseSPDYStreamHandler):
    def on_header(self, nv):
        sys.stdout.write('Stream#{}\n'.format(self.stream_id))
        for k, v in nv:
            sys.stdout.write('{}: {}\n'.format(k, v))

    def on_data(self, data):
        sys.stdout.write('Stream#{}\n'.format(self.stream_id))
        sys.stdout.buffer.write(data)

    def on_close(self, status_code):
        sys.stdout.write('Stream#{} closed\n'.format(self.stream_id))

if __name__ == '__main__':
    uris = sys.argv[1:]
    spdylay.urlfetch(uris, MyStreamHandler)
