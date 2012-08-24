#!/usr/bin/env python

# The example SPDY server. Python 3.3 or later is required because TLS
# NPN is used in spdylay.ThreadedSPDYServer. Put private key and
# certificate file in the current working directory.

import spdylay

# private key file
KEY_FILE='server.key'
# certificate file
CERT_FILE='server.crt'

class MySPDYRequestHandler(spdylay.BaseSPDYRequestHandler):

    def do_GET(self):
        if self.path == '/notfound':
            # Example code to return error
            self.send_error(404)
            return

        self.send_response(200)
        self.send_header('content-type', 'text/html; charset=UTF-8')

        content = '''\
<html>
<head><title>SPDY FTW</title></head>
<body>
<h1>SPDY FTW</h1>
<p>The age of HTTP/1.1 is over. The time of SPDY has come.</p>
</body>
</html>'''.encode('UTF-8')

        self.wfile.write(content)

if __name__ == "__main__":
    HOST, PORT = "localhost", 3000

    server = spdylay.ThreadedSPDYServer((HOST, PORT),
                                        MySPDYRequestHandler,
                                        cert_file=CERT_FILE,
                                        key_file=KEY_FILE)
    server.start()
