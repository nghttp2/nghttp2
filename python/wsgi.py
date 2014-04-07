# nghttp2 - HTTP/2.0 C Library

# Copyright (c) 2013 Tatsuhiro Tsujikawa

# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:

# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
import io
import sys
from urllib.parse import urlparse

import nghttp2

def _dance_decode(b):
    # TODO faster than looping through and mod-128'ing all unicode points?
    return b.decode('utf-8').encode('latin1').decode('latin1')

class WSGIContainer(nghttp2.BaseRequestHandler):

    _BASE_ENVIRON = {
        'wsgi.version': (1,0),
        'wsgi.url_scheme': 'http', # FIXME
        'wsgi.multithread': True, # TODO I think?
        'wsgi.multiprocess': False, # TODO no idea
        'wsgi.run_once': True, # TODO now I'm just guessing
        'wsgi.errors': sys.stderr, # TODO will work for testing - is this even used by any frameworks?
    }

    def __init__(self, app, *args, **kwargs):
        super(WSGIContainer, self).__init__(*args, **kwargs)
        self.app = app
        self.chunks = []

    def on_data(self, chunk):
        self.chunks.append(chunk)

    def on_request_done(self):
        environ = WSGIContainer._BASE_ENVIRON.copy()
        parsed = urlparse(self.path)

        environ['wsgi.input'] = io.BytesIO(b''.join(self.chunks))

        for name, value in self.headers:
            mangled_name = b'HTTP_' + name.replace(b'-', b'_').upper()
            environ[_dance_decode(mangled_name)] = _dance_decode(value)

        environ.update(dict(
            REQUEST_METHOD=_dance_decode(self.method),
            # TODO SCRIPT_NAME? like APPLICATION_ROOT in Flask...
            PATH_INFO=_dance_decode(parsed.path),
            QUERY_STRING=_dance_decode(parsed.query),
            CONTENT_TYPE=environ.get('HTTP_CONTENT_TYPE', ''),
            CONTENT_LENGTH=environ.get('HTTP_CONTENT_LENGTH', ''),
            SERVER_NAME=_dance_decode(self.host),
            SERVER_PORT='', # FIXME probably requires changes in nghttp2
            SERVER_PROTOCOL='HTTP/2.0',
        ))

        response_status = [None]
        response_headers = [None]
        response_chunks = []

        def start_response(status, headers, exc_info=None):
            if response_status[0] is not None:
                raise AssertionError('Response already started')
            exc_info = None # avoid dangling circular ref - TODO is this necessary? borrowed from snippet in WSGI spec

            response_status[0] = status
            response_headers[0] = headers
            # TODO handle exc_info

            return lambda chunk: response_chunks.append(chunk)

        # TODO technically, this breaks the WSGI spec by buffering the status,
        # headers, and body until all are completely output from the app before
        # writing the response, but it looks like nghttp2 doesn't support any
        # other way for now

        # TODO disallow yielding/returning before start_response is called
        response_chunks.extend(self.app(environ, start_response))
        response_body = b''.join(response_chunks)

        # TODO automatically set content-length if not provided
        self.send_response(
            status=response_status[0],
            headers=response_headers[0],
            body=response_body,
        )

def wsgi_app(app):
    return lambda *args, **kwargs: WSGIContainer(app, *args, **kwargs)


if __name__ == '__main__':
    import ssl
    from werkzeug.testapp import test_app

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ssl_ctx.options = ssl.OP_ALL | ssl.OP_NO_SSLv2
    ssl_ctx.load_cert_chain('server.crt', 'server.key')

    server = nghttp2.HTTP2Server(('127.0.0.1', 8443), wsgi_app(test_app),
                                 ssl=ssl_ctx)
    server.serve_forever()
