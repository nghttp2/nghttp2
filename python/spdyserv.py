#!/usr/bin/env python

# The example SPDY server.  You need Python 3.3 or later because we
# use TLS NPN. Put private key and certificate file in the current
# working directory.

import socket
import threading
import socketserver
import ssl
import io

import spdylay

# private key file
KEY_FILE='server.key'
# certificate file
CERT_FILE='server.crt'

def send_cb(session, data):
    ssctrl = session.user_data
    ssctrl.sock.sendall(data)
    return len(data)

def read_cb(session, stream_id, length, source):
    data = source.read(length)
    if data:
        status = spdylay.ERR_OK
    else:
        status = spdylay.ERR_EOF
    return data, status

def on_ctrl_recv_cb(session, frame):
    ssctrl = session.user_data
    if frame.frame_type == spdylay.SYN_STREAM:
        # This will crash cookies...
        nv = dict(frame.nv)
        if b'user-agent' in nv:
            user_agent = nv[b'user-agent'].decode('utf-8')
        else:
            user_agent = ''
        html = '''\
<html>
<head><title>SPDY FTW</title></head>
<body>
<h1>SPDY FTW</h1>
<p>The age of HTTP/1.1 is over. The time of SPDY has come.</p>
<p>Your browser {} supports SPDY.</p>
</body>
</html>
'''.format(user_agent)
        data_prd = spdylay.DataProvider(io.BytesIO(bytes(html, 'utf-8')),
                                        read_cb)

        stctrl = StreamCtrl(frame.stream_id, data_prd)
        ssctrl.streams[frame.stream_id] = stctrl
        nv = [(b':status', b'200 OK'),
              (b':version', b'HTTP/1.1'),
              (b'server', b'python+spdylay')]
        session.submit_response(frame.stream_id, nv, data_prd)

class StreamCtrl:
    def __init__(self, stream_id, data_prd):
        self.stream_id = stream_id
        self.data_prd = data_prd

class SessionCtrl:
    def __init__(self, sock):
        self.sock = sock
        self.streams = {}

class ThreadedSPDYRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        ctx.set_npn_protocols(['spdy/3', 'spdy/2'])
        sock = ctx.wrap_socket(self.request, server_side=True)
        if sock.selected_npn_protocol() == 'spdy/3':
            version = spdylay.PROTO_SPDY3
        elif sock.selected_npn_protocol() == 'spdy/2':
            version = spdylay.PROTO_SPDY2
        else:
            return

        ssctrl = SessionCtrl(sock)
        session = spdylay.Session(spdylay.SERVER,
                                  version,
                                  send_cb=send_cb,
                                  on_ctrl_recv_cb=on_ctrl_recv_cb,
                                  user_data=ssctrl)

        session.submit_settings(\
            spdylay.FLAG_SETTINGS_NONE,
            [(spdylay.SETTINGS_MAX_CONCURRENT_STREAMS,
              spdylay.ID_FLAG_SETTINGS_NONE,
              100)])
        while session.want_read() or session.want_write():
            data = sock.recv(4096)
            if data:
                session.recv(data)
                session.send()
            else:
                break

class ThreadedSPDYServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, svaddr, handler):
        self.allow_reuse_address = True
        socketserver.TCPServer.__init__(self, svaddr, handler)

if __name__ == "__main__":
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = "localhost", 3000

    server = ThreadedSPDYServer((HOST, PORT), ThreadedSPDYRequestHandler)
    ip, port = server.server_address

    # Start a thread with the server -- that thread will then start one
    # more thread for each request
    server_thread = threading.Thread(target=server.serve_forever)
    # Exit the server thread when the main thread terminates
    #server_thread.daemon = True
    server_thread.start()
