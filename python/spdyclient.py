#!/usr/bin/env python

# The example SPDY client.  You need Python 3.3 or later because we
# use TLS NPN.
#
# Usage: spdyclient.py URI
#
import socket
import sys
import ssl
import select
import zlib
from urllib.parse import urlsplit
import spdylay

def connect(hostname, port):
    s = None
    for res in socket.getaddrinfo(hostname, port, socket.AF_UNSPEC,
                                  socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
        except OSError as msg:
            s = None
            continue
        try:
            s.connect(sa)
        except OSError as msg:
            s.close()
            s = None
            continue
        break
    return s

class Request:
    def __init__(self, uri):
        self.uri = uri
        self.stream_id = 0
        self.decomp = None

class SessionCtrl:
    def __init__(self, sock):
        self.sock = sock
        self.requests = set()
        self.streams = {}
        self.finish = False

def send_cb(session, data):
    ssctrl = session.user_data
    wlen = ssctrl.sock.send(data)
    return wlen

def before_ctrl_send_cb(session, frame):
    if frame.frame_type == spdylay.SYN_STREAM:
        req = session.get_stream_user_data(frame.stream_id)
        if req:
            req.stream_id = frame.stream_id
            session.user_data.streams[req.stream_id] = req

def on_ctrl_recv_cb(session, frame):
    if frame.frame_type == spdylay.SYN_REPLY or\
            frame.frame_type == spdylay.HEADERS:
        if frame.stream_id in session.user_data.streams:
            req = session.user_data.streams[frame.stream_id]
            if req.decomp:
                return
            for k, v in frame.nv:
                if k == 'content-encoding' and \
                        (v.lower() == 'gzip' or v.lower() == 'deflate'):
                    req.decomp = zlib.decompressobj()

def on_data_chunk_recv_cb(session, flags, stream_id, data):
    if stream_id in session.user_data.streams:
        req = session.user_data.streams[stream_id]
        if req.decomp:
            sys.stdout.buffer.write(req.decomp.decompress(data))
        else:
            sys.stdout.buffer.write(data)

def on_stream_close_cb(session, stream_id, status_code):
    if stream_id in session.user_data.streams:
        del session.user_data.streams[stream_id]
        session.user_data.finish = True

def get(uri):
    uricomps = urlsplit(uri)
    if uricomps.scheme != 'https':
        print('Unsupported scheme')
        sys.exit(1)
    hostname = uricomps.hostname
    port = uricomps.port if uricomps.port else 443

    rawsock = connect(hostname, port)
    if rawsock is None:
        print('Could not open socket')
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ctx.set_npn_protocols(['spdy/3', 'spdy/2'])

    sock = ctx.wrap_socket(rawsock, server_side=False,
                           do_handshake_on_connect=False)
    sock.setblocking(False)

    while True:
        try:
            sock.do_handshake()
            break
        except ssl.SSLWantReadError as e:
            select.select([sock], [], [])
        except ssl.SSLWantWriteError as e:
            select.select([], [sock], [])

    if sock.selected_npn_protocol() == 'spdy/3':
        version = spdylay.PROTO_SPDY3
    elif sock.selected_npn_protocol() == 'spdy/2':
        version = spdylay.PROTO_SPDY2
    else:
        return

    sessionctrl = SessionCtrl(sock)
    req = Request(uri)
    sessionctrl.requests.add(req)

    session = spdylay.Session(spdylay.CLIENT,
                              version,
                              send_cb=send_cb,
                              on_ctrl_recv_cb=on_ctrl_recv_cb,
                              on_data_chunk_recv_cb=on_data_chunk_recv_cb,
                              before_ctrl_send_cb=before_ctrl_send_cb,
                              on_stream_close_cb=on_stream_close_cb,
                              user_data=sessionctrl)

    session.submit_settings(\
        spdylay.FLAG_SETTINGS_NONE,
        [(spdylay.SETTINGS_MAX_CONCURRENT_STREAMS,
          spdylay.ID_FLAG_SETTINGS_NONE,
          100)])

    if uricomps.port != 443:
        hostport = uricomps.netloc
    else:
        hostport = uricomps.hostname
    if uricomps.path:
        path = uricomps.path
    else:
        path = '/'
    if uricomps.query:
        path = '?'.join([path, uricomps.query])

    session.submit_request(0, [(':method', 'GET'),
                               (':scheme', 'https'),
                               (':path', path),
                               (':version', 'HTTP/1.1'),
                               (':host', hostport),
                               ('accept', '*/*'),
                               ('user-agent', 'python-spdylay')],
                           stream_user_data=req)

    while (session.want_read() or session.want_write()) \
            and not sessionctrl.finish:
        want_read = want_write = False
        try:
            data = sock.recv(4096)
            if data:
                session.recv(data)
            else:
                break
        except ssl.SSLWantReadError:
            want_read = True
        except ssl.SSLWantWriteError:
            want_write = True
        try:
            session.send()
        except ssl.SSLWantReadError:
            want_read = True
        except ssl.SSLWantWriteError:
            want_write = True

        if want_read or want_write:
            select.select([sock] if want_read else [],
                          [sock] if want_write else [],
                          [])

if __name__ == '__main__':
    uri = sys.argv[1]
    get(uri)
