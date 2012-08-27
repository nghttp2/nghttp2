#!/usr/bin/env python

import unittest
import io
import collections

import spdylay

class BufferList:
    def __init__(self):
        self.buffers = collections.deque()

    def add_buffer(self, bytebuf):
        self.buffers.append(bytebuf)

    def get_bytes(self, length):
        while self.buffers:
            first = self.buffers[0]
            data = first.read(length)
            if data:
                return data
            else:
                self.buffers.popleft()
        return None

class IOBridge:
    def __init__(self, inputs, outputs):
        self.inputs = inputs
        self.outputs = outputs

class Streams:
    def __init__(self, iob):
        self.iob = iob
        self.streams = {}
        self.recv_frames = []
        self.recv_data = io.BytesIO()

def recv_cb(session, length):
    iob = session.user_data.iob
    return iob.inputs.get_bytes(length)

def send_cb(session, data):
    iob = session.user_data.iob
    iob.outputs.add_buffer(io.BytesIO(data))
    return len(data)

def read_cb(session, stream_id, length, read_ctrl, source):
    data = source.read(length)
    if not data:
        read_ctrl.flags = spdylay.READ_EOF
    return data

def on_data_chunk_recv_cb(session, flags, stream_id, data):
    session.user_data.recv_data.write(data)

def on_ctrl_recv_cb(session, frame):
    session.user_data.recv_frames.append(frame)

class SpdylayTests(unittest.TestCase):

    def setUp(self):
        client_output = BufferList()
        server_output = BufferList()

        client_iob = IOBridge(server_output, client_output)
        server_iob = IOBridge(client_output, server_output)

        self.client_streams = Streams(client_iob)
        self.server_streams = Streams(server_iob)

        self.client_session = spdylay.Session(\
            spdylay.CLIENT,
            spdylay.PROTO_SPDY3,
            user_data=self.client_streams,
            recv_cb=recv_cb,
            send_cb=send_cb,
            on_ctrl_recv_cb=on_ctrl_recv_cb,
            on_data_chunk_recv_cb=on_data_chunk_recv_cb)

        self.server_session = spdylay.Session(\
            spdylay.SERVER,
            spdylay.PROTO_SPDY3,
            user_data=self.server_streams,
            recv_cb=recv_cb,
            send_cb=send_cb,
            on_ctrl_recv_cb=on_ctrl_recv_cb,
            on_data_chunk_recv_cb=on_data_chunk_recv_cb)

    def test_submit_request_and_response(self):
        data_prd = spdylay.DataProvider(io.BytesIO(b'Hello World'), read_cb)
        self.client_session.submit_request(0, [(u':method', u'POST')],
                                           data_prd=data_prd,
                                           stream_user_data=data_prd)
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(1, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[0]
        self.assertEqual(spdylay.SYN_STREAM, frame.frame_type)
        self.assertEqual(1, frame.stream_id)
        self.assertEqual(0, frame.assoc_stream_id)
        self.assertEqual(0, frame.pri)
        self.assertEqual((u':method', u'POST'), frame.nv[0])

        self.assertEqual(b'Hello World',
                         self.server_streams.recv_data.getvalue())

        self.assertEqual(data_prd, self.client_session.get_stream_user_data(1))

        data_prd = spdylay.DataProvider(io.BytesIO(b'Foo the bar'), read_cb)
        self.server_session.submit_response(1, [(u':status', u'200 OK')],
                                            data_prd=data_prd)
        self.server_session.send()
        self.client_session.recv()

        self.assertEqual(1, len(self.client_streams.recv_frames))
        frame = self.client_streams.recv_frames[0]
        self.assertEqual(spdylay.SYN_REPLY, frame.frame_type)
        self.assertEqual(1, frame.stream_id)
        self.assertEqual((u':status', u'200 OK'), frame.nv[0])

        self.assertEqual(b'Foo the bar',
                         self.client_streams.recv_data.getvalue())

    def test_submit_syn_stream_and_syn_stream(self):
        self.client_session.submit_syn_stream(spdylay.CTRL_FLAG_FIN, 2,
                                              [(u':path', u'/')])
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(1, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[0]
        self.assertEqual(spdylay.SYN_STREAM, frame.frame_type)
        self.assertEqual(1, frame.stream_id)
        self.assertEqual(0, frame.assoc_stream_id)
        self.assertEqual(2, frame.pri)
        self.assertEqual((u':path', u'/'), frame.nv[0])

        self.server_session.submit_syn_reply(spdylay.CTRL_FLAG_FIN, 1,
                                             [(u':version', u'HTTP/1.1')])
        self.server_session.send()
        self.client_session.recv()

        self.assertEqual(1, len(self.client_streams.recv_frames))
        frame = self.client_streams.recv_frames[0]
        self.assertEqual(spdylay.SYN_REPLY, frame.frame_type)
        self.assertEqual(1, frame.stream_id)
        self.assertEqual((u':version', u'HTTP/1.1'), frame.nv[0])

    def test_submit_rst_stream(self):
        self.client_session.submit_syn_stream(spdylay.CTRL_FLAG_FIN, 2,
                                              [(u':path', u'/')])
        self.client_session.send()
        self.server_session.recv()

        self.server_session.submit_rst_stream(1, spdylay.PROTOCOL_ERROR)
        self.server_session.send()
        self.client_session.recv()

        self.assertEqual(1, len(self.client_streams.recv_frames))
        frame = self.client_streams.recv_frames[0]
        self.assertEqual(spdylay.RST_STREAM, frame.frame_type)
        self.assertEqual(1, frame.stream_id)
        self.assertEqual(spdylay.PROTOCOL_ERROR, frame.status_code)

    def test_submit_goaway(self):
        self.client_session.submit_goaway(spdylay.GOAWAY_PROTOCOL_ERROR)
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(1, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[0]
        self.assertEqual(spdylay.GOAWAY, frame.frame_type)
        self.assertEqual(spdylay.GOAWAY_PROTOCOL_ERROR, frame.status_code)

    def test_resume_data(self):
        with self.assertRaises(spdylay.InvalidArgumentError):
            self.client_session.resume_data(1)

    def test_get_pri_lowest(self):
        self.assertEqual(7, self.client_session.get_pri_lowest())

    def test_fail_session(self):
        self.client_session.fail_session(spdylay.GOAWAY_PROTOCOL_ERROR)
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(1, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[0]
        self.assertEqual(spdylay.GOAWAY, frame.frame_type)
        self.assertEqual(spdylay.GOAWAY_PROTOCOL_ERROR, frame.status_code)

        self.assertFalse(self.client_session.want_read())
        self.assertFalse(self.client_session.want_write())

    def test_deferred_data(self):
        def deferred_read_cb(session, stream_id, length, read_ctrl, source):
            return spdylay.ERR_DEFERRED

        data_prd = spdylay.DataProvider(io.BytesIO(b'Hello World'),
                                        deferred_read_cb)
        self.client_session.submit_request(0, [(u':method', u'POST')],
                                           data_prd=data_prd,
                                           stream_user_data=data_prd)
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(1, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[0]
        self.assertEqual(spdylay.SYN_STREAM, frame.frame_type)
        self.assertEqual(1, frame.stream_id)
        self.assertEqual(0, frame.assoc_stream_id)
        self.assertEqual(0, frame.pri)
        self.assertEqual((u':method', u'POST'), frame.nv[0])

        self.assertEqual(b'', self.server_streams.recv_data.getvalue())

        data_prd.read_cb = read_cb

        self.client_session.resume_data(1)

        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(b'Hello World',
                         self.server_streams.recv_data.getvalue())

    def test_recv_cb_eof(self):
        def eof_recv_cb(session, length):
            raise spdylay.EOFError()

        self.client_session = spdylay.Session(\
            spdylay.CLIENT,
            spdylay.PROTO_SPDY3,
            user_data=self.client_streams,
            recv_cb=eof_recv_cb)

        with self.assertRaises(spdylay.EOFError):
            self.client_session.recv()

    def test_recv_cb_callback_failure(self):
        def cbfail_recv_cb(session, length):
            raise spdylay.CallbackFailureError()

        self.client_session = spdylay.Session(\
            spdylay.CLIENT,
            spdylay.PROTO_SPDY3,
            user_data=self.client_streams,
            recv_cb=cbfail_recv_cb)

        with self.assertRaises(spdylay.CallbackFailureError):
            self.client_session.recv()

    def test_send_cb_callback_failure(self):
        def cbfail_send_cb(session, data):
            raise spdylay.CallbackFailureError()

        self.client_session = spdylay.Session(\
            spdylay.CLIENT,
            spdylay.PROTO_SPDY3,
            user_data=self.client_streams,
            send_cb=cbfail_send_cb)

        self.client_session.submit_goaway(spdylay.GOAWAY_OK)

        with self.assertRaises(spdylay.CallbackFailureError):
            self.client_session.send()

    def test_submit_data(self):
        self.client_session.submit_syn_stream(spdylay.CTRL_FLAG_NONE, 2,
                                              [(u':path', u'/')])
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(1, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[0]
        self.assertEqual(spdylay.SYN_STREAM, frame.frame_type)
        self.assertEqual(1, frame.stream_id)

        data_prd = spdylay.DataProvider(io.BytesIO(b'Hello World'), read_cb)
        self.client_session.submit_data(1, spdylay.DATA_FLAG_FIN, data_prd)
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(b'Hello World',
                         self.server_streams.recv_data.getvalue())

    def test_submit_headers(self):
        self.client_session.submit_syn_stream(spdylay.CTRL_FLAG_NONE, 2,
                                              [(u':path', u'/')])
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(1, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[0]
        self.assertEqual(spdylay.SYN_STREAM, frame.frame_type)
        self.assertEqual(1, frame.stream_id)

        self.client_session.submit_headers(spdylay.CTRL_FLAG_FIN, 1,
                                           [(u':host', u'localhost')])
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(2, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[1]
        self.assertEqual(spdylay.HEADERS, frame.frame_type)
        self.assertEqual(1, frame.stream_id)
        self.assertEqual((u':host', u'localhost'), frame.nv[0])

    def test_submit_ping(self):
        self.client_session.submit_ping()
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(1, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[0]
        self.assertEqual(spdylay.PING, frame.frame_type)
        self.assertEqual(1, frame.unique_id)

    def test_submit_window_update(self):
        self.client_session.submit_syn_stream(spdylay.CTRL_FLAG_NONE, 2,
                                              [(u':path', u'/')])
        self.client_session.send()
        self.server_session.recv()

        self.assertEqual(1, len(self.server_streams.recv_frames))
        frame = self.server_streams.recv_frames[0]
        self.assertEqual(spdylay.SYN_STREAM, frame.frame_type)
        self.assertEqual(1, frame.stream_id)

        self.server_session.submit_window_update(1, 4096)
        self.server_session.send()
        self.client_session.recv()

        self.assertEqual(1, len(self.client_streams.recv_frames))
        frame = self.client_streams.recv_frames[0]
        self.assertEqual(spdylay.WINDOW_UPDATE, frame.frame_type)
        self.assertEqual(1, frame.stream_id)
        self.assertEqual(4096, frame.delta_window_size)

    def test_get_npn_protocols(self):
        protos = spdylay.get_npn_protocols()
        self.assertEqual(['spdy/3', 'spdy/2'], protos)

if __name__ == '__main__':
    unittest.main()
