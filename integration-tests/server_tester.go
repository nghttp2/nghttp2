package nghttp2

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/bradfitz/http2"
	"github.com/bradfitz/http2/hpack"
	"github.com/tatsuhiro-t/go-nghttp2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	serverBin  = buildDir + "/src/nghttpx"
	serverPort = 3009
)

func pair(name, value string) hpack.HeaderField {
	return hpack.HeaderField{
		Name:  name,
		Value: value,
	}
}

type serverTester struct {
	args          []string  // command-line arguments
	cmd           *exec.Cmd // test frontend server process, which is test subject
	t             *testing.T
	ts            *httptest.Server // backend server
	conn          net.Conn         // connection to frontend server
	h2PrefaceSent bool             // HTTP/2 preface was sent in conn
	nextStreamID  uint32           // next stream ID
	fr            *http2.Framer
	headerBlkBuf  bytes.Buffer // buffer to store encoded header block
	enc           *hpack.Encoder
	header        http.Header // received header fields
	dec           *hpack.Decoder
	authority     string // server's host:port
	frCh          chan http2.Frame
	errCh         chan error
}

func newServerTester(args []string, t *testing.T, handler http.HandlerFunc) *serverTester {
	ts := httptest.NewUnstartedServer(handler)

	backendTLS := false
	for _, k := range args {
		if k == "--http2-bridge" {
			backendTLS = true
			break
		}
	}
	if backendTLS {
		nghttp2.ConfigureServer(ts.Config, &nghttp2.Server{})
		// According to httptest/server.go, we have to set
		// NextProtos separately for ts.TLS.  NextProtos set
		// in nghttp2.ConfigureServer is effectively ignored.
		ts.TLS = new(tls.Config)
		ts.TLS.NextProtos = append(ts.TLS.NextProtos, "h2-14")
		ts.StartTLS()
		args = append(args, "-k")
	} else {
		ts.Start()
	}
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("Error parsing URL from httptest.Server: %v", err)
	}

	// URL.Host looks like "127.0.0.1:8080", but we want
	// "127.0.0.1,8080"
	b := "-b" + strings.Replace(u.Host, ":", ",", -1)
	args = append(args, fmt.Sprintf("-f127.0.0.1,%v", serverPort), b,
		"--errorlog-file="+buildDir+"/integration-tests/log.txt",
		"-LINFO", "--frontend-no-tls")

	st := &serverTester{
		cmd:          exec.Command(serverBin, args...),
		t:            t,
		ts:           ts,
		nextStreamID: 1,
		authority:    u.Host,
		frCh:         make(chan http2.Frame),
		errCh:        make(chan error),
	}

	if err := st.cmd.Start(); err != nil {
		st.t.Fatalf("Error starting %v: %v", serverBin, err)
	}

	retry := 0
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%v", serverPort))
		if err != nil {
			retry += 1
			if retry >= 10 {
				st.t.Fatalf("Error server is not responding too long; server command-line arguments may be invalid")
			}
			time.Sleep(150 * time.Millisecond)
			continue
		}
		st.conn = conn
		break
	}

	st.fr = http2.NewFramer(st.conn, st.conn)
	st.enc = hpack.NewEncoder(&st.headerBlkBuf)
	st.dec = hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		st.header.Add(f.Name, f.Value)
	})

	return st
}

func (st *serverTester) Close() {
	if st.conn != nil {
		st.conn.Close()
	}
	if st.cmd != nil {
		st.cmd.Process.Kill()
		st.cmd.Wait()
	}
	if st.ts != nil {
		st.ts.Close()
	}
}

func (st *serverTester) readFrame() (http2.Frame, error) {
	go func() {
		f, err := st.fr.ReadFrame()
		if err != nil {
			st.errCh <- err
			return
		}
		st.frCh <- f
	}()

	select {
	case f := <-st.frCh:
		return f, nil
	case err := <-st.errCh:
		return nil, err
	case <-time.After(2 * time.Second):
		return nil, errors.New("timeout waiting for frame")
	}
}

type requestParam struct {
	name      string              // name for this request to identify the request in log easily
	streamID  uint32              // stream ID, automatically assigned if 0
	method    string              // method, defaults to GET
	scheme    string              // scheme, defaults to http
	authority string              // authority, defaults to backend server address
	path      string              // path, defaults to /
	header    []hpack.HeaderField // additional request header fields
	body      []byte              // request body
}

func (st *serverTester) http2(rp requestParam) (*serverResponse, error) {
	res := &serverResponse{}
	st.headerBlkBuf.Reset()
	st.header = make(http.Header)

	var id uint32
	if rp.streamID != 0 {
		id = rp.streamID
		if id >= st.nextStreamID && id%2 == 1 {
			st.nextStreamID = id + 2
		}
	} else {
		id = st.nextStreamID
		st.nextStreamID += 2
	}

	if !st.h2PrefaceSent {
		st.h2PrefaceSent = true
		fmt.Fprint(st.conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
		if err := st.fr.WriteSettings(); err != nil {
			return nil, err
		}
	}

	method := "GET"
	if rp.method != "" {
		method = rp.method
	}
	_ = st.enc.WriteField(pair(":method", method))

	scheme := "http"
	if rp.scheme != "" {
		scheme = rp.scheme
	}
	_ = st.enc.WriteField(pair(":scheme", scheme))

	authority := st.authority
	if rp.authority != "" {
		authority = rp.authority
	}
	_ = st.enc.WriteField(pair(":authority", authority))

	path := "/"
	if rp.path != "" {
		path = rp.path
	}
	_ = st.enc.WriteField(pair(":path", path))

	_ = st.enc.WriteField(pair("test-case", rp.name))

	for _, h := range rp.header {
		_ = st.enc.WriteField(pair(strings.ToLower(h.Name), h.Value))
	}

	err := st.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		EndStream:     len(rp.body) == 0,
		EndHeaders:    true,
		BlockFragment: st.headerBlkBuf.Bytes(),
	})
	if err != nil {
		return nil, err
	}

	if len(rp.body) != 0 {
		// TODO we assume rp.body fits in 1 frame
		if err := st.fr.WriteData(id, true, rp.body); err != nil {
			return nil, err
		}
	}

loop:
	for {
		fr, err := st.readFrame()
		if err != nil {
			return res, err
		}
		switch f := fr.(type) {
		case *http2.HeadersFrame:
			_, err := st.dec.Write(f.HeaderBlockFragment())
			if err != nil {
				return res, err
			}
			if f.FrameHeader.StreamID != id {
				st.header = make(http.Header)
				break
			}
			res.header = cloneHeader(st.header)
			res.status, err = strconv.Atoi(res.header.Get(":status"))
			if err != nil {
				return res, fmt.Errorf("Error parsing status code: %v", err)
			}

			if f.StreamEnded() {
				break loop
			}
		case *http2.DataFrame:
			if f.FrameHeader.StreamID != id {
				break
			}
			res.body = append(res.body, f.Data()...)
			if f.StreamEnded() {
				break loop
			}
		case *http2.RSTStreamFrame:
			if f.FrameHeader.StreamID != id {
				break
			}
			res.errCode = f.ErrCode
			break loop
		case *http2.GoAwayFrame:
			if f.FrameHeader.StreamID != id || f.ErrCode == http2.ErrCodeNo {
				break
			}
			res.errCode = f.ErrCode
			res.connErr = true
			break loop
		case *http2.SettingsFrame:
			if f.IsAck() {
				break
			}
			if err := st.fr.WriteSettingsAck(); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

type serverResponse struct {
	status  int           // HTTP status code
	header  http.Header   // response header fields
	body    []byte        // response body
	errCode http2.ErrCode // error code received in RST_STREAM or GOAWAY
	connErr bool          // true if connection error
}

func cloneHeader(h http.Header) http.Header {
	h2 := make(http.Header, len(h))
	for k, vv := range h {
		vv2 := make([]string, len(vv))
		copy(vv2, vv)
		h2[k] = vv2
	}
	return h2
}

func noopHandler(w http.ResponseWriter, r *http.Request) {}
