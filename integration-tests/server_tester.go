package nghttp2

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/tatsuhiro-t/go-nghttp2"
	"github.com/tatsuhiro-t/spdy"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/net/websocket"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	serverBin  = buildDir + "/src/nghttpx"
	serverPort = 3009
	testDir    = sourceDir + "/integration-tests"
	logDir     = buildDir + "/integration-tests"
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
	url           string    // test frontend server URL
	t             *testing.T
	ts            *httptest.Server // backend server
	frontendHost  string           // frontend server host
	backendHost   string           // backend server host
	conn          net.Conn         // connection to frontend server
	h2PrefaceSent bool             // HTTP/2 preface was sent in conn
	nextStreamID  uint32           // next stream ID
	fr            *http2.Framer    // HTTP/2 framer
	spdyFr        *spdy.Framer     // SPDY/3.1 framer
	headerBlkBuf  bytes.Buffer     // buffer to store encoded header block
	enc           *hpack.Encoder   // HTTP/2 HPACK encoder
	header        http.Header      // received header fields
	dec           *hpack.Decoder   // HTTP/2 HPACK decoder
	authority     string           // server's host:port
	frCh          chan http2.Frame // used for incoming HTTP/2 frame
	spdyFrCh      chan spdy.Frame  // used for incoming SPDY frame
	errCh         chan error
}

// newServerTester creates test context for plain TCP frontend
// connection.
func newServerTester(args []string, t *testing.T, handler http.HandlerFunc) *serverTester {
	return newServerTesterInternal(args, t, handler, false, serverPort, nil)
}

func newServerTesterConnectPort(args []string, t *testing.T, handler http.HandlerFunc, port int) *serverTester {
	return newServerTesterInternal(args, t, handler, false, port, nil)
}

func newServerTesterHandler(args []string, t *testing.T, handler http.Handler) *serverTester {
	return newServerTesterInternal(args, t, handler, false, serverPort, nil)
}

// newServerTester creates test context for TLS frontend connection.
func newServerTesterTLS(args []string, t *testing.T, handler http.HandlerFunc) *serverTester {
	return newServerTesterInternal(args, t, handler, true, serverPort, nil)
}

func newServerTesterTLSConnectPort(args []string, t *testing.T, handler http.HandlerFunc, port int) *serverTester {
	return newServerTesterInternal(args, t, handler, true, port, nil)
}

// newServerTester creates test context for TLS frontend connection
// with given clientConfig
func newServerTesterTLSConfig(args []string, t *testing.T, handler http.HandlerFunc, clientConfig *tls.Config) *serverTester {
	return newServerTesterInternal(args, t, handler, true, serverPort, clientConfig)
}

// newServerTesterInternal creates test context.  If frontendTLS is
// true, set up TLS frontend connection.  connectPort is the server
// side port where client connection is made.
func newServerTesterInternal(src_args []string, t *testing.T, handler http.Handler, frontendTLS bool, connectPort int, clientConfig *tls.Config) *serverTester {
	ts := httptest.NewUnstartedServer(handler)

	args := []string{}

	var backendTLS, dns, externalDNS, acceptProxyProtocol, redirectIfNotTLS bool

	for _, k := range src_args {
		switch k {
		case "--http2-bridge":
			backendTLS = true
		case "--dns":
			dns = true
		case "--external-dns":
			dns = true
			externalDNS = true
		case "--accept-proxy-protocol":
			acceptProxyProtocol = true
		case "--redirect-if-not-tls":
			redirectIfNotTLS = true
		default:
			args = append(args, k)
		}
	}
	if backendTLS {
		nghttp2.ConfigureServer(ts.Config, &nghttp2.Server{})
		// According to httptest/server.go, we have to set
		// NextProtos separately for ts.TLS.  NextProtos set
		// in nghttp2.ConfigureServer is effectively ignored.
		ts.TLS = new(tls.Config)
		ts.TLS.NextProtos = append(ts.TLS.NextProtos, "h2")
		ts.StartTLS()
		args = append(args, "-k")
	} else {
		ts.Start()
	}
	scheme := "http"
	if frontendTLS {
		scheme = "https"
		args = append(args, testDir+"/server.key", testDir+"/server.crt")
	}

	backendURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("Error parsing URL from httptest.Server: %v", err)
	}

	// URL.Host looks like "127.0.0.1:8080", but we want
	// "127.0.0.1,8080"
	b := "-b"
	if !externalDNS {
		b += fmt.Sprintf("%v;", strings.Replace(backendURL.Host, ":", ",", -1))
	} else {
		sep := strings.LastIndex(backendURL.Host, ":")
		if sep == -1 {
			t.Fatalf("backendURL.Host %v does not contain separator ':'", backendURL.Host)
		}
		// We use awesome service nip.io.
		b += fmt.Sprintf("%v.nip.io,%v;", backendURL.Host[:sep], backendURL.Host[sep+1:])
	}

	if backendTLS {
		b += ";proto=h2;tls"
	}
	if dns {
		b += ";dns"
	}

	if redirectIfNotTLS {
		b += ";redirect-if-not-tls"
	}

	noTLS := ";no-tls"
	if frontendTLS {
		noTLS = ""
	}

	var proxyProto string
	if acceptProxyProtocol {
		proxyProto = ";proxyproto"
	}

	args = append(args, fmt.Sprintf("-f127.0.0.1,%v%v%v", serverPort, noTLS, proxyProto), b,
		"--errorlog-file="+logDir+"/log.txt", "-LINFO")

	authority := fmt.Sprintf("127.0.0.1:%v", connectPort)

	st := &serverTester{
		cmd:          exec.Command(serverBin, args...),
		t:            t,
		ts:           ts,
		url:          fmt.Sprintf("%v://%v", scheme, authority),
		frontendHost: fmt.Sprintf("127.0.0.1:%v", serverPort),
		backendHost:  backendURL.Host,
		nextStreamID: 1,
		authority:    authority,
		frCh:         make(chan http2.Frame),
		spdyFrCh:     make(chan spdy.Frame),
		errCh:        make(chan error),
	}

	st.cmd.Stdout = os.Stdout
	st.cmd.Stderr = os.Stderr

	if err := st.cmd.Start(); err != nil {
		st.t.Fatalf("Error starting %v: %v", serverBin, err)
	}

	retry := 0
	for {
		time.Sleep(50 * time.Millisecond)

		var conn net.Conn
		var err error
		if frontendTLS {
			var tlsConfig *tls.Config
			if clientConfig == nil {
				tlsConfig = new(tls.Config)
			} else {
				tlsConfig = clientConfig
			}
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.NextProtos = []string{"h2", "spdy/3.1"}
			conn, err = tls.Dial("tcp", authority, tlsConfig)
		} else {
			conn, err = net.Dial("tcp", authority)
		}
		if err != nil {
			retry += 1
			if retry >= 100 {
				st.Close()
				st.t.Fatalf("Error server is not responding too long; server command-line arguments may be invalid")
			}
			continue
		}
		if frontendTLS {
			tlsConn := conn.(*tls.Conn)
			cs := tlsConn.ConnectionState()
			if !cs.NegotiatedProtocolIsMutual {
				st.Close()
				st.t.Fatalf("Error negotiated next protocol is not mutual")
			}
		}
		st.conn = conn
		break
	}

	st.fr = http2.NewFramer(st.conn, st.conn)
	spdyFr, err := spdy.NewFramer(st.conn, st.conn)
	if err != nil {
		st.Close()
		st.t.Fatalf("Error spdy.NewFramer: %v", err)
	}
	st.spdyFr = spdyFr
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
		done := make(chan struct{})
		go func() {
			st.cmd.Wait()
			close(done)
		}()

		st.cmd.Process.Signal(syscall.SIGQUIT)

		select {
		case <-done:
		case <-time.After(10 * time.Second):
			st.cmd.Process.Kill()
			<-done
		}
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
	case <-time.After(5 * time.Second):
		return nil, errors.New("timeout waiting for frame")
	}
}

func (st *serverTester) readSpdyFrame() (spdy.Frame, error) {
	go func() {
		f, err := st.spdyFr.ReadFrame()
		if err != nil {
			st.errCh <- err
			return
		}
		st.spdyFrCh <- f
	}()

	select {
	case f := <-st.spdyFrCh:
		return f, nil
	case err := <-st.errCh:
		return nil, err
	case <-time.After(2 * time.Second):
		return nil, errors.New("timeout waiting for frame")
	}
}

type requestParam struct {
	name        string              // name for this request to identify the request in log easily
	streamID    uint32              // stream ID, automatically assigned if 0
	method      string              // method, defaults to GET
	scheme      string              // scheme, defaults to http
	authority   string              // authority, defaults to backend server address
	path        string              // path, defaults to /
	header      []hpack.HeaderField // additional request header fields
	body        []byte              // request body
	trailer     []hpack.HeaderField // trailer part
	httpUpgrade bool                // true if upgraded to HTTP/2 through HTTP Upgrade
	noEndStream bool                // true if END_STREAM should not be sent
}

// wrapper for request body to set trailer part
type chunkedBodyReader struct {
	trailer        []hpack.HeaderField
	trailerWritten bool
	body           io.Reader
	req            *http.Request
}

func (cbr *chunkedBodyReader) Read(p []byte) (n int, err error) {
	// document says that we have to set http.Request.Trailer
	// after request was sent and before body returns EOF.
	if !cbr.trailerWritten {
		cbr.trailerWritten = true
		for _, h := range cbr.trailer {
			cbr.req.Trailer.Set(h.Name, h.Value)
		}
	}
	return cbr.body.Read(p)
}

func (st *serverTester) websocket(rp requestParam) (*serverResponse, error) {
	urlstring := st.url + "/echo"

	config, err := websocket.NewConfig(urlstring, st.url)
	if err != nil {
		st.t.Fatalf("websocket.NewConfig(%q, %q) returned error: %v", urlstring, st.url, err)
	}

	config.Header.Add("Test-Case", rp.name)
	for _, h := range rp.header {
		config.Header.Add(h.Name, h.Value)
	}

	ws, err := websocket.NewClient(config, st.conn)
	if err != nil {
		st.t.Fatalf("Error creating websocket client: %v", err)
	}

	if _, err := ws.Write(rp.body); err != nil {
		st.t.Fatalf("ws.Write() returned error: %v", err)
	}

	msg := make([]byte, 1024)
	var n int
	if n, err = ws.Read(msg); err != nil {
		st.t.Fatalf("ws.Read() returned error: %v", err)
	}

	res := &serverResponse{
		body: msg[:n],
	}

	return res, nil
}

func (st *serverTester) http1(rp requestParam) (*serverResponse, error) {
	method := "GET"
	if rp.method != "" {
		method = rp.method
	}

	var body io.Reader
	var cbr *chunkedBodyReader
	if rp.body != nil {
		body = bytes.NewBuffer(rp.body)
		if len(rp.trailer) != 0 {
			cbr = &chunkedBodyReader{
				trailer: rp.trailer,
				body:    body,
			}
			body = cbr
		}
	}

	reqURL := st.url

	if rp.path != "" {
		u, err := url.Parse(st.url)
		if err != nil {
			st.t.Fatalf("Error parsing URL from st.url %v: %v", st.url, err)
		}
		u.Path = ""
		u.RawQuery = ""
		reqURL = u.String() + rp.path
	}

	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return nil, err
	}
	for _, h := range rp.header {
		req.Header.Add(h.Name, h.Value)
	}
	req.Header.Add("Test-Case", rp.name)
	if cbr != nil {
		cbr.req = req
		// this makes request use chunked encoding
		req.ContentLength = -1
		req.Trailer = make(http.Header)
		for _, h := range cbr.trailer {
			req.Trailer.Set(h.Name, "")
		}
	}
	if err := req.Write(st.conn); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(st.conn), req)
	if err != nil {
		return nil, err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	res := &serverResponse{
		status:    resp.StatusCode,
		header:    resp.Header,
		body:      respBody,
		connClose: resp.Close,
	}

	return res, nil
}

func (st *serverTester) spdy(rp requestParam) (*serverResponse, error) {
	res := &serverResponse{}

	var id spdy.StreamId
	if rp.streamID != 0 {
		id = spdy.StreamId(rp.streamID)
		if id >= spdy.StreamId(st.nextStreamID) && id%2 == 1 {
			st.nextStreamID = uint32(id) + 2
		}
	} else {
		id = spdy.StreamId(st.nextStreamID)
		st.nextStreamID += 2
	}

	method := "GET"
	if rp.method != "" {
		method = rp.method
	}

	scheme := "http"
	if rp.scheme != "" {
		scheme = rp.scheme
	}

	host := st.authority
	if rp.authority != "" {
		host = rp.authority
	}

	path := "/"
	if rp.path != "" {
		path = rp.path
	}

	header := make(http.Header)
	header.Add(":method", method)
	header.Add(":scheme", scheme)
	header.Add(":host", host)
	header.Add(":path", path)
	header.Add(":version", "HTTP/1.1")
	header.Add("test-case", rp.name)
	for _, h := range rp.header {
		header.Add(h.Name, h.Value)
	}

	var synStreamFlags spdy.ControlFlags
	if len(rp.body) == 0 && !rp.noEndStream {
		synStreamFlags = spdy.ControlFlagFin
	}
	if err := st.spdyFr.WriteFrame(&spdy.SynStreamFrame{
		CFHeader: spdy.ControlFrameHeader{
			Flags: synStreamFlags,
		},
		StreamId: id,
		Headers:  header,
	}); err != nil {
		return nil, err
	}

	if len(rp.body) != 0 {
		var dataFlags spdy.DataFlags
		if !rp.noEndStream {
			dataFlags = spdy.DataFlagFin
		}
		if err := st.spdyFr.WriteFrame(&spdy.DataFrame{
			StreamId: id,
			Flags:    dataFlags,
			Data:     rp.body,
		}); err != nil {
			return nil, err
		}
	}

loop:
	for {
		fr, err := st.readSpdyFrame()
		if err != nil {
			return res, err
		}
		switch f := fr.(type) {
		case *spdy.SynReplyFrame:
			if f.StreamId != id {
				break
			}
			res.header = cloneHeader(f.Headers)
			if _, err := fmt.Sscan(res.header.Get(":status"), &res.status); err != nil {
				return res, fmt.Errorf("Error parsing status code: %v", err)
			}
			if f.CFHeader.Flags&spdy.ControlFlagFin != 0 {
				break loop
			}
		case *spdy.DataFrame:
			if f.StreamId != id {
				break
			}
			res.body = append(res.body, f.Data...)
			if f.Flags&spdy.DataFlagFin != 0 {
				break loop
			}
		case *spdy.RstStreamFrame:
			if f.StreamId != id {
				break
			}
			res.spdyRstErrCode = f.Status
			break loop
		case *spdy.GoAwayFrame:
			if f.Status == spdy.GoAwayOK {
				break
			}
			res.spdyGoAwayErrCode = f.Status
			break loop
		}
	}
	return res, nil
}

func (st *serverTester) http2(rp requestParam) (*serverResponse, error) {
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

	res := &serverResponse{
		streamID: id,
	}

	streams := make(map[uint32]*serverResponse)
	streams[id] = res

	if !rp.httpUpgrade {
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
			_ = st.enc.WriteField(h)
		}

		err := st.fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      id,
			EndStream:     len(rp.body) == 0 && len(rp.trailer) == 0 && !rp.noEndStream,
			EndHeaders:    true,
			BlockFragment: st.headerBlkBuf.Bytes(),
		})
		if err != nil {
			return nil, err
		}

		if len(rp.body) != 0 {
			// TODO we assume rp.body fits in 1 frame
			if err := st.fr.WriteData(id, len(rp.trailer) == 0 && !rp.noEndStream, rp.body); err != nil {
				return nil, err
			}
		}

		if len(rp.trailer) != 0 {
			st.headerBlkBuf.Reset()
			for _, h := range rp.trailer {
				_ = st.enc.WriteField(h)
			}
			err := st.fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      id,
				EndStream:     true,
				EndHeaders:    true,
				BlockFragment: st.headerBlkBuf.Bytes(),
			})
			if err != nil {
				return nil, err
			}
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
			sr, ok := streams[f.FrameHeader.StreamID]
			if !ok {
				st.header = make(http.Header)
				break
			}
			sr.header = cloneHeader(st.header)
			var status int
			status, err = strconv.Atoi(sr.header.Get(":status"))
			if err != nil {
				return res, fmt.Errorf("Error parsing status code: %v", err)
			}
			sr.status = status
			if f.StreamEnded() {
				if streamEnded(res, streams, sr) {
					break loop
				}
			}
		case *http2.PushPromiseFrame:
			_, err := st.dec.Write(f.HeaderBlockFragment())
			if err != nil {
				return res, err
			}
			sr := &serverResponse{
				streamID:  f.PromiseID,
				reqHeader: cloneHeader(st.header),
			}
			streams[sr.streamID] = sr
		case *http2.DataFrame:
			sr, ok := streams[f.FrameHeader.StreamID]
			if !ok {
				break
			}
			sr.body = append(sr.body, f.Data()...)
			if f.StreamEnded() {
				if streamEnded(res, streams, sr) {
					break loop
				}
			}
		case *http2.RSTStreamFrame:
			sr, ok := streams[f.FrameHeader.StreamID]
			if !ok {
				break
			}
			sr.errCode = f.ErrCode
			if streamEnded(res, streams, sr) {
				break loop
			}
		case *http2.GoAwayFrame:
			if f.ErrCode == http2.ErrCodeNo {
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
	sort.Sort(ByStreamID(res.pushResponse))
	return res, nil
}

func streamEnded(mainSr *serverResponse, streams map[uint32]*serverResponse, sr *serverResponse) bool {
	delete(streams, sr.streamID)
	if mainSr.streamID != sr.streamID {
		mainSr.pushResponse = append(mainSr.pushResponse, sr)
	}
	return len(streams) == 0
}

type serverResponse struct {
	status            int                  // HTTP status code
	header            http.Header          // response header fields
	body              []byte               // response body
	streamID          uint32               // stream ID in HTTP/2
	errCode           http2.ErrCode        // error code received in HTTP/2 RST_STREAM or GOAWAY
	connErr           bool                 // true if HTTP/2 connection error
	spdyGoAwayErrCode spdy.GoAwayStatus    // status code received in SPDY RST_STREAM
	spdyRstErrCode    spdy.RstStreamStatus // status code received in SPDY GOAWAY
	connClose         bool                 // Connection: close is included in response header in HTTP/1 test
	reqHeader         http.Header          // http request header, currently only sotres pushed request header
	pushResponse      []*serverResponse    // pushed response
}

type ByStreamID []*serverResponse

func (b ByStreamID) Len() int {
	return len(b)
}

func (b ByStreamID) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

func (b ByStreamID) Less(i, j int) bool {
	return b[i].streamID < b[j].streamID
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

type APIResponse struct {
	Status string                 `json:"status,omitempty"`
	Code   int                    `json:"code,omitempty"`
	Data   map[string]interface{} `json:"data,omitempty"`
}
