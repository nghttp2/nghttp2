package nghttp2

import (
	"crypto/tls"
	"fmt"
	"github.com/bradfitz/http2"
	"github.com/bradfitz/http2/hpack"
	"io"
	"io/ioutil"
	"net/http"
	"syscall"
	"testing"
)

// TestH2H1PlainGET tests whether simple HTTP/2 GET request works.
func TestH2H1PlainGET(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1PlainGET",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}

	want := 200
	if res.status != want {
		t.Errorf("status = %v; want %v", res.status, want)
	}
}

// TestH2H1AddXff tests that server generates X-Forwarded-For header
// field when forwarding request to backend.
func TestH2H1AddXff(t *testing.T) {
	st := newServerTester([]string{"--add-x-forwarded-for"}, t, func(w http.ResponseWriter, r *http.Request) {
		xff := r.Header.Get("X-Forwarded-For")
		want := "127.0.0.1"
		if xff != want {
			t.Errorf("X-Forwarded-For = %v; want %v", xff, want)
		}
	})
	defer st.Close()

	_, err := st.http2(requestParam{
		name: "TestH2H1AddXff",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
}

// TestH2H1AddXff2 tests that server appends X-Forwarded-For header
// field to existing one when forwarding request to backend.
func TestH2H1AddXff2(t *testing.T) {
	st := newServerTester([]string{"--add-x-forwarded-for"}, t, func(w http.ResponseWriter, r *http.Request) {
		xff := r.Header.Get("X-Forwarded-For")
		want := "host, 127.0.0.1"
		if xff != want {
			t.Errorf("X-Forwarded-For = %v; want %v", xff, want)
		}
	})
	defer st.Close()

	_, err := st.http2(requestParam{
		name: "TestH2H1AddXff2",
		header: []hpack.HeaderField{
			pair("x-forwarded-for", "host"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
}

// TestH2H1StripXff tests that --strip-incoming-x-forwarded-for
// option.
func TestH2H1StripXff(t *testing.T) {
	st := newServerTester([]string{"--strip-incoming-x-forwarded-for"}, t, func(w http.ResponseWriter, r *http.Request) {
		if xff, found := r.Header["X-Forwarded-For"]; found {
			t.Errorf("X-Forwarded-For = %v; want nothing", xff)
		}
	})
	defer st.Close()

	_, err := st.http2(requestParam{
		name: "TestH2H1StripXff1",
		header: []hpack.HeaderField{
			pair("x-forwarded-for", "host"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
}

// TestH2H1StripAddXff tests that --strip-incoming-x-forwarded-for and
// --add-x-forwarded-for options.
func TestH2H1StripAddXff(t *testing.T) {
	args := []string{
		"--strip-incoming-x-forwarded-for",
		"--add-x-forwarded-for",
	}
	st := newServerTester(args, t, func(w http.ResponseWriter, r *http.Request) {
		xff := r.Header.Get("X-Forwarded-For")
		want := "127.0.0.1"
		if xff != want {
			t.Errorf("X-Forwarded-For = %v; want %v", xff, want)
		}
	})
	defer st.Close()

	_, err := st.http2(requestParam{
		name: "TestH2H1StripAddXff",
		header: []hpack.HeaderField{
			pair("x-forwarded-for", "host"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
}

// TestH2H1GenerateVia tests that server generates Via header field to and
// from backend server.
func TestH2H1GenerateVia(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Via"), "2.0 nghttpx"; got != want {
			t.Errorf("Via: %v; want %v", got, want)
		}
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1GenerateVia",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	if got, want := res.header.Get("Via"), "1.1 nghttpx"; got != want {
		t.Errorf("Via: %v; want %v", got, want)
	}
}

// TestH2H1AppendVia tests that server adds value to existing Via
// header field to and from backend server.
func TestH2H1AppendVia(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Via"), "foo, 2.0 nghttpx"; got != want {
			t.Errorf("Via: %v; want %v", got, want)
		}
		w.Header().Add("Via", "bar")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1AppendVia",
		header: []hpack.HeaderField{
			pair("via", "foo"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	if got, want := res.header.Get("Via"), "bar, 1.1 nghttpx"; got != want {
		t.Errorf("Via: %v; want %v", got, want)
	}
}

// TestH2H1NoVia tests that server does not add value to existing Via
// header field to and from backend server.
func TestH2H1NoVia(t *testing.T) {
	st := newServerTester([]string{"--no-via"}, t, func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Via"), "foo"; got != want {
			t.Errorf("Via: %v; want %v", got, want)
		}
		w.Header().Add("Via", "bar")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1NoVia",
		header: []hpack.HeaderField{
			pair("via", "foo"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	if got, want := res.header.Get("Via"), "bar"; got != want {
		t.Errorf("Via: %v; want %v", got, want)
	}
}

// TestH2H1HostRewrite tests that server rewrites host header field
func TestH2H1HostRewrite(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("request-host", r.Host)
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1HostRewrite",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	if got, want := res.status, 200; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
	if got, want := res.header.Get("request-host"), st.backendHost; got != want {
		t.Errorf("request-host: %v; want %v", got, want)
	}
}

// TestH2H1BadRequestCL tests that server rejects request whose
// content-length header field value does not match its request body
// size.
func TestH2H1BadRequestCL(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	// we set content-length: 1024, but the actual request body is
	// 3 bytes.
	res, err := st.http2(requestParam{
		name:   "TestH2H1BadRequestCL",
		method: "POST",
		header: []hpack.HeaderField{
			pair("content-length", "1024"),
		},
		body: []byte("foo"),
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}

	want := http2.ErrCodeProtocol
	if res.errCode != want {
		t.Errorf("res.errCode = %v; want %v", res.errCode, want)
	}
}

// TestH2H1BadResponseCL tests that server returns error when
// content-length response header field value does not match its
// response body size.
func TestH2H1BadResponseCL(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		// we set content-length: 1024, but only send 3 bytes.
		w.Header().Add("Content-Length", "1024")
		w.Write([]byte("foo"))
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1BadResponseCL",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}

	want := http2.ErrCodeProtocol
	if res.errCode != want {
		t.Errorf("res.errCode = %v; want %v", res.errCode, want)
	}
}

// TestH2H1LocationRewrite tests location header field rewriting
// works.
func TestH2H1LocationRewrite(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		// TODO we cannot get st.ts's port number here.. 8443
		// is just a place holder.  We ignore it on rewrite.
		w.Header().Add("Location", "http://127.0.0.1:8443/p/q?a=b#fragment")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1LocationRewrite",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}

	want := fmt.Sprintf("http://127.0.0.1:%v/p/q?a=b#fragment", serverPort)
	if got := res.header.Get("Location"); got != want {
		t.Errorf("Location: %v; want %v", got, want)
	}
}

// TestH2H1ChunkedRequestBody tests that chunked request body works.
func TestH2H1ChunkedRequestBody(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		want := "[chunked]"
		if got := fmt.Sprint(r.TransferEncoding); got != want {
			t.Errorf("Transfer-Encoding: %v; want %v", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Error reading r.body: %v", err)
		}
		want = "foo"
		if got := string(body); got != want {
			t.Errorf("body: %v; want %v", got, want)
		}
	})
	defer st.Close()

	_, err := st.http2(requestParam{
		name:   "TestH2H1ChunkedRequestBody",
		method: "POST",
		body:   []byte("foo"),
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
}

// TestH2H1MultipleRequestCL tests that server rejects request with
// multiple Content-Length request header fields.
func TestH2H1MultipleRequestCL(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward bad request")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1MultipleRequestCL",
		header: []hpack.HeaderField{
			pair("content-length", "1"),
			pair("content-length", "1"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	want := 400
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestH2H1InvalidRequestCL tests that server rejects request with
// Content-Length which cannot be parsed as a number.
func TestH2H1InvalidRequestCL(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward bad request")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1InvalidRequestCL",
		header: []hpack.HeaderField{
			pair("content-length", ""),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	want := 400
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestH2H1ConnectFailure tests that server handles the situation that
// connection attempt to HTTP/1 backend failed.
func TestH2H1ConnectFailure(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	// shutdown backend server to simulate backend connect failure
	st.ts.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1ConnectFailure",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	want := 503
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestH2H1AssembleCookies tests that crumbled cookies in HTTP/2
// request is assembled into 1 when forwarding to HTTP/1 backend link.
func TestH2H1AssembleCookies(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Cookie"), "alpha; bravo; charlie"; got != want {
			t.Errorf("Cookie: %v; want %v", got, want)
		}
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1AssembleCookies",
		header: []hpack.HeaderField{
			pair("cookie", "alpha"),
			pair("cookie", "bravo"),
			pair("cookie", "charlie"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	if got, want := res.status, 200; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestH2H1TETrailers tests that server accepts TE request header
// field if it has trailers only.
func TestH2H1TETrailers(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1TETrailers",
		header: []hpack.HeaderField{
			pair("te", "trailers"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	if got, want := res.status, 200; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestH2H1TEGzip tests that server resets stream if TE request header
// field contains gzip.
func TestH2H1TEGzip(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not forward bad request")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1TEGzip",
		header: []hpack.HeaderField{
			pair("te", "gzip"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	if got, want := res.errCode, http2.ErrCodeProtocol; got != want {
		t.Errorf("res.errCode = %v; want %v", res.errCode, want)
	}
}

func TestH2H1SNI(t *testing.T) {
	st := newServerTesterTLSConfig([]string{"--subcert=" + testDir + "/alt-server.key:" + testDir + "/alt-server.crt"}, t, noopHandler, &tls.Config{
		ServerName: "alt-domain",
	})
	defer st.Close()

	tlsConn := st.conn.(*tls.Conn)
	connState := tlsConn.ConnectionState()
	cert := connState.PeerCertificates[0]

	if got, want := cert.Subject.CommonName, "alt-domain"; got != want {
		t.Errorf("CommonName: %v; want %v", got, want)
	}
}

// TestH2H1GracefulShutdown tests graceful shutdown.
func TestH2H1GracefulShutdown(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	fmt.Fprint(st.conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if err := st.fr.WriteSettings(); err != nil {
		t.Fatalf("st.fr.WriteSettings(): %v", err)
	}

	header := []hpack.HeaderField{
		pair(":method", "GET"),
		pair(":scheme", "http"),
		pair(":authority", st.authority),
		pair(":path", "/"),
	}

	for _, h := range header {
		_ = st.enc.WriteField(h)
	}

	if err := st.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		EndStream:     false,
		EndHeaders:    true,
		BlockFragment: st.headerBlkBuf.Bytes(),
	}); err != nil {
		t.Fatalf("st.fr.WriteHeaders(): %v", err)
	}

	// send SIGQUIT signal to nghttpx to perform graceful shutdown
	st.cmd.Process.Signal(syscall.SIGQUIT)

	// after signal, finish request body
	if err := st.fr.WriteData(1, true, nil); err != nil {
		t.Fatalf("st.fr.WriteData(): %v", err)
	}

	numGoAway := 0

	for {
		fr, err := st.readFrame()
		if err != nil {
			if err == io.EOF {
				want := 2
				if got := numGoAway; got != want {
					t.Fatalf("numGoAway: %v; want %v", got, want)
				}
				return
			}
			t.Fatalf("st.readFrame(): %v", err)
		}
		switch f := fr.(type) {
		case *http2.GoAwayFrame:
			numGoAway += 1
			want := http2.ErrCodeNo
			if got := f.ErrCode; got != want {
				t.Fatalf("f.ErrCode(%v): %v; want %v", numGoAway, got, want)
			}
			switch numGoAway {
			case 1:
				want := (uint32(1) << 31) - 1
				if got := f.LastStreamID; got != want {
					t.Fatalf("f.LastStreamID(%v): %v; want %v", numGoAway, got, want)
				}
			case 2:
				want := uint32(1)
				if got := f.LastStreamID; got != want {
					t.Fatalf("f.LastStreamID(%v): %v; want %v", numGoAway, got, want)
				}
			case 3:
				t.Fatalf("too many GOAWAYs received")
			}
		}
	}
}

// TestH2H2MultipleResponseCL tests that server returns error if
// multiple Content-Length response header fields are received.
func TestH2H2MultipleResponseCL(t *testing.T) {
	st := newServerTester([]string{"--http2-bridge"}, t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-length", "1")
		w.Header().Add("content-length", "1")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H2MultipleResponseCL",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	want := 502
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestH2H2InvalidResponseCL tests that server returns error if
// Content-Length response header field value cannot be parsed as a
// number.
func TestH2H2InvalidResponseCL(t *testing.T) {
	st := newServerTester([]string{"--http2-bridge"}, t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-length", "")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H2InvalidResponseCL",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	want := 502
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestH2H2ConnectFailure tests that server handles the situation that
// connection attempt to HTTP/2 backend failed.
func TestH2H2ConnectFailure(t *testing.T) {
	st := newServerTester([]string{"--http2-bridge"}, t, noopHandler)
	defer st.Close()

	// simulate backend connect attempt failure
	st.ts.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H2ConnectFailure",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	want := 503
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestH2H2HostRewrite tests that server rewrites host header field
func TestH2H2HostRewrite(t *testing.T) {
	st := newServerTester([]string{"--http2-bridge"}, t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("request-host", r.Host)
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H2HostRewrite",
	})
	if err != nil {
		t.Fatalf("Error st.http2() = %v", err)
	}
	if got, want := res.status, 200; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
	if got, want := res.header.Get("request-host"), st.backendHost; got != want {
		t.Errorf("request-host: %v; want %v", got, want)
	}
}
