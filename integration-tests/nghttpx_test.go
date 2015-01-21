package nghttp2

import (
	"bufio"
	"fmt"
	"github.com/bradfitz/http2"
	"github.com/bradfitz/http2/hpack"
	"golang.org/x/net/spdy"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestH1H1PlainGET(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	res, err := st.http1(requestParam{
		name: "TestH1H1PlainGET",
	})
	if err != nil {
		t.Fatalf("Error st.http1() = %v", err)
	}

	want := 200
	if got := res.status; got != want {
		t.Errorf("status = %v; want %v", got, want)
	}
}

func TestH1H1PlainGETClose(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	res, err := st.http1(requestParam{
		name: "TestH1H1PlainGETClose",
		header: []hpack.HeaderField{
			pair("Connection", "close"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.http1() = %v", err)
	}

	want := 200
	if got := res.status; got != want {
		t.Errorf("status = %v; want %v", got, want)
	}
}

func TestH1H1MultipleRequestCL(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward bad request")
	})
	defer st.Close()

	if _, err := io.WriteString(st.conn, fmt.Sprintf(`GET / HTTP/1.1
Host: %v
Test-Case: TestH1H1MultipleRequestCL
Content-Length: 0
Content-Length: 1

`, st.authority)); err != nil {
		t.Fatalf("Error io.WriteString() = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(st.conn), nil)
	if err != nil {
		t.Fatalf("Error http.ReadResponse() = %v", err)
	}

	want := 400
	if got := resp.StatusCode; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

func TestH1H1ConnectFailure(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	// shutdown backend server to simulate backend connect failure
	st.ts.Close()

	res, err := st.http1(requestParam{
		name: "TestH1H1ConnectFailure",
	})
	if err != nil {
		t.Fatalf("Error st.http1() = %v", err)
	}
	want := 502
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

func TestH1H2NoHost(t *testing.T) {
	st := newServerTester([]string{"--http2-bridge"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward bad request")
	})
	defer st.Close()

	// without Host header field, we expect 400 response
	if _, err := io.WriteString(st.conn, "GET / HTTP/1.1\r\nTest-Case: TestH1H2NoHost\r\n\r\n"); err != nil {
		t.Fatalf("Error io.WriteString() = %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(st.conn), nil)
	if err != nil {
		t.Fatalf("Error http.ReadResponse() = %v", err)
	}

	want := 400
	if got := resp.StatusCode; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

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

func TestH2H1MultipleRequestCL(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward bad request")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestH2H1MultipleRequestCL",
		header: []hpack.HeaderField{
			pair("content-length", "1"),
			pair("content-length", "2"),
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
	want := 502
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

func TestH2H2MultipleResponseCL(t *testing.T) {
	st := newServerTester([]string{"--http2-bridge"}, t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-length", "1")
		w.Header().Add("content-length", "2")
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

func TestS3H1PlainGET(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, noopHandler)
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1PlainGET",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}

	want := 200
	if got := res.status; got != want {
		t.Errorf("status = %v; want %v", got, want)
	}
}

func TestS3H1BadRequestCL(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, noopHandler)
	defer st.Close()

	// we set content-length: 1024, but the actual request body is
	// 3 bytes.
	res, err := st.spdy(requestParam{
		name:   "TestS3H1BadRequestCL",
		method: "POST",
		header: []hpack.HeaderField{
			pair("content-length", "1024"),
		},
		body: []byte("foo"),
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}

	want := spdy.ProtocolError
	if got := res.spdyRstErrCode; got != want {
		t.Errorf("res.spdyRstErrCode = %v; want %v", got, want)
	}
}

func TestS3H1MultipleRequestCL(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward bad request")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1MultipleRequestCL",
		header: []hpack.HeaderField{
			pair("content-length", "1"),
			pair("content-length", "2"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	want := 400
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

func TestS3H1InvalidRequestCL(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward bad request")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1InvalidRequestCL",
		header: []hpack.HeaderField{
			pair("content-length", ""),
		},
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	want := 400
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}
