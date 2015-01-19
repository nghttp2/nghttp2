package nghttp2

import (
	"fmt"
	"github.com/bradfitz/http2"
	"github.com/bradfitz/http2/hpack"
	"io/ioutil"
	"net/http"
	"testing"
)

func TestPlainGET(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestPlainGet",
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}

	want := 200
	if res.status != want {
		t.Errorf("status = %v; want %v", res.status, want)
	}
}

func TestAddXff(t *testing.T) {
	st := newServerTester([]string{"--add-x-forwarded-for"}, t, func(w http.ResponseWriter, r *http.Request) {
		xff := r.Header.Get("X-Forwarded-For")
		want := "127.0.0.1"
		if xff != want {
			t.Errorf("X-Forwarded-For = %v; want %v", xff, want)
		}
	})
	defer st.Close()

	_, err := st.http2(requestParam{
		name: "TestAddXff",
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}
}

func TestAddXff2(t *testing.T) {
	st := newServerTester([]string{"--add-x-forwarded-for"}, t, func(w http.ResponseWriter, r *http.Request) {
		xff := r.Header.Get("X-Forwarded-For")
		want := "host, 127.0.0.1"
		if xff != want {
			t.Errorf("X-Forwarded-For = %v; want %v", xff, want)
		}
	})
	defer st.Close()

	_, err := st.http2(requestParam{
		name: "TestAddXff2",
		header: []hpack.HeaderField{
			pair("x-forwarded-for", "host"),
		},
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}
}

func TestStripXff(t *testing.T) {
	st := newServerTester([]string{"--strip-incoming-x-forwarded-for"}, t, func(w http.ResponseWriter, r *http.Request) {
		if xff, found := r.Header["X-Forwarded-For"]; found {
			t.Errorf("X-Forwarded-For = %v; want nothing", xff)
		}
	})
	defer st.Close()

	_, err := st.http2(requestParam{
		name: "TestStripXff1",
		header: []hpack.HeaderField{
			pair("x-forwarded-for", "host"),
		},
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}
}

func TestStripAddXff(t *testing.T) {
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
		name: "TestStripAddXff",
		header: []hpack.HeaderField{
			pair("x-forwarded-for", "host"),
		},
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}
}

func TestHTTP2BadRequestCL(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	// we set content-length: 1024, but the actual request body is
	// 3 bytes.
	res, err := st.http2(requestParam{
		name:   "TestHTTP2BadRequestCL",
		method: "POST",
		header: []hpack.HeaderField{
			pair("content-length", "1024"),
		},
		body: []byte("foo"),
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}

	want := http2.ErrCodeProtocol
	if res.errCode != want {
		t.Errorf("res.errCode = %v; want %v", res.errCode, want)
	}
}

func TestHTTP2BadResponseCL(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		// we set content-length: 1024, but only send 3 bytes.
		w.Header().Add("Content-Length", "1024")
		w.Write([]byte("foo"))
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestHTTP2BadResponseCL",
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}

	want := http2.ErrCodeProtocol
	if res.errCode != want {
		t.Errorf("res.errCode = %v; want %v", res.errCode, want)
	}
}

func TestHTTP2LocationRewrite(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		// TODO we cannot get st.ts's port number here.. 8443
		// is just a place holder.  We ignore it on rewrite.
		w.Header().Add("Location", "http://127.0.0.1:8443/p/q?a=b#fragment")
	})
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestHTTP2LocationRewrite",
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}

	want := fmt.Sprintf("http://127.0.0.1:%v/p/q?a=b#fragment", serverPort)
	if got := res.header.Get("Location"); got != want {
		t.Errorf("Location: %v; want %v", got, want)
	}
}

func TestHTTP2ChunkedRequestBody(t *testing.T) {
	st := newServerTester(nil, t, func(w http.ResponseWriter, r *http.Request) {
		want := "[chunked]"
		if got := fmt.Sprint(r.TransferEncoding); got != want {
			t.Errorf("Transfer-Encoding: %v; want %v", got, want)
		}
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Error reading r.body: %v", err)
		}
		want = "foo"
		if got := string(body); got != want {
			t.Errorf("body: %v; want %v", got, want)
		}
	})
	defer st.Close()

	_, err := st.http2(requestParam{
		name:   "TestHTTP2ChunkedRequestBody",
		method: "POST",
		body:   []byte("foo"),
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}
}

func TestHTTP2DuplicateRequestCL(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestHTTP2DuplicateRequestCL",
		header: []hpack.HeaderField{
			pair("content-length", "1"),
			pair("content-length", "2"),
		},
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}
	want := 400
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

func TestHTTP2InvalidRequestCL(t *testing.T) {
	st := newServerTester(nil, t, noopHandler)
	defer st.Close()

	res, err := st.http2(requestParam{
		name: "TestHTTP2InvalidRequestCL",
		header: []hpack.HeaderField{
			pair("content-length", ""),
		},
	})
	if err != nil {
		t.Errorf("Error st.http2() = %v", err)
	}
	want := 400
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}
