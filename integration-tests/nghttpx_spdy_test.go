package nghttp2

import (
	"github.com/bradfitz/http2/hpack"
	"golang.org/x/net/spdy"
	"net/http"
	"testing"
)

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

func TestS3H2ConnectFailure(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--http2-bridge"}, t, noopHandler)
	defer st.Close()

	// simulate backend connect attempt failure
	st.ts.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H2ConnectFailure",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	want := 503
	if got := res.status; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}
