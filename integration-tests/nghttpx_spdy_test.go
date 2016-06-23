package nghttp2

import (
	"encoding/json"
	"github.com/tatsuhiro-t/spdy"
	"golang.org/x/net/http2/hpack"
	"net/http"
	"testing"
)

// TestS3H1PlainGET tests whether simple SPDY GET request works.
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

// TestS3H1BadRequestCL tests that server rejects request whose
// content-length header field value does not match its request body
// size.
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

// TestS3H1MultipleRequestCL tests that server rejects request with
// multiple Content-Length request header fields.
func TestS3H1MultipleRequestCL(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward bad request")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1MultipleRequestCL",
		header: []hpack.HeaderField{
			pair("content-length", "1"),
			pair("content-length", "1"),
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

// TestS3H1InvalidRequestCL tests that server rejects request with
// Content-Length which cannot be parsed as a number.
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

// TestS3H1GenerateVia tests that server generates Via header field to and
// from backend server.
func TestS3H1GenerateVia(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Via"), "1.1 nghttpx"; got != want {
			t.Errorf("Via: %v; want %v", got, want)
		}
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1GenerateVia",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.header.Get("Via"), "1.1 nghttpx"; got != want {
		t.Errorf("Via: %v; want %v", got, want)
	}
}

// TestS3H1AppendVia tests that server adds value to existing Via
// header field to and from backend server.
func TestS3H1AppendVia(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Via"), "foo, 1.1 nghttpx"; got != want {
			t.Errorf("Via: %v; want %v", got, want)
		}
		w.Header().Add("Via", "bar")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1AppendVia",
		header: []hpack.HeaderField{
			pair("via", "foo"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.header.Get("Via"), "bar, 1.1 nghttpx"; got != want {
		t.Errorf("Via: %v; want %v", got, want)
	}
}

// TestS3H1NoVia tests that server does not add value to existing Via
// header field to and from backend server.
func TestS3H1NoVia(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--no-via"}, t, func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("Via"), "foo"; got != want {
			t.Errorf("Via: %v; want %v", got, want)
		}
		w.Header().Add("Via", "bar")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1NoVia",
		header: []hpack.HeaderField{
			pair("via", "foo"),
		},
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.header.Get("Via"), "bar"; got != want {
		t.Errorf("Via: %v; want %v", got, want)
	}
}

// TestS3H1HeaderFieldBuffer tests that request with header fields
// larger than configured buffer size is rejected.
func TestS3H1HeaderFieldBuffer(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--header-field-buffer=10"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("execution path should not be here")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1HeaderFieldBuffer",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.spdyRstErrCode, spdy.InternalError; got != want {
		t.Errorf("res.spdyRstErrCode: %v; want %v", got, want)
	}
}

// TestS3H1HeaderFields tests that request with header fields more
// than configured number is rejected.
func TestS3H1HeaderFields(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--max-header-fields=1"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("execution path should not be here")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1HeaderFields",
		// we have at least 5 pseudo-header fields sent, and
		// that ensures that buffer limit exceeds.
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.spdyRstErrCode, spdy.InternalError; got != want {
		t.Errorf("res.spdyRstErrCode: %v; want %v", got, want)
	}
}

// TestS3H1InvalidMethod tests that server rejects invalid method with
// 501.
func TestS3H1InvalidMethod(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward this request")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name:   "TestS3H1InvalidMethod",
		method: "get",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.status, 501; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestS3H1BadHost tests that server rejects request including bad
// character in :host header field.
func TestS3H1BadHost(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward this request")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name:      "TestS3H1BadHost",
		authority: `foo\bar`,
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.status, 400; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestS3H1BadScheme tests that server rejects request including bad
// character in :scheme header field.
func TestS3H1BadScheme(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server should not forward this request")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name:   "TestS3H1BadScheme",
		scheme: `http*`,
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.status, 400; got != want {
		t.Errorf("status: %v; want %v", got, want)
	}
}

// TestS3H1ReqPhaseSetHeader tests mruby request phase hook
// modifies request header fields.
func TestS3H1ReqPhaseSetHeader(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--mruby-file=" + testDir + "/req-set-header.rb"}, t, func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("User-Agent"), "mruby"; got != want {
			t.Errorf("User-Agent = %v; want %v", got, want)
		}
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1ReqPhaseSetHeader",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}

	if got, want := res.status, 200; got != want {
		t.Errorf("status = %v; want %v", got, want)
	}
}

// TestS3H1ReqPhaseReturn tests mruby request phase hook returns
// custom response.
func TestS3H1ReqPhaseReturn(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--mruby-file=" + testDir + "/req-return.rb"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("request should not be forwarded")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1ReqPhaseReturn",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}

	if got, want := res.status, 404; got != want {
		t.Errorf("status = %v; want %v", got, want)
	}

	hdtests := []struct {
		k, v string
	}{
		{"content-length", "20"},
		{"from", "mruby"},
	}
	for _, tt := range hdtests {
		if got, want := res.header.Get(tt.k), tt.v; got != want {
			t.Errorf("%v = %v; want %v", tt.k, got, want)
		}
	}

	if got, want := string(res.body), "Hello World from req"; got != want {
		t.Errorf("body = %v; want %v", got, want)
	}
}

// TestS3H1RespPhaseSetHeader tests mruby response phase hook modifies
// response header fields.
func TestS3H1RespPhaseSetHeader(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--mruby-file=" + testDir + "/resp-set-header.rb"}, t, noopHandler)
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1RespPhaseSetHeader",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}

	if got, want := res.status, 200; got != want {
		t.Errorf("status = %v; want %v", got, want)
	}

	if got, want := res.header.Get("alpha"), "bravo"; got != want {
		t.Errorf("alpha = %v; want %v", got, want)
	}
}

// TestS3H1RespPhaseReturn tests mruby response phase hook returns
// custom response.
func TestS3H1RespPhaseReturn(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--mruby-file=" + testDir + "/resp-return.rb"}, t, noopHandler)
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H1RespPhaseReturn",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}

	if got, want := res.status, 404; got != want {
		t.Errorf("status = %v; want %v", got, want)
	}

	hdtests := []struct {
		k, v string
	}{
		{"content-length", "21"},
		{"from", "mruby"},
	}
	for _, tt := range hdtests {
		if got, want := res.header.Get(tt.k), tt.v; got != want {
			t.Errorf("%v = %v; want %v", tt.k, got, want)
		}
	}

	if got, want := string(res.body), "Hello World from resp"; got != want {
		t.Errorf("body = %v; want %v", got, want)
	}
}

// // TestS3H2ConnectFailure tests that server handles the situation that
// // connection attempt to HTTP/2 backend failed.
// func TestS3H2ConnectFailure(t *testing.T) {
// 	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--http2-bridge"}, t, noopHandler)
// 	defer st.Close()

// 	// simulate backend connect attempt failure
// 	st.ts.Close()

// 	res, err := st.spdy(requestParam{
// 		name: "TestS3H2ConnectFailure",
// 	})
// 	if err != nil {
// 		t.Fatalf("Error st.spdy() = %v", err)
// 	}
// 	want := 503
// 	if got := res.status; got != want {
// 		t.Errorf("status: %v; want %v", got, want)
// 	}
// }

// TestS3H2ReqPhaseReturn tests mruby request phase hook returns
// custom response.
func TestS3H2ReqPhaseReturn(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--http2-bridge", "--mruby-file=" + testDir + "/req-return.rb"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("request should not be forwarded")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H2ReqPhaseReturn",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}

	if got, want := res.status, 404; got != want {
		t.Errorf("status = %v; want %v", got, want)
	}

	hdtests := []struct {
		k, v string
	}{
		{"content-length", "20"},
		{"from", "mruby"},
	}
	for _, tt := range hdtests {
		if got, want := res.header.Get(tt.k), tt.v; got != want {
			t.Errorf("%v = %v; want %v", tt.k, got, want)
		}
	}

	if got, want := string(res.body), "Hello World from req"; got != want {
		t.Errorf("body = %v; want %v", got, want)
	}
}

// TestS3H2RespPhaseReturn tests mruby response phase hook returns
// custom response.
func TestS3H2RespPhaseReturn(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--http2-bridge", "--mruby-file=" + testDir + "/resp-return.rb"}, t, noopHandler)
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3H2RespPhaseReturn",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}

	if got, want := res.status, 404; got != want {
		t.Errorf("status = %v; want %v", got, want)
	}

	hdtests := []struct {
		k, v string
	}{
		{"content-length", "21"},
		{"from", "mruby"},
	}
	for _, tt := range hdtests {
		if got, want := res.header.Get(tt.k), tt.v; got != want {
			t.Errorf("%v = %v; want %v", tt.k, got, want)
		}
	}

	if got, want := string(res.body), "Hello World from resp"; got != want {
		t.Errorf("body = %v; want %v", got, want)
	}
}

// TestS3APIBackendconfig exercise backendconfig API endpoint routine
// for successful case.
func TestS3APIBackendconfig(t *testing.T) {
	st := newServerTesterTLSConnectPort([]string{"--npn-list=spdy/3.1", "-f127.0.0.1,3010;api"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("request should not be forwarded")
	}, 3010)
	defer st.Close()

	res, err := st.spdy(requestParam{
		name:   "TestS3APIBackendconfig",
		path:   "/api/v1beta1/backendconfig",
		method: "PUT",
		body: []byte(`# comment
backend=127.0.0.1,3011

`),
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.status, 200; got != want {
		t.Errorf("res.status: %v; want %v", got, want)
	}

	var apiResp APIResponse
	err = json.Unmarshal(res.body, &apiResp)
	if err != nil {
		t.Fatalf("Error unmarshaling API response: %v", err)
	}
	if got, want := apiResp.Status, "Success"; got != want {
		t.Errorf("apiResp.Status: %v; want %v", got, want)
	}
	if got, want := apiResp.Code, 200; got != want {
		t.Errorf("apiResp.Status: %v; want %v", got, want)
	}
}

// TestS3APIBackendconfigQuery exercise backendconfig API endpoint
// routine with query.
func TestS3APIBackendconfigQuery(t *testing.T) {
	st := newServerTesterTLSConnectPort([]string{"--npn-list=spdy/3.1", "-f127.0.0.1,3010;api"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("request should not be forwarded")
	}, 3010)
	defer st.Close()

	res, err := st.spdy(requestParam{
		name:   "TestS3APIBackendconfigQuery",
		path:   "/api/v1beta1/backendconfig?foo=bar",
		method: "PUT",
		body: []byte(`# comment
backend=127.0.0.1,3011

`),
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.status, 200; got != want {
		t.Errorf("res.status: %v; want %v", got, want)
	}

	var apiResp APIResponse
	err = json.Unmarshal(res.body, &apiResp)
	if err != nil {
		t.Fatalf("Error unmarshaling API response: %v", err)
	}
	if got, want := apiResp.Status, "Success"; got != want {
		t.Errorf("apiResp.Status: %v; want %v", got, want)
	}
	if got, want := apiResp.Code, 200; got != want {
		t.Errorf("apiResp.Status: %v; want %v", got, want)
	}
}

// TestS3APIBackendconfigBadMethod exercise backendconfig API endpoint
// routine with bad method.
func TestS3APIBackendconfigBadMethod(t *testing.T) {
	st := newServerTesterTLSConnectPort([]string{"--npn-list=spdy/3.1", "-f127.0.0.1,3010;api"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("request should not be forwarded")
	}, 3010)
	defer st.Close()

	res, err := st.spdy(requestParam{
		name:   "TestS3APIBackendconfigBadMethod",
		path:   "/api/v1beta1/backendconfig",
		method: "GET",
		body: []byte(`# comment
backend=127.0.0.1,3011

`),
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.status, 405; got != want {
		t.Errorf("res.status: %v; want %v", got, want)
	}

	var apiResp APIResponse
	err = json.Unmarshal(res.body, &apiResp)
	if err != nil {
		t.Fatalf("Error unmarshaling API response: %v", err)
	}
	if got, want := apiResp.Status, "Failure"; got != want {
		t.Errorf("apiResp.Status: %v; want %v", got, want)
	}
	if got, want := apiResp.Code, 405; got != want {
		t.Errorf("apiResp.Status: %v; want %v", got, want)
	}
}

// TestS3APINotFound exercise backendconfig API endpoint routine when
// API endpoint is not found.
func TestS3APINotFound(t *testing.T) {
	st := newServerTesterTLSConnectPort([]string{"--npn-list=spdy/3.1", "-f127.0.0.1,3010;api"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("request should not be forwarded")
	}, 3010)
	defer st.Close()

	res, err := st.spdy(requestParam{
		name:   "TestS3APINotFound",
		path:   "/api/notfound",
		method: "GET",
		body: []byte(`# comment
backend=127.0.0.1,3011

`),
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.status, 404; got != want {
		t.Errorf("res.status: %v; want %v", got, want)
	}

	var apiResp APIResponse
	err = json.Unmarshal(res.body, &apiResp)
	if err != nil {
		t.Fatalf("Error unmarshaling API response: %v", err)
	}
	if got, want := apiResp.Status, "Failure"; got != want {
		t.Errorf("apiResp.Status: %v; want %v", got, want)
	}
	if got, want := apiResp.Code, 404; got != want {
		t.Errorf("apiResp.Status: %v; want %v", got, want)
	}
}

// TestS3Healthmon tests health monitor endpoint.
func TestS3Healthmon(t *testing.T) {
	st := newServerTesterTLSConnectPort([]string{"--npn-list=spdy/3.1", "-f127.0.0.1,3011;healthmon"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("request should not be forwarded")
	}, 3011)
	defer st.Close()

	res, err := st.spdy(requestParam{
		name: "TestS3Healthmon",
		path: "/alpha/bravo",
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.status, 200; got != want {
		t.Errorf("res.status: %v; want %v", got, want)
	}
}

// TestS3ResponseBeforeRequestEnd tests the situation where response
// ends before request body finishes.
func TestS3ResponseBeforeRequestEnd(t *testing.T) {
	st := newServerTesterTLS([]string{"--npn-list=spdy/3.1", "--mruby-file=" + testDir + "/req-return.rb"}, t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not be forwarded")
	})
	defer st.Close()

	res, err := st.spdy(requestParam{
		name:        "TestS3ResponseBeforeRequestEnd",
		noEndStream: true,
	})
	if err != nil {
		t.Fatalf("Error st.spdy() = %v", err)
	}
	if got, want := res.status, 404; got != want {
		t.Errorf("res.status: %v; want %v", got, want)
	}
}
