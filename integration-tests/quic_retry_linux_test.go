//go:build quic && linux

package nghttp2

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestH3RetryPreservesTerminalState(t *testing.T) {
	env, record := faultLibrary(t, "quic_retry",
		"ngtcp2_conn_read_pkt_versioned", "ngtcp2_ccerr_set_liberr",
		"ngtcp2_conn_write_connection_close_versioned", "ngtcp2_conn_del")
	st := newServerTester(t, options{quic: true, env: env})
	defer st.Close()
	res, err := st.http3(requestParam{name: t.Name()})
	if err != nil || res.status != http.StatusOK {
		t.Fatalf("request after Retry: response=%v error=%v", res, err)
	}
	data, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	trace := string(data)
	if !strings.Contains(trace, "retry-injected") ||
		!strings.Contains(trace, "retry-connection-deleted") ||
		!strings.Contains(trace, "retry-type-preserved") ||
		strings.Contains(trace, "retry-type-lost") ||
		strings.Contains(trace, "retry-connection-closed") {
		t.Fatalf("Retry teardown: %s", trace)
	}
}
