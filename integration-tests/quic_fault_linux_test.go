//go:build quic && linux

package nghttp2

import (
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// faultLibrary injects faults only into the child server. Static ngtcp2
// symbols cannot be intercepted, so that configuration is explicitly skipped.
func faultLibrary(t *testing.T, name string, required ...string) ([]string, string) {
	t.Helper()
	binary, err := elf.Open(serverBin)
	var formatError *elf.FormatError
	if errors.As(err, &formatError) {
		// Autotools uses a libtool wrapper; inspect the ELF it launches.
		binary, err = elf.Open(filepath.Join(filepath.Dir(serverBin), ".libs",
			filepath.Base(serverBin)))
	}
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	symbols, err := binary.ImportedSymbols()
	if errors.Is(err, elf.ErrNoSymbols) {
		t.Skip("fault injection requires dynamic symbols")
	}
	if err != nil {
		t.Fatal(err)
	}
	imported := make(map[string]bool)
	for _, symbol := range symbols {
		imported[symbol.Name] = true
	}
	for _, symbol := range required {
		if !imported[symbol] {
			t.Skipf("fault injection requires dynamic symbol %s", symbol)
		}
	}
	dir := t.TempDir()
	library := filepath.Join(dir, "fault.so")
	record := filepath.Join(dir, "record")
	flags, err := exec.Command("pkg-config", "--cflags", "libngtcp2").Output()
	if err != nil {
		t.Fatal(err)
	}
	cc := strings.Fields(os.Getenv("CC"))
	if len(cc) == 0 {
		cc = []string{"cc"}
	}
	args := append(cc[1:], "-shared", "-fPIC", "-o", library,
		filepath.Join(testDir, "testdata", name+".c"), "-ldl")
	args = append(args, strings.Fields(string(flags))...)
	if output, err := exec.Command(cc[0], args...).CombinedOutput(); err != nil {
		t.Fatalf("build fault library: %v\n%s", err, output)
	}
	preload := library
	if current := os.Getenv("LD_PRELOAD"); current != "" {
		preload += ":" + current
	}
	return []string{"LD_PRELOAD=" + preload, "NGHTTP2_TEST_RECORD=" + record}, record
}
