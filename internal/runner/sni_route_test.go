package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCaptureInterfaceMatchesLocalRoute(t *testing.T) {
	t.Parallel()

	if err := checkCaptureRoute(context.Background(), "lo", "127.0.0.1", 443); err != nil {
		t.Fatalf("loopback route: %v", err)
	}
	if err := checkCaptureRoute(context.Background(), "no-such-interface", "127.0.0.1", 443); err == nil {
		t.Fatal("missing interface must fail")
	}
}

func TestCaptureLinkTypeIsEthernetOrLoopback(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "type")
	for _, tt := range []struct {
		value string
		ok    bool
	}{{"1\n", true}, {"772\n", true}, {"65534\n", false}, {"bad\n", false}} {
		if err := os.WriteFile(path, []byte(tt.value), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := checkCaptureLinkType(path); (err == nil) != tt.ok {
			t.Fatalf("link type %q: error = %v, want success %v", tt.value, err, tt.ok)
		}
	}
}
