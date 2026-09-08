//go:build !linux

package serverconfig

import (
	"context"
	"strings"
	"testing"
)

func TestUnsupportedLoaderDoesNotOpenPath(t *testing.T) {
	path := "/private/profile-canary-does-not-exist"
	_, err := NewLoader(0).Load(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_PLATFORM") || strings.Contains(err.Error(), path) {
		t.Fatalf("Load() error = %v", err)
	}
}
