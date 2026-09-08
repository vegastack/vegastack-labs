package store

import (
	"context"
	"runtime"
	"testing"
)

func TestOpenIsUnavailableOutsideLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux lifecycle tests exercise functional opens")
	}
	_, err := Open(context.Background(), Config{DatabasePath: "ignored", Mode: OpenExisting})
	if Code(err) != "UNSUPPORTED_PLATFORM" {
		t.Fatalf("Open() code = %q", Code(err))
	}
}
