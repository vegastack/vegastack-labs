//go:build !linux

package identity

import (
	"context"
	"strings"
	"testing"
)

func TestLoadCloudflareAccessProfileIsUnsupportedWithoutOpeningPath(t *testing.T) {
	path := "/private/cloudflare-profile-canary-does-not-exist"
	_, err := LoadCloudflareAccessProfile(context.Background(), path)
	if err == nil || !strings.Contains(err.Error(), "UNSUPPORTED_PLATFORM") || strings.Contains(err.Error(), path) {
		t.Fatalf("LoadCloudflareAccessProfile() error = %v", err)
	}
}
