//go:build linux

package nativecredential

import (
	"context"
	"testing"
)

func TestNativeAuthorityScope(t *testing.T) {
	authority, err := NewNativeAuthority([]string{"example.service"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Restart(context.Background(), "other.service"); err == nil {
		t.Fatal("unenrolled unit restarted")
	}
	if _, err := NewNativeAuthority([]string{"*.service"}); err == nil {
		t.Fatal("wildcard enrollment accepted")
	}
	if _, err := NewNativeAuthority([]string{"example.service", "example.service"}); err == nil {
		t.Fatal("duplicate enrollment accepted")
	}
}
