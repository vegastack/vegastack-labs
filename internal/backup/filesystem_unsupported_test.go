//go:build !linux

package backup

import "testing"

func TestArtifactLayoutIsUnavailableOutsideLinux(t *testing.T) {
	if _, err := newArtifactLayout(Config{Root: "/ignored"}); err == nil || err.Error() != failureUnsupported {
		t.Fatalf("newArtifactLayout() error = %v", err)
	}
}
