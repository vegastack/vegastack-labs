//go:build !linux

package cli

import "testing"

func testNodeCommandThroughTransport(t *testing.T, _ string) {
	t.Helper()
	t.Skip("actual local server-profile transport coverage runs in the required Linux node CLI tests")
}
