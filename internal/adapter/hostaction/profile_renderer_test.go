package hostaction

import "testing"

func TestAccessAndBaselineUseOneProfileRendererLock(t *testing.T) {
	if AccessRendererDigest() != BaselineRendererDigest() || LinuxRoleRendererDigest() != AccessRendererDigest() {
		t.Fatal("one protected profile cannot satisfy both staged renderers")
	}
}
