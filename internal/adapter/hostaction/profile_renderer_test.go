package hostaction

import "testing"

func TestAccessAndBaselineUseOneProfileRendererLock(t *testing.T) {
	if AccessRendererDigest() != BaselineRendererDigest() {
		t.Fatal("one protected profile cannot satisfy both staged renderers")
	}
}
