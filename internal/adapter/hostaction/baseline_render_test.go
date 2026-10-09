package hostaction

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestBaselineRendererRefusesUnboundInput(t *testing.T) {
	for _, in := range []generated.DebianBaselineInput{{}, {ProfileID: "{{ lookup('pipe', 'id') }}"}, {RenderedPolicyDigest: BaselineRendererDigest()}} {
		if _, err := RenderBaselineRole(context.Background(), in); err == nil {
			t.Fatal("unbound renderer input accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RenderBaselineRole(ctx, generated.DebianBaselineInput{}); err == nil {
		t.Fatal("canceled render accepted")
	}
}
