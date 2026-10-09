package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
)

func TestReplacementCoreRejectsUnconfiguredOrUnknownEffect(t *testing.T) {
	e := &HostReplacementEffect{}
	if _, err := e.Execute(context.Background(), ExactStepBinding{}); err == nil {
		t.Fatal("unconfigured effect accepted")
	}
	if _, err := e.Verify(context.Background(), ExactStepBinding{}, adapter.Effect{Status: "succeeded", ResultDigest: "invented"}); err == nil {
		t.Fatal("unconfigured result accepted")
	}
	for _, op := range []string{"host.alias.claim", "host.replacement.freeze", "host.replacement.commit"} {
		if !isCoreOperation("core.host-replacement", op) || isCoreOperation("wrong-adapter", op) {
			t.Fatal("incorrect core dispatch")
		}
		b := ExactStepBinding{Plan: generated.Plan{}}
		if replacementEffectShape(b) {
			t.Fatal("missing typed replacement accepted")
		}
	}
	if isCoreOperation("core.host-replacement", "host.replacement.erase") {
		t.Fatal("unknown destructive operation dispatched")
	}
}
