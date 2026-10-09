//go:build linux || darwin

package debianaccess

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"testing"
)

func TestReadOnlyAccessCollectionIsObservedAdapterEffect(t *testing.T) {
	f := nativeFixtureNew(t)
	apply, _ := NewHandler("debian.access.apply", f.n)
	if _, e := apply.Execute(context.Background(), f.bundle); e != nil {
		t.Fatal(e)
	}
	f.bundle.ActionID = "debian.access.collect"
	h, _ := NewHandler(f.bundle.ActionID, f.n)
	r, e := h.Execute(context.Background(), f.bundle)
	if e != nil {
		t.Fatal(e)
	}
	if r.Changed || !r.EffectObserved {
		t.Fatal("read-only result confused with mutation", r)
	}
	if e = adapter.ValidateEffect(adapter.Effect{Status: r.Status, Changed: r.Changed, EffectObserved: r.EffectObserved, ResultDigest: r.ResultDigest}); e != nil {
		t.Fatal(e)
	}
}
