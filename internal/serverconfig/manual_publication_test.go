package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestManualPublicationBindingsProtectedTargets(t *testing.T) {
	good := generated.ManualPublicationBinding{Schema: generated.SchemaIDManualPublicationBinding, SchemaVersion: "1.0.0", BindingID: "publication", RegistryOrigin: "https://registry.example.invalid", Repository: "team/app", ReferenceID: "publication-key", MaterialVersion: "v1", CandidatePath: "/protected/candidate.json", CandidateDigest: hostaction.Digest("candidate"), TrustPolicyPath: "/protected/policy.json", TrustPolicyDigest: hostaction.Digest("policy"), ImageDigest: hostaction.Digest("image")}
	out, e := FreezeManualPublicationBindings([]generated.ManualPublicationBinding{good})
	if e != nil || len(out) != 1 {
		t.Fatal(out, e)
	}
	out[0].Repository = "other"
	if good.Repository != "team/app" {
		t.Fatal("binding alias")
	}
	for _, edit := range []func(*generated.ManualPublicationBinding){func(b *generated.ManualPublicationBinding) { b.RegistryOrigin = "http://registry.invalid" }, func(b *generated.ManualPublicationBinding) { b.RegistryOrigin = "https://registry.invalid/path" }, func(b *generated.ManualPublicationBinding) { b.CandidatePath = "relative.json" }, func(b *generated.ManualPublicationBinding) { b.Repository = "team/../app" }} {
		b := good
		edit(&b)
		if _, e = FreezeManualPublicationBindings([]generated.ManualPublicationBinding{b}); e == nil {
			t.Fatal("unsafe protected binding accepted")
		}
	}
	if _, e = FreezeManualPublicationBindings([]generated.ManualPublicationBinding{good, good}); e == nil {
		t.Fatal("duplicate binding accepted")
	}
}
