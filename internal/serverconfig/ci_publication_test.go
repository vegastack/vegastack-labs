package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestCIPublicationBindingsProtectedTargets(t *testing.T) {
	good := generated.CiPublicationBinding{Schema: generated.SchemaIDCiPublicationBinding, SchemaVersion: "1.0.0", BindingID: "publication", EnrollmentID: "source", SourceRunID: "run-a", SourceStepID: "step-a", RegistryOrigin: "https://registry.example.invalid", Repository: "team/app", ReferenceID: "publication-key", MaterialVersion: "v1", CandidatePath: "/protected/candidate.json", CandidateDigest: hostaction.Digest("candidate")}
	out, e := FreezeCIPublicationBindings([]generated.CiPublicationBinding{good})
	if e != nil || len(out) != 1 {
		t.Fatal(out, e)
	}
	out[0].Repository = "other"
	if good.Repository != "team/app" {
		t.Fatal("binding alias")
	}
	for _, edit := range []func(*generated.CiPublicationBinding){func(b *generated.CiPublicationBinding) { b.RegistryOrigin = "http://registry.invalid" }, func(b *generated.CiPublicationBinding) { b.RegistryOrigin = "https://registry.invalid/path" }, func(b *generated.CiPublicationBinding) { b.CandidatePath = "relative.json" }, func(b *generated.CiPublicationBinding) { b.Repository = "team/../app" }} {
		b := good
		edit(&b)
		if _, e = FreezeCIPublicationBindings([]generated.CiPublicationBinding{b}); e == nil {
			t.Fatal("unsafe protected binding accepted")
		}
	}
	if _, e = FreezeCIPublicationBindings([]generated.CiPublicationBinding{good, good}); e == nil {
		t.Fatal("duplicate binding accepted")
	}
}
