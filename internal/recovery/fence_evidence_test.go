package recovery

import (
	"context"
	"testing"
)

func TestInstalledFenceEvidenceUsesExactFinalSourceBinding(t *testing.T) {
	installed, _, qualified, binding, now, _ := installedSourceFixture(t)
	requirement := hostFenceRequirement(binding)
	reader, err := VerifyInstalledFenceEvidence(context.Background(), binding, []FenceRequirement{requirement}, installed, qualified, now)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := reader.Current(context.Background(), requirement)
	if err != nil || len(proofs) != 2 {
		t.Fatalf("proofs=%#v err=%v", proofs, err)
	}
	if proofs[0].SourceDigest == "" || proofs[0].ManifestDigest != installed.Pin.ManifestDigest || proofs[0].TrustRootDigest != installed.Pin.adminRootDigest {
		t.Fatalf("source attribution = %#v", proofs[0])
	}

	changed := binding
	changed.PlanDigest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if _, err := VerifyInstalledFenceEvidence(context.Background(), changed, []FenceRequirement{requirement}, installed, qualified, now); err == nil {
		t.Fatal("changed post-plan binding accepted")
	}
	partial := requirement
	partial.RequiredEvidenceKinds = partial.RequiredEvidenceKinds[:1]
	if _, err := VerifyInstalledFenceEvidence(context.Background(), binding, []FenceRequirement{partial}, installed, qualified, now); err == nil {
		t.Fatal("partial direct-denial group accepted")
	}
}
