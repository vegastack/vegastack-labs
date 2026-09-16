package credentialref

import "testing"

func testBinding() StepBinding {
	return StepBinding{OperationID: "operation-a", AdapterID: "adapter-a", TargetID: "service-a", ReferenceID: "ref-a", ConsumerID: "adapter-a", PurposeID: "deploy-a", MaterialVersion: "version-a", ResolverID: "native-a", StateRevision: 3, RecoveryEpoch: 1}
}

func TestStepBindingDigestChangesForEveryAuthorityField(t *testing.T) {
	base := testBinding()
	if !ValidBinding(base) || base.Digest() == "" {
		t.Fatal("exact binding rejected")
	}
	for name, mutate := range map[string]func(*StepBinding){
		"operation": func(b *StepBinding) { b.OperationID = "operation-b" },
		"adapter":   func(b *StepBinding) { b.AdapterID = "adapter-b" },
		"target":    func(b *StepBinding) { b.TargetID = "service-b" },
		"reference": func(b *StepBinding) { b.ReferenceID = "ref-b" },
		"consumer":  func(b *StepBinding) { b.ConsumerID = "adapter-b" },
		"purpose":   func(b *StepBinding) { b.PurposeID = "deploy-b" },
		"material":  func(b *StepBinding) { b.MaterialVersion = "version-b" },
		"resolver":  func(b *StepBinding) { b.ResolverID = "native-b" },
		"revision":  func(b *StepBinding) { b.StateRevision++ },
		"epoch":     func(b *StepBinding) { b.RecoveryEpoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if changed.Digest() == base.Digest() {
				t.Fatal("authority field missing from binding digest")
			}
		})
	}
	if ManifestDigest([]StepBinding{base}) == ManifestDigest(nil) {
		t.Fatal("empty manifest shares authority digest")
	}
}

func TestOperationManifestDigestExcludesOtherOperations(t *testing.T) {
	first := testBinding()
	second := first
	second.OperationID = "operation-b"
	if got := OperationManifestDigest([]StepBinding{first, second}, first.OperationID); got != ManifestDigest([]StepBinding{first}) {
		t.Fatalf("operation digest widened: %s", got)
	}
	if got := OperationManifestDigest([]StepBinding{first}, "operation-b"); got != "" {
		t.Fatalf("missing operation digest: %s", got)
	}
}
