package store

import (
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func TestConsumerVerificationRequiresExactBoundDeniedEvidence(t *testing.T) {
	binding := credentialref.LifecycleBinding{
		OperationID: "operation-a", Action: credentialref.ActionActivate,
		ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"},
		RequiredDeniedConsumerIDs: []string{"consumer-denied"},
		MaterialVersion:           "version-a", ResolverID: "fixture-resolver", TargetID: "target-a",
		CiphertextFingerprint: "sha256:" + strings.Repeat("a", 64),
		StateRevision:         3, RecoveryEpoch: 1,
	}
	digest := "sha256:" + strings.Repeat("b", 64)
	positive, err := credentialref.NewConsumerVerification(binding, "consumer-a", "profile-a", "role-a", digest, "loaded", "verified", true)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := credentialref.NewConsumerVerification(binding, "consumer-denied", "profile-b", "role-b", digest, "reader-denied", "denied", false)
	if err != nil {
		t.Fatal(err)
	}
	valid := []credentialref.ConsumerVerification{positive, denied}
	if err := requireConsumerVerifications(binding, valid, []string{"consumer-a"}); err != nil {
		t.Fatalf("exact positive and denied evidence rejected: %v", err)
	}
	for name, mutate := range map[string]func(*credentialref.ConsumerVerification){
		"old denied material": func(v *credentialref.ConsumerVerification) { v.MaterialVersion = "version-old" },
		"foreign denied cipher": func(v *credentialref.ConsumerVerification) {
			v.CiphertextFingerprint = "sha256:" + strings.Repeat("c", 64)
		},
		"invalid denied profile": func(v *credentialref.ConsumerVerification) { v.ProfileID = "Bad ID" },
		"invalid denied role":    func(v *credentialref.ConsumerVerification) { v.RoleID = "Bad ID" },
		"invalid denied reason":  func(v *credentialref.ConsumerVerification) { v.ReasonCode = "Bad Reason" },
		"nonhex denied digest":   func(v *credentialref.ConsumerVerification) { v.EvidenceDigest = "sha256:" + strings.Repeat("z", 64) },
		"restart marked on deny": func(v *credentialref.ConsumerVerification) { v.RestartObserved = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := append([]credentialref.ConsumerVerification(nil), valid...)
			mutate(&changed[1])
			if err := requireConsumerVerifications(binding, changed, []string{"consumer-a"}); err == nil {
				t.Fatal("unbound or malformed denied evidence accepted")
			}
		})
	}
}
