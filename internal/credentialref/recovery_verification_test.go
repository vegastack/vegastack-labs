package credentialref

import (
	"strings"
	"testing"
)

func validRecoveryVerificationBinding() LifecycleBinding {
	binding := validActivateBinding()
	binding.Action = ActionRecover
	binding.RequiredDeniedConsumerIDs = nil
	binding.DraftID = stagePointer("draft-a")
	sealOrigin(&binding)
	binding.PriorRecoveryEpoch = epochPointer(2)
	binding.CustodyProofDigest = stagePointer(testCustody)
	binding.FormerControllerFenceDigest = stagePointer(testFence)
	return binding
}

func TestRecoveryVerificationBindsExactDraftAndEpochPair(t *testing.T) {
	binding := validRecoveryVerificationBinding()
	evidenceDigest := "sha256:" + strings.Repeat("d", 64)
	evidence, err := NewRecoveryVerification(binding, testCustody, testFence, evidenceDigest)
	if err != nil || !ValidRecoveryVerification(binding, evidence) {
		t.Fatalf("valid exact recovery evidence rejected: %v", err)
	}
	if evidence.DraftID != *binding.DraftID || evidence.PriorRecoveryEpoch != *binding.PriorRecoveryEpoch || evidence.RecoveryEpoch != binding.RecoveryEpoch {
		t.Fatal("recovery evidence lost exact draft or epoch pair")
	}
	for name, change := range map[string]func(*RecoveryVerification){
		"foreign draft":       func(v *RecoveryVerification) { v.DraftID = "draft-other" },
		"old epoch":           func(v *RecoveryVerification) { v.RecoveryEpoch-- },
		"foreign prior epoch": func(v *RecoveryVerification) { v.PriorRecoveryEpoch-- },
		"custody mismatch":    func(v *RecoveryVerification) { v.CustodyProofDigest = evidenceDigest },
		"fence mismatch":      func(v *RecoveryVerification) { v.FormerControllerFenceDigest = evidenceDigest },
		"nonhex evidence":     func(v *RecoveryVerification) { v.EvidenceDigest = "sha256:" + strings.Repeat("z", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := evidence
			change(&changed)
			if ValidRecoveryVerification(binding, changed) {
				t.Fatal("tampered recovery evidence accepted")
			}
		})
	}
	for name, values := range map[string][3]string{
		"wrong custody":      {evidenceDigest, testFence, evidenceDigest},
		"wrong fence":        {testCustody, evidenceDigest, evidenceDigest},
		"uppercase evidence": {testCustody, testFence, "sha256:" + strings.Repeat("A", 64)},
		"nonhex custody":     {"sha256:" + strings.Repeat("z", 64), testFence, evidenceDigest},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRecoveryVerification(binding, values[0], values[1], values[2]); err == nil {
				t.Fatal("invalid recovery evidence constructed")
			}
		})
	}
}
