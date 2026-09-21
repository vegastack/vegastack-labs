package credentialref

// NewRecoveryVerification constructs metadata-only recovery evidence for one
// exact, already-sealed draft and external recovery epoch transition. It does
// not establish custody, fencing, or host-key proof; those are caller duties.
func NewRecoveryVerification(binding LifecycleBinding, custodyProofDigest, fenceDigest, evidenceDigest string) (RecoveryVerification, error) {
	verification := RecoveryVerification{
		CustodyProofDigest:          custodyProofDigest,
		FormerControllerFenceDigest: fenceDigest,
		RecoveryEpoch:               binding.RecoveryEpoch,
		EvidenceDigest:              evidenceDigest,
	}
	if binding.DraftID != nil {
		verification.DraftID = *binding.DraftID
	}
	if binding.PriorRecoveryEpoch != nil {
		verification.PriorRecoveryEpoch = *binding.PriorRecoveryEpoch
	}
	if !ValidRecoveryVerification(binding, verification) {
		return RecoveryVerification{}, newError("INPUT_INVALID", "credential-recovery-verification")
	}
	return verification, nil
}

// ValidRecoveryVerification rejects a caller-built evidence record unless it
// matches every recovery field sealed into the lifecycle plan.
func ValidRecoveryVerification(binding LifecycleBinding, verification RecoveryVerification) bool {
	return binding.Action == ActionRecover && ValidLifecycleBinding(binding) &&
		binding.DraftID != nil && binding.PriorRecoveryEpoch != nil &&
		binding.CustodyProofDigest != nil && binding.FormerControllerFenceDigest != nil &&
		verification.DraftID == *binding.DraftID &&
		verification.PriorRecoveryEpoch == *binding.PriorRecoveryEpoch &&
		verification.RecoveryEpoch == binding.RecoveryEpoch &&
		verification.RecoveryEpoch > verification.PriorRecoveryEpoch &&
		verification.CustodyProofDigest == *binding.CustodyProofDigest &&
		verification.FormerControllerFenceDigest == *binding.FormerControllerFenceDigest &&
		ValidSHA256Digest(verification.CustodyProofDigest) &&
		ValidSHA256Digest(verification.FormerControllerFenceDigest) &&
		ValidSHA256Digest(verification.EvidenceDigest)
}
