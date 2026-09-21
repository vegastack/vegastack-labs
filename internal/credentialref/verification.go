package credentialref

import (
	"regexp"
	"slices"
)

var reasonCodePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// ValidSHA256Digest accepts only a canonical lowercase hexadecimal SHA-256
// digest. Provider-shaped references and merely length-correct strings fail.
func ValidSHA256Digest(value string) bool {
	return fingerprintPattern.MatchString(value)
}

// ValidReasonCode accepts a bounded, non-sensitive machine reason code.
func ValidReasonCode(code string) bool {
	return reasonCodePattern.MatchString(code)
}

// NewConsumerVerification is the provider-neutral constructor for evidence
// about one exact consumer of a sealed lifecycle binding. No value material is
// retained in the result.
func NewConsumerVerification(binding LifecycleBinding, consumerID, profileID, roleID, evidenceDigest, reasonCode, result string, restartObserved bool) (ConsumerVerification, error) {
	verification := ConsumerVerification{
		ConsumerID:            consumerID,
		ProfileID:             profileID,
		RoleID:                roleID,
		MaterialVersion:       binding.MaterialVersion,
		CiphertextFingerprint: binding.CiphertextFingerprint,
		EvidenceDigest:        evidenceDigest,
		RestartObserved:       restartObserved,
		Result:                result,
		ReasonCode:            reasonCode,
	}
	if !ValidConsumerVerification(binding, verification) {
		return ConsumerVerification{}, newError("INPUT_INVALID", "credential-consumer-verification")
	}
	return verification, nil
}

// ValidConsumerVerification rechecks both positive and required-denied proof
// against the same sealed version and ciphertext identity before persistence.
func ValidConsumerVerification(binding LifecycleBinding, verification ConsumerVerification) bool {
	if !ValidLifecycleBinding(binding) || (binding.Action != ActionActivate && binding.Action != ActionRotate) {
		return false
	}
	for _, id := range []string{verification.ConsumerID, verification.ProfileID, verification.RoleID} {
		if _, err := ParseID(id); err != nil {
			return false
		}
	}
	if verification.MaterialVersion != binding.MaterialVersion || verification.CiphertextFingerprint != binding.CiphertextFingerprint || !ValidSHA256Digest(verification.EvidenceDigest) || !ValidReasonCode(verification.ReasonCode) {
		return false
	}
	switch verification.Result {
	case "verified":
		if !verification.RestartObserved || !slices.Contains(binding.ConsumerIDs, verification.ConsumerID) {
			return false
		}
		if binding.ResolverID == "native-systemd" {
			for _, reader := range binding.NativeConsumers {
				if reader.ConsumerID == verification.ConsumerID {
					return reader.ProfileID == verification.ProfileID && reader.RoleID == verification.RoleID
				}
			}
			return false
		}
		return true
	case "denied":
		if verification.RestartObserved || !slices.Contains(binding.RequiredDeniedConsumerIDs, verification.ConsumerID) {
			return false
		}
		if binding.ResolverID == "native-systemd" {
			for _, reader := range binding.NativeDeniedReaders {
				if reader.ConsumerID == verification.ConsumerID {
					return reader.ProfileID == verification.ProfileID && reader.RoleID == verification.RoleID
				}
			}
			return false
		}
		return true
	default:
		return false
	}
}
