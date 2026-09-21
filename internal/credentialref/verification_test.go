package credentialref

import (
	"strings"
	"testing"
)

func TestStrictVerificationDigestAndReasonCode(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	for _, value := range []string{good, "sha256:" + strings.Repeat("0", 64)} {
		if !ValidSHA256Digest(value) {
			t.Fatalf("valid SHA-256 digest rejected: %q", value)
		}
	}
	for _, value := range []string{"sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("z", 64), good + "a", good[:len(good)-1], "SHA256:" + strings.Repeat("a", 64)} {
		if ValidSHA256Digest(value) {
			t.Fatalf("invalid SHA-256 digest accepted: %q", value)
		}
	}
	if !ValidReasonCode("reader-denied") || !ValidReasonCode("a") || !ValidReasonCode("a"+strings.Repeat("0", 63)) {
		t.Fatal("valid reason code rejected")
	}
	for _, value := range []string{"", "-denied", "Reader-Denied", "reader_denied", "reader.denied", "a" + strings.Repeat("0", 64)} {
		if ValidReasonCode(value) {
			t.Fatalf("invalid reason code accepted: %q", value)
		}
	}
}

func TestConsumerVerificationBindsPositiveAndDeniedEvidence(t *testing.T) {
	binding := validActivateBinding()
	digest := "sha256:" + strings.Repeat("d", 64)
	positive, err := NewConsumerVerification(binding, "consumer-a", "profile-a", "role-a", digest, "loaded-version", "verified", true)
	if err != nil || !ValidConsumerVerification(binding, positive) {
		t.Fatalf("positive evidence rejected: %v", err)
	}
	denied, err := NewConsumerVerification(binding, "consumer-denied", "profile-a", "role-a", digest, "reader-denied", "denied", false)
	if err != nil || !ValidConsumerVerification(binding, denied) {
		t.Fatalf("denied evidence rejected: %v", err)
	}
	if denied.MaterialVersion != binding.MaterialVersion || denied.CiphertextFingerprint != binding.CiphertextFingerprint {
		t.Fatal("denied evidence not bound to exact material and fingerprint")
	}

	for name, mutate := range map[string]func(*ConsumerVerification){
		"old material":        func(v *ConsumerVerification) { v.MaterialVersion = "version-old" },
		"foreign fingerprint": func(v *ConsumerVerification) { v.CiphertextFingerprint = "sha256:" + strings.Repeat("e", 64) },
		"invalid profile":     func(v *ConsumerVerification) { v.ProfileID = "Bad ID" },
		"invalid role":        func(v *ConsumerVerification) { v.RoleID = "Bad ID" },
		"invalid digest":      func(v *ConsumerVerification) { v.EvidenceDigest = "sha256:" + strings.Repeat("z", 64) },
		"invalid reason":      func(v *ConsumerVerification) { v.ReasonCode = "Bad Reason" },
		"positive in denial":  func(v *ConsumerVerification) { v.ConsumerID = "consumer-a" },
		"restart on denial":   func(v *ConsumerVerification) { v.RestartObserved = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := denied
			mutate(&changed)
			if ValidConsumerVerification(binding, changed) {
				t.Fatal("tampered denied evidence accepted")
			}
		})
	}
	if _, err := NewConsumerVerification(binding, "Bad ID", "profile-a", "role-a", digest, "reader-denied", "denied", false); err == nil {
		t.Fatal("invalid consumer ID accepted")
	}
	if _, err := NewConsumerVerification(binding, "consumer-a", "profile-a", "role-a", digest, "loaded-version", "verified", false); err == nil {
		t.Fatal("unobserved positive evidence accepted")
	}
}
