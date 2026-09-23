package recovery

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSourceAdmissionDigestIsCanonicalAndRejectsInvalidRecipient(t *testing.T) {
	t.Helper()
	witnessPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	required := []BoundaryRequirement{
		{Kind: "host-service", SubjectID: "service-a", TargetID: "former-host", AdapterID: "host-denial-v1", FormerIdentityID: "former-instance", ProbeID: "service-denied"},
		{Kind: "host-service", SubjectID: "service-a", TargetID: "former-host", AdapterID: "host-denial-v1", FormerIdentityID: "former-instance", ProbeID: "alternate-process-denied"},
	}
	admission := SourceAdmission{
		FormerHostID: "former-host", FormerInstanceID: "former-instance", ReplacementHostID: "replacement-host", ReplacementInstanceID: "replacement-instance",
		DraftID: "draft-a", CiphertextFingerprint: "sha256:" + strings.Repeat("a", 64), PriorEpoch: 3, NewEpoch: 4,
		WitnessKeyID: "witness-key", WitnessInstanceID: "outside-instance", RecipientKeyID: "recipient-key",
		WitnessPublicKey: witnessPublic, RecipientPublicKey: recipient.PublicKey().Bytes(),
		AdminRootDigest: "sha256:" + strings.Repeat("b", 64), FenceQualificationDigest: "sha256:" + strings.Repeat("c", 64), Requirements: required,
	}
	digest := SourceAdmissionDigest(admission)
	if digest == "" {
		t.Fatal("valid stable source admission rejected")
	}
	reordered := admission
	reordered.Requirements = []BoundaryRequirement{required[1], required[0]}
	if got := SourceAdmissionDigest(reordered); got != digest {
		t.Fatalf("caller order changed canonical admission: got %q want %q", got, digest)
	}
	if admission.Requirements[0] != required[0] || admission.Requirements[1] != required[1] {
		t.Fatal("canonicalization mutated caller requirements")
	}
	invalid := admission
	invalid.RecipientPublicKey = make([]byte, 32)
	if got := SourceAdmissionDigest(invalid); got != "" {
		t.Fatalf("unusable X25519 recipient admitted: %q", got)
	}
}
