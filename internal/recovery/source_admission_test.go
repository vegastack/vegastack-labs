package recovery

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
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
		ValidFrom: time.Date(2026, 9, 24, 5, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC),
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

func TestSignedSourceAdmissionIsPrePlanAndExact(t *testing.T) {
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	recipient, _ := ecdh.X25519().GenerateKey(rand.Reader)
	admission := SourceAdmission{
		FormerHostID: "former-host", FormerInstanceID: "former-instance", ReplacementHostID: "replacement-host", ReplacementInstanceID: "replacement-instance",
		DraftID: "draft-a", CiphertextFingerprint: "sha256:" + strings.Repeat("a", 64), PriorEpoch: 3, NewEpoch: 4,
		WitnessKeyID: "witness-key", WitnessInstanceID: "outside-instance", RecipientKeyID: "recipient-key",
		WitnessPublicKey: witnessPublic, RecipientPublicKey: recipient.PublicKey().Bytes(), AdminRootDigest: recoveryAdminRootDigest(adminPublic),
		FenceQualificationDigest: "sha256:" + strings.Repeat("c", 64), Requirements: []BoundaryRequirement{
			{Kind: "host-service", SubjectID: "service-a", TargetID: "former-host", AdapterID: "host-denial-v1", FormerIdentityID: "former-instance", ProbeID: "alternate-process-denied"},
			{Kind: "host-service", SubjectID: "service-a", TargetID: "former-host", AdapterID: "host-denial-v1", FormerIdentityID: "former-instance", ProbeID: "service-denied"},
		},
		ValidFrom: time.Date(2026, 9, 24, 5, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC),
	}
	canonical, err := canonicalSourceAdmission(admission)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(SignedSourceAdmission{Payload: admission, Signature: ed25519.Sign(adminPrivate, canonical)})
	expected := SourceAdmissionExpectation{FormerHostID: admission.FormerHostID, FormerInstanceID: admission.FormerInstanceID, ReplacementHostID: admission.ReplacementHostID, ReplacementInstanceID: admission.ReplacementInstanceID, DraftID: admission.DraftID, CiphertextFingerprint: admission.CiphertextFingerprint, SourceAdmissionDigest: SourceAdmissionDigest(admission), FenceQualificationDigest: admission.FenceQualificationDigest, PriorEpoch: admission.PriorEpoch, NewEpoch: admission.NewEpoch}
	if _, err := ParseSignedSourceAdmission(raw, adminPublic, expected, admission.ValidFrom.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	expected.SourceAdmissionDigest = "sha256:" + strings.Repeat("d", 64)
	if _, err := ParseSignedSourceAdmission(raw, adminPublic, expected, admission.ValidFrom.Add(time.Minute)); err == nil {
		t.Fatal("wrong pre-plan source admission digest accepted")
	}
	// A plan digest is intentionally absent: this artifact closes the stable
	// admission stage, while the later witness package binds the exact plan/run.
	if strings.Contains(string(raw), "planDigest") {
		t.Fatal("pre-plan source admission contains circular plan binding")
	}
}
