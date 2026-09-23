package recovery

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestAdmissionFenceRequirementsAreStaticAndProfileBound(t *testing.T) {
	witness, _, _ := ed25519.GenerateKey(rand.Reader)
	recipient, _ := ecdh.X25519().GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 24, 5, 0, 0, 0, time.UTC)
	admission := SourceAdmission{FormerHostID: "former-host", FormerInstanceID: "former-instance", ReplacementHostID: "replacement-host", ReplacementInstanceID: "replacement-instance", DraftID: "draft-a", CiphertextFingerprint: "sha256:" + strings.Repeat("a", 64), PriorEpoch: 3, NewEpoch: 4, WitnessKeyID: "witness-key", WitnessInstanceID: "outside-instance", RecipientKeyID: "recipient-key", WitnessPublicKey: witness, RecipientPublicKey: recipient.PublicKey().Bytes(), AdminRootDigest: "sha256:" + strings.Repeat("b", 64), FenceQualificationDigest: "sha256:" + strings.Repeat("c", 64), ValidFrom: now, ExpiresAt: now.Add(time.Hour), Requirements: []BoundaryRequirement{
		{Kind: "host-service", SubjectID: "service-a", TargetID: "former-host", AdapterID: "host-denial-v1", FormerIdentityID: "former-identity", ProbeID: "service-denied"},
		{Kind: "host-service", SubjectID: "service-a", TargetID: "former-host", AdapterID: "host-denial-v1", FormerIdentityID: "former-identity", ProbeID: "alternate-process-denied"},
	}}
	source := VerifiedSource{Binding: generated.RestoreSourceBinding{PointID: "point-a", RecoveryEpoch: 3}}
	profile := store.GateAppliedProfile{ProfileID: "labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", RecoveryEpoch: 3}
	requirements, err := AdmissionFenceRequirements(admission, profile, source, "build-a", "1.0.0")
	if err != nil || len(requirements) != 1 || len(requirements[0].RequiredEvidenceKinds) != 2 || requirements[0].FormerInstanceID != admission.FormerInstanceID {
		t.Fatalf("requirements=%#v err=%v", requirements, err)
	}
	profile.RecoveryEpoch++
	if _, err := AdmissionFenceRequirements(admission, profile, source, "build-a", "1.0.0"); err == nil {
		t.Fatal("cross-epoch applied profile accepted")
	}
}
