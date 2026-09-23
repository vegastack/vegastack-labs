//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func acceptanceDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// This fixture composes the real native comparator with the #159 source-loader
// adapter seam. It is never registered in production: #108 has not established
// current recovery-required authority and no live denial adapter is qualified.
type acceptanceRecoverySource struct {
	*installedRecoverySource
	custody, fence string
	enrollment     *acceptanceRecoveryEnrollment
}

type acceptanceRecoveryEnrollment struct {
	witnessPublic            ed25519.PublicKey
	witnessPrivate           ed25519.PrivateKey
	adminPublic              ed25519.PublicKey
	adminPrivate             ed25519.PrivateKey
	recipientKey             *ecdh.PrivateKey
	required                 []recovery.BoundaryRequirement
	sourceAdmissionDigest    string
	fenceQualificationDigest string
}

type acceptanceInstalledAuthority struct {
	binding  recovery.WitnessBinding
	required []recovery.BoundaryRequirement
}

func (authority acceptanceInstalledAuthority) CurrentInstalledRecovery(context.Context, RecoveryCustodyRequest) (installedRecoveryAuthority, error) {
	return installedRecoveryAuthority{Binding: authority.binding, Required: append([]recovery.BoundaryRequirement(nil), authority.required...), SourceAdmissionDigest: authority.binding.SourceAdmissionDigest, FenceQualificationDigest: authority.binding.FenceQualificationDigest}, nil
}

type acceptanceInstalledLoader struct {
	binding   recovery.WitnessBinding
	required  []recovery.BoundaryRequirement
	candidate recoveryWitnessCandidate
	public    installedRecoveryCandidate
}

func (loader acceptanceInstalledLoader) LoadVerified(_ context.Context, binding recovery.WitnessBinding, required []recovery.BoundaryRequirement, _ time.Time) (installedRecoveryCandidate, error) {
	if binding != loader.binding || len(required) != len(loader.required) {
		return installedRecoveryCandidate{}, recovery.ErrWitnessUnavailable
	}
	for index := range required {
		if required[index] != loader.required[index] {
			return installedRecoveryCandidate{}, recovery.ErrWitnessUnavailable
		}
	}
	return loader.public, nil
}

func newAcceptanceRecoveryEnrollment(t *testing.T, binding recovery.WitnessBinding) *acceptanceRecoveryEnrollment {
	t.Helper()
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	required := []recovery.BoundaryRequirement{
		{Kind: "host-service", SubjectID: "former-service", TargetID: "former-host", AdapterID: "synthetic-adapter", FormerIdentityID: "former-identity", ProbeID: "service-denied"},
		{Kind: "host-service", SubjectID: "former-service", TargetID: "former-host", AdapterID: "synthetic-adapter", FormerIdentityID: "former-identity", ProbeID: "alternate-process-denied"},
	}
	fenceQualificationDigest := acceptanceDigest([]byte("fixture-qualification"))
	sourceAdmissionDigest := recovery.SourceAdmissionDigest(recovery.SourceAdmission{
		FormerHostID: binding.FormerHostID, FormerInstanceID: binding.FormerInstanceID,
		ReplacementHostID: binding.ReplacementHostID, ReplacementInstanceID: binding.ReplacementInstanceID,
		DraftID: binding.DraftID, CiphertextFingerprint: binding.CiphertextFingerprint,
		PriorEpoch: binding.PriorEpoch, NewEpoch: binding.NewEpoch,
		WitnessKeyID: "witness-key", WitnessInstanceID: "outside-instance", RecipientKeyID: "recipient-key",
		WitnessPublicKey: witnessPublic, RecipientPublicKey: recipientKey.PublicKey().Bytes(),
		AdminRootDigest: acceptanceDigest(adminPublic), FenceQualificationDigest: fenceQualificationDigest,
		Requirements: required,
	})
	if sourceAdmissionDigest == "" {
		t.Fatal("invalid pre-plan recovery source admission")
	}
	return &acceptanceRecoveryEnrollment{witnessPublic: witnessPublic, witnessPrivate: witnessPrivate, adminPublic: adminPublic, adminPrivate: adminPrivate,
		recipientKey: recipientKey, required: required, sourceAdmissionDigest: sourceAdmissionDigest, fenceQualificationDigest: fenceQualificationDigest}
}

func newAcceptanceRecoverySource(t *testing.T, binding recovery.WitnessBinding, draft store.CredentialImportDraft, native nativecredential.VerifyRecoveryRequest, material []byte, enrollment *acceptanceRecoveryEnrollment) *acceptanceRecoverySource {
	t.Helper()
	now := time.Now().UTC()
	if enrollment == nil {
		enrollment = newAcceptanceRecoveryEnrollment(t, binding)
	}
	binding.SourceAdmissionDigest = enrollment.sourceAdmissionDigest
	binding.FenceQualificationDigest = enrollment.fenceQualificationDigest
	manifest := recovery.RecoveryManifest{
		ManifestID: "manifest-acceptance", WitnessKeyID: "witness-key", WitnessInstanceID: "outside-instance",
		WitnessPublicKey: enrollment.witnessPublic, RecipientKeyID: "recipient-key", RecipientPublicKey: enrollment.recipientKey.PublicKey().Bytes(),
		Binding: binding, ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
	}
	manifestBytes, err := recovery.CanonicalRecoveryManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signedManifest, err := json.Marshal(recovery.SignedRecoveryManifest{Payload: manifest, Signature: ed25519.Sign(enrollment.adminPrivate, manifestBytes)})
	if err != nil {
		t.Fatal(err)
	}
	pin, err := recovery.ParseSignedRecoveryManifest(signedManifest, enrollment.adminPublic, binding, now)
	if err != nil {
		t.Fatal(err)
	}
	required := enrollment.required
	transcripts := make([]recovery.DirectDenialTranscript, 0, len(required))
	for _, item := range required {
		transcripts = append(transcripts, recovery.DirectDenialTranscript{
			Requirement: item, ObserverID: "outside-observer", ChallengeID: binding.ChallengeID, ResponseClass: "direct-denial",
			ResponseDigest: acceptanceDigest([]byte(item.ProbeID)), ObservedAt: now.Add(-time.Second),
			ExpiresAt: now.Add(20 * time.Second), SessionExpiry: now.Add(20 * time.Second), Denied: true,
		})
	}
	payload := recovery.WitnessPayload{Binding: binding, KeyID: pin.KeyID, WitnessInstanceID: pin.WitnessInstanceID,
		IssuedAt: now.Add(-time.Second), ObservedAt: now.Add(-time.Second), ExpiresAt: now.Add(20 * time.Second), Transcripts: transcripts}
	canonical, err := recovery.CanonicalWitnessPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed := recovery.SignedWitness{Payload: payload, Signature: ed25519.Sign(enrollment.witnessPrivate, canonical)}
	qualified := recovery.NewQualifiedAdapters()
	qualified.Register("synthetic-adapter", isolatedWitnessAdapter{})
	envelope, err := recovery.SealProtectedEnvelope(context.Background(), pin, binding, io.NopCloser(bytes.NewReader(material)))
	if err != nil {
		t.Fatal(err)
	}
	witnessCandidate := recoveryWitnessCandidate{Pin: pin, Expected: binding, Signed: signed, Required: required, Qualified: qualified,
		Envelope: envelope, Recipient: recovery.NewProtectedRecipient(pin, &isolatedRecipientKeySource{key: enrollment.recipientKey.Bytes()}), Receipts: &isolatedReceipts{}}
	handoffDigests, err := recovery.SourceHandoffDigest(recovery.InstalledPackage{Pin: pin, Witness: signed, Envelope: envelope}, enrollment.fenceQualificationDigest)
	if err != nil {
		t.Fatal(err)
	}
	public := installedRecoveryCandidate{
		sourceDigest:   handoffDigests.SourceDigest,
		manifestDigest: pin.ManifestDigest, witnessDigest: handoffDigests.WitnessDigest, fenceDigest: enrollment.fenceQualificationDigest, envelopeDigest: handoffDigests.EnvelopeDigest, sourceAdmissionDigest: enrollment.sourceAdmissionDigest,
		consume: func(ctx context.Context, compare func(io.ReadCloser) error) error {
			return witnessCandidate.verify(ctx, compare)
		},
	}
	loader := acceptanceInstalledLoader{binding: binding, required: required, candidate: witnessCandidate, public: public}
	return &acceptanceRecoverySource{installedRecoverySource: &installedRecoverySource{
		authority: acceptanceInstalledAuthority{binding: binding, required: required}, loader: loader,
		ciphertextRoot: native.CiphertextDirectory, ownerUID: native.ExpectedUID, clock: time.Now, compare: nativecredential.VerifyRecoveredDraft,
	}, custody: enrollment.sourceAdmissionDigest, fence: enrollment.fenceQualificationDigest, enrollment: enrollment}
}

func TestCredentialRecoveryAcceptanceNativeWitnessAndDraft(t *testing.T) {
	if os.Getenv("VSK_NATIVE_CREDENTIAL_RECOVERY") != "1" {
		t.Skip("disposable Linux host-key fixture required")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil || os.Geteuid() != 0 {
		t.Fatal("host-key fixture must run as root in disposable Docker")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	material := []byte("synthetic-independent-recovery-canary")
	t.Cleanup(func() {
		for i := range material {
			material[i] = 0
		}
	})
	oldName := "credential-old-acceptance"
	oldFingerprint, err := nativecredential.StageEncrypted(context.Background(), bytes.NewReader(material),
		nativecredential.StageRequest{Name: oldName, CiphertextDirectory: directory, ExpectedUID: 0})
	if err != nil {
		t.Fatal(err)
	}
	const hostKey = "/var/lib/systemd/credential.secret"
	retained := hostKey + ".vsk-144-acceptance-old"
	if _, err := os.Lstat(retained); !os.IsNotExist(err) {
		t.Fatal("fixture sibling already exists")
	}
	if err := os.Rename(hostKey, retained); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(hostKey)
		if err := os.Rename(retained, hostKey); err != nil {
			t.Error(err)
		}
	})
	setup := exec.Command("/usr/bin/systemd-creds", "setup")
	setup.Stdout, setup.Stderr = io.Discard, io.Discard
	if err := setup.Run(); err != nil {
		t.Fatal("replacement fixture host key unavailable")
	}
	name := "credential-new-acceptance"
	fingerprint, err := nativecredential.StageEncrypted(context.Background(), bytes.NewReader(material),
		nativecredential.StageRequest{Name: name, CiphertextDirectory: directory, ExpectedUID: 0})
	if err != nil {
		t.Fatal(err)
	}
	old := nativecredential.VerifyRecoveryRequest{Name: oldName, CiphertextDirectory: directory, ExpectedUID: 0, ExpectedFingerprint: oldFingerprint}
	if _, err := nativecredential.VerifyRecoveredDraft(context.Background(), old, io.NopCloser(bytes.NewReader(material))); err == nil {
		t.Fatal("former ciphertext decrypted under replacement host key")
	}
	step, lifecycle, draft, _ := recoveryCustodyFixture(t)
	lifecycle.CiphertextFingerprint = fingerprint
	step.Step.ArtifactDigest = fingerprint
	draft.CiphertextName, draft.CiphertextFingerprint = name, fingerprint
	native := nativecredential.VerifyRecoveryRequest{Name: name, CiphertextDirectory: directory, ExpectedUID: 0, ExpectedFingerprint: fingerprint}
	binding := recovery.WitnessBinding{FormerHostID: "former-host", FormerInstanceID: "former-instance",
		ReplacementHostID: "replacement-host", ReplacementInstanceID: "replacement-instance",
		DraftID: draft.DraftID, CiphertextFingerprint: fingerprint, PlanDigest: step.Plan.PlanDigest,
		RunID: step.Run.RunID, StepID: step.Step.StepID, LeaseID: step.Lease.LeaseID,
		ChallengeID: "challenge-acceptance", ReceiptID: "receipt-acceptance",
		PriorEpoch: *lifecycle.PriorRecoveryEpoch, NewEpoch: lifecycle.RecoveryEpoch, StateRevision: lifecycle.StateRevision}
	source := newAcceptanceRecoverySource(t, binding, draft, native, material, nil)
	binding = source.installedRecoverySource.authority.(acceptanceInstalledAuthority).binding
	lifecycle.CustodyProofDigest, lifecycle.FormerControllerFenceDigest = &source.custody, &source.fence
	revision := recoveryRevisionFixture{token: store.RevisionToken{StateRevision: lifecycle.StateRevision, RecoveryEpoch: lifecycle.RecoveryEpoch}}
	verifier, err := NewRecoveryCustodyVerifier(recoveryDraftFixture{draft: draft}, revision, source)
	if err != nil {
		t.Fatal(err)
	}
	changedDraft := draft
	changedDraft.DraftID = "foreign-draft"
	foreignDraftVerifier, err := NewRecoveryCustodyVerifier(recoveryDraftFixture{draft: changedDraft}, revision, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreignDraftVerifier.Verify(context.Background(), step, lifecycle); err == nil || strings.Contains(err.Error(), string(material)) {
		t.Fatal("foreign sealed draft accepted or leaked private material")
	}
	for label, mutate := range map[string]func(*run.ExactStepBinding, *credentialref.LifecycleBinding){
		"plan": func(s *run.ExactStepBinding, _ *credentialref.LifecycleBinding) {
			s.Plan.PlanDigest = acceptanceDigest([]byte("wrong-plan"))
		},
		"lease": func(s *run.ExactStepBinding, _ *credentialref.LifecycleBinding) { s.Lease.LeaseID = "wrong-lease" },
		"epoch": func(_ *run.ExactStepBinding, l *credentialref.LifecycleBinding) { l.RecoveryEpoch++ },
	} {
		changedStep, changedLifecycle := step, lifecycle
		mutate(&changedStep, &changedLifecycle)
		if _, err := verifier.Verify(context.Background(), changedStep, changedLifecycle); err == nil || strings.Contains(err.Error(), string(material)) {
			t.Fatalf("%s mismatch accepted or leaked private material", label)
		}
	}
	result, err := verifier.Verify(context.Background(), step, lifecycle)
	if err != nil || !credentialref.ValidRecoveryVerification(lifecycle, result) {
		t.Fatalf("exact signed witness, custody and native draft rejected: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), step, lifecycle); err == nil || strings.Contains(err.Error(), string(material)) {
		t.Fatal("one-use receipt replay accepted or leaked private material")
	}
	wrong := acceptanceDigest([]byte("wrong-fence"))
	wrongLifecycle := lifecycle
	wrongLifecycle.FormerControllerFenceDigest = &wrong
	second := newAcceptanceRecoverySource(t, binding, draft, native, material, source.enrollment)
	secondVerifier, err := NewRecoveryCustodyVerifier(recoveryDraftFixture{draft: draft}, revision, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondVerifier.Verify(context.Background(), step, wrongLifecycle); err == nil || strings.Contains(err.Error(), string(material)) {
		t.Fatal("foreign fence accepted or leaked private material")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := secondVerifier.Verify(cancelled, step, lifecycle); err == nil {
		t.Fatal("cancelled recovery accepted")
	}
}
