package recovery

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"
)

func installedSourceFixture(t *testing.T) (InstalledPackage, []BoundaryRequirement, QualifiedAdapters, WitnessBinding, time.Time, []byte) {
	t.Helper()
	pin, binding, _, now := witnessFixture(t)
	now = time.Now().UTC()
	pin.ExpiresAt = now.Add(time.Hour)
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	required, _, _, _ := boundaryFixture()
	required = required[:2]
	pin.PublicKey = witnessPublic
	pin.RecipientPublicKey = recipient.PublicKey().Bytes()
	pin.Requirements = append([]BoundaryRequirement(nil), required...)
	adminPublic, adminPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	first := required[0]
	entry := AdapterQualification{AdapterID: first.AdapterID, Kind: first.Kind, SubjectID: first.SubjectID, TargetID: first.TargetID, FormerIdentityID: first.FormerIdentityID, ImplementationDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ValidFrom: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload := QualificationRecord{RecordID: "registration-1", Entries: []AdapterQualification{entry}}
	canonical, err := CanonicalQualificationRecord(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(SignedQualificationRecord{Payload: payload, Signature: ed25519.Sign(adminPrivate, canonical)})
	if err != nil {
		t.Fatal(err)
	}
	factories := map[string]qualifiedFactory{entry.AdapterID: {implementationDigest: entry.ImplementationDigest, new: func(AdapterQualification) DirectDenialVerifier { return fixtureDenialVerifier{} }}}
	pin.adminRootDigest = recoveryAdminRootDigest(adminPublic)
	pin.pinSeal = pin.seal()
	qualified, err := parseQualifiedAdapters(raw, adminPublic, required, now, factories)
	if err != nil {
		t.Fatalf("qualification: %v", err)
	}
	binding.FenceQualificationDigest = qualified.qualificationDigest
	binding.SourceAdmissionDigest = SourceAdmissionDigest(SourceAdmission{
		FormerHostID: binding.FormerHostID, FormerInstanceID: binding.FormerInstanceID,
		ReplacementHostID: binding.ReplacementHostID, ReplacementInstanceID: binding.ReplacementInstanceID,
		DraftID: binding.DraftID, CiphertextFingerprint: binding.CiphertextFingerprint,
		PriorEpoch: binding.PriorEpoch, NewEpoch: binding.NewEpoch,
		WitnessKeyID: pin.KeyID, WitnessInstanceID: pin.WitnessInstanceID, RecipientKeyID: pin.RecipientKeyID,
		WitnessPublicKey: pin.PublicKey, RecipientPublicKey: pin.RecipientPublicKey,
		AdminRootDigest: pin.adminRootDigest, FenceQualificationDigest: qualified.qualificationDigest, TargetReleaseBuildID: binding.TargetReleaseBuildID, TargetToolVersion: binding.TargetToolVersion, TargetSchemaVersion: binding.TargetSchemaVersion, RequiredDependencies: binding.RequiredDependencies, Requirements: required,
	})
	pin.manifestBinding = binding
	pin.pinSeal = pin.seal()
	signed, envelope, err := CollectWitness(context.Background(), CollectRequest{Pin: pin, Binding: binding, Required: required, Adapters: map[string]recoverydenial.Adapter{"adapter-1": collectorAdapter{now: now}}, SigningKey: io.NopCloser(bytes.NewReader(witnessPrivate.Seed())), Material: io.NopCloser(bytes.NewReader([]byte("synthetic-private-canary"))), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("collect source: %v", err)
	}
	return InstalledPackage{Pin: pin, Witness: signed, Envelope: envelope}, required, qualified, binding, now, recipient.Bytes()
}

func TestInstalledSourceRejectsPartialFenceAndBurnsFailedCustody(t *testing.T) {
	installed, required, qualified, binding, now, recipientSeed := installedSourceFixture(t)
	if _, err := VerifyInstalledSource(context.Background(), binding, required[:1], installed, qualified, now); err == nil {
		t.Fatal("partial required boundary admitted")
	}
	otherRoot := qualified
	otherRoot.adminRootDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := VerifyInstalledSource(context.Background(), binding, required, installed, otherRoot, now); err == nil {
		t.Fatal("qualification from a different admin root admitted")
	}
	bad := qualified
	bad.entries = map[string]DirectDenialVerifier{"adapter-1": fixtureDenialVerifier{reject: true}}
	if _, err := VerifyInstalledSource(context.Background(), binding, required, installed, bad, now); err == nil {
		t.Fatal("former writer survived direct denial")
	}
	handoff, err := VerifyInstalledSource(context.Background(), binding, required, installed, qualified, now)
	if err != nil {
		t.Fatal(err)
	}
	digests, err := SourceHandoffDigest(installed, qualified.qualificationDigest)
	if err != nil || handoff.WitnessDigest != digests.WitnessDigest || handoff.EnvelopeDigest != digests.EnvelopeDigest || handoff.SourceDigest != digests.SourceDigest {
		t.Fatalf("verified handoff diverged from production digest derivation: handoff=%+v digests=%+v err=%v", handoff, digests, err)
	}
	if handoff.ManifestDigest != installed.Pin.ManifestDigest || handoff.SourceDigest == "" || handoff.FenceDigest != qualified.qualificationDigest {
		t.Fatal("public handoff digests missing")
	}
	protectedRecipient := NewProtectedRecipient(installed.Pin, &syntheticPrivateKeySource{key: recipientSeed})
	receipts := &testReceipts{}
	if err := handoff.ConsumeCustody(context.Background(), protectedRecipient, receipts, func(io.ReadCloser) error { return errors.New("comparison failed") }); err == nil {
		t.Fatal("failed comparison accepted")
	}
	if err := handoff.ConsumeCustody(context.Background(), protectedRecipient, receipts, func(io.ReadCloser) error { return nil }); err == nil {
		t.Fatal("receipt replayed")
	}
	for name, change := range map[string]func(*WitnessBinding){
		"draft": func(b *WitnessBinding) { b.DraftID = "other-draft" },
		"plan": func(b *WitnessBinding) {
			b.PlanDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		},
		"epoch": func(b *WitnessBinding) { b.NewEpoch++ },
		"lease": func(b *WitnessBinding) { b.LeaseID = "other-lease" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := binding
			change(&changed)
			if _, err := VerifyInstalledSource(context.Background(), changed, required, installed, qualified, now); err == nil {
				t.Fatal("wrong exact binding admitted")
			}
		})
	}
	if _, err := VerifyInstalledSource(context.Background(), binding, required, installed, qualified, now.Add(time.Hour)); err == nil {
		t.Fatal("stale source admitted")
	}
	second, err := VerifyInstalledSource(context.Background(), binding, required, installed, qualified, now)
	if err != nil {
		t.Fatal(err)
	}
	secondRecipient := NewProtectedRecipient(installed.Pin, &syntheticPrivateKeySource{key: recipientSeed})
	if err := second.ConsumeCustody(context.Background(), secondRecipient, &testReceipts{}, func(reader io.ReadCloser) error {
		value, readErr := io.ReadAll(reader)
		if readErr != nil || !bytes.Equal(value, []byte("synthetic-private-canary")) {
			return errors.New("wrong private material")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
