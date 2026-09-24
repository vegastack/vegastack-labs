package recovery

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync/atomic"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const sourceHandoffDomain = "vegastack-labs.dev/recovery-source-handoff/v1\x00"

// VerifiedSourceHandoff exposes only public digests and expiry. Private fields
// retain one exact verified binding and opaque ciphertext until one use.
type VerifiedSourceHandoff struct {
	SourceDigest          string
	ManifestDigest        string
	WitnessDigest         string
	FenceDigest           string
	EnvelopeDigest        string
	SourceAdmissionDigest string
	ExpiresAt             time.Time
	binding               WitnessBinding
	envelope              ProtectedEnvelope
	used                  *atomic.Bool
}

func validateProtectedEnvelope(envelope ProtectedEnvelope, pin PinnedWitness, binding WitnessBinding) error {
	digest, _, _, err := transportBinding(pin, binding)
	if err != nil || envelope.Version != 1 || envelope.RecipientKeyID != pin.RecipientKeyID || envelope.BindingDigest != digest || envelope.ReceiptID != binding.ReceiptID || len(envelope.EphemeralPublicKey) != 32 || len(envelope.Nonce) != 12 || len(envelope.Ciphertext) < 24 || len(envelope.Ciphertext) > 4112 {
		return ErrWitnessUnavailable
	}
	return nil
}

func cloneProtectedEnvelope(envelope ProtectedEnvelope) ProtectedEnvelope {
	envelope.EphemeralPublicKey = append([]byte(nil), envelope.EphemeralPublicKey...)
	envelope.Nonce = append([]byte(nil), envelope.Nonce...)
	envelope.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	return envelope
}

type SourceHandoffDigests struct {
	WitnessDigest, EnvelopeDigest, SourceDigest string
}

// SourceHandoffDigest is the single production derivation for the actual
// post-plan witness, envelope and combined source identities. Qualification
// and signature verification remain mandatory separate admission steps.
func SourceHandoffDigest(installed InstalledPackage, qualificationDigest string) (SourceHandoffDigests, error) {
	var unavailable SourceHandoffDigests
	if !witnessDigest.MatchString(installed.Pin.ManifestDigest) || !witnessDigest.MatchString(qualificationDigest) || len(installed.Witness.Signature) != ed25519.SignatureSize {
		return unavailable, ErrWitnessUnavailable
	}
	witnessBytes, err := CanonicalWitnessPayload(installed.Witness.Payload)
	if err != nil {
		return unavailable, ErrWitnessUnavailable
	}
	witnessHash := sha256.Sum256(append(append([]byte(nil), witnessBytes...), installed.Witness.Signature...))
	witnessID := "sha256:" + hex.EncodeToString(witnessHash[:])
	envelopeBytes, err := json.Marshal(installed.Envelope)
	if err != nil {
		return unavailable, ErrWitnessUnavailable
	}
	envelopeHash := sha256.Sum256(envelopeBytes)
	envelopeID := "sha256:" + hex.EncodeToString(envelopeHash[:])
	sourceHash := sha256.Sum256([]byte(sourceHandoffDomain + installed.Pin.ManifestDigest + "\x00" + witnessID + "\x00" + qualificationDigest + "\x00" + envelopeID))
	return SourceHandoffDigests{WitnessDigest: witnessID, EnvelopeDigest: envelopeID, SourceDigest: "sha256:" + hex.EncodeToString(sourceHash[:])}, nil
}

// VerifyInstalledSource cannot qualify arbitrary caller registries: only an
// administrator-signed, exact compiled-factory registration gets the private
// sourceQualified seal. It still re-probes every direct-denial endpoint now.
func VerifyInstalledSource(ctx context.Context, expected WitnessBinding, required []BoundaryRequirement, installed InstalledPackage, qualified QualifiedAdapters, now time.Time) (VerifiedSourceHandoff, error) {
	var unavailable VerifiedSourceHandoff
	if ctx == nil || ctx.Err() != nil || now.IsZero() || !validCompleteRequirements(required) || !installed.Pin.matchesBinding(expected) || !witnessDigest.MatchString(installed.Pin.adminRootDigest) || installed.Pin.adminRootDigest != qualified.adminRootDigest || !qualified.sourceQualified || !witnessDigest.MatchString(qualified.qualificationDigest) || qualified.qualificationExpiry.IsZero() || !now.Before(qualified.qualificationExpiry) || len(required) != len(installed.Pin.Requirements) {
		return unavailable, ErrWitnessUnavailable
	}
	for i := range required {
		if required[i] != installed.Pin.Requirements[i] {
			return unavailable, ErrWitnessUnavailable
		}
	}
	if VerifyWitnessBundle(ctx, installed.Pin, expected, installed.Witness, required, qualified, now) != nil || validateProtectedEnvelope(installed.Envelope, installed.Pin, expected) != nil || ctx.Err() != nil {
		return unavailable, ErrWitnessUnavailable
	}
	admissionDigest := SourceAdmissionDigest(SourceAdmission{FormerHostID: expected.FormerHostID, FormerInstanceID: expected.FormerInstanceID, ReplacementHostID: expected.ReplacementHostID, ReplacementInstanceID: expected.ReplacementInstanceID, DraftID: expected.DraftID, CiphertextFingerprint: expected.CiphertextFingerprint, PriorEpoch: expected.PriorEpoch, NewEpoch: expected.NewEpoch, WitnessKeyID: installed.Pin.KeyID, WitnessInstanceID: installed.Pin.WitnessInstanceID, RecipientKeyID: installed.Pin.RecipientKeyID, WitnessPublicKey: installed.Pin.PublicKey, RecipientPublicKey: installed.Pin.RecipientPublicKey, AdminRootDigest: installed.Pin.adminRootDigest, FenceQualificationDigest: qualified.qualificationDigest, TargetReleaseBuildID: expected.TargetReleaseBuildID, TargetToolVersion: expected.TargetToolVersion, TargetSchemaVersion: expected.TargetSchemaVersion, RequiredDependencies: append([]generated.RestoreDependencyBinding(nil), expected.RequiredDependencies...), Requirements: required})
	if admissionDigest == "" || admissionDigest != expected.SourceAdmissionDigest || qualified.qualificationDigest != expected.FenceQualificationDigest {
		return unavailable, ErrWitnessUnavailable
	}
	digests, err := SourceHandoffDigest(installed, qualified.qualificationDigest)
	if err != nil {
		return unavailable, ErrWitnessUnavailable
	}
	expires := installed.Pin.ExpiresAt
	for _, candidate := range []time.Time{installed.Witness.Payload.ExpiresAt, qualified.qualificationExpiry} {
		if candidate.Before(expires) {
			expires = candidate
		}
	}
	if !now.Before(expires) {
		return unavailable, ErrWitnessUnavailable
	}
	return VerifiedSourceHandoff{SourceDigest: digests.SourceDigest, ManifestDigest: installed.Pin.ManifestDigest, WitnessDigest: digests.WitnessDigest, FenceDigest: qualified.qualificationDigest, EnvelopeDigest: digests.EnvelopeDigest, SourceAdmissionDigest: admissionDigest, ExpiresAt: expires, binding: expected, envelope: cloneProtectedEnvelope(installed.Envelope), used: new(atomic.Bool)}, nil
}

// ConsumeCustody burns the handoff locally before opening the protected
// recipient. VerifyCustody then durably burns the OS receipt and challenge
// before the exact comparator sees any opened private bytes.
func (handoff *VerifiedSourceHandoff) ConsumeCustody(ctx context.Context, recipient ProtectedRecipient, receipts ReceiptStore, compare func(io.ReadCloser) error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrWitnessUnavailable
		}
	}()
	if handoff == nil || handoff.used == nil || ctx == nil || ctx.Err() != nil || recipient == nil || receipts == nil || compare == nil || !time.Now().UTC().Before(handoff.ExpiresAt) || handoff.used.Swap(true) {
		return ErrWitnessUnavailable
	}
	stream, openErr := recipient.Open(ctx, cloneProtectedEnvelope(handoff.envelope), handoff.binding)
	if openErr != nil {
		if stream.Reader != nil {
			_ = stream.Reader.Close()
		}
		return ErrWitnessUnavailable
	}
	return VerifyCustody(ctx, handoff.binding, stream, receipts, compare)
}
