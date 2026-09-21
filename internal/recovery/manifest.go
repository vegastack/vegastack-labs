package recovery

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

const manifestDomain = "vegastack-labs.dev/recovery-manifest/v1\x00"

type RecoveryManifest struct {
	ManifestID            string    `json:"manifestId"`
	WitnessKeyID          string    `json:"witnessKeyId"`
	WitnessInstanceID     string    `json:"witnessInstanceId"`
	WitnessPublicKey      []byte    `json:"witnessPublicKey"`
	RecipientKeyID        string    `json:"recipientKeyId"`
	RecipientPublicKey    []byte    `json:"recipientPublicKey"`
	FormerHostID          string    `json:"formerHostId"`
	FormerInstanceID      string    `json:"formerInstanceId"`
	ReplacementHostID     string    `json:"replacementHostId"`
	ReplacementInstanceID string    `json:"replacementInstanceId"`
	PriorEpoch            int64     `json:"priorEpoch"`
	NewEpoch              int64     `json:"newEpoch"`
	ValidFrom             time.Time `json:"validFrom"`
	ExpiresAt             time.Time `json:"expiresAt"`
	Revoked               bool      `json:"revoked"`
}

type SignedRecoveryManifest struct {
	Payload   RecoveryManifest `json:"payload"`
	Signature []byte           `json:"signature"`
}

func CanonicalRecoveryManifest(payload RecoveryManifest) ([]byte, error) {
	if !validWitnessToken(payload.ManifestID) || !validWitnessToken(payload.WitnessKeyID) || !validWitnessToken(payload.WitnessInstanceID) || !validWitnessToken(payload.RecipientKeyID) || len(payload.WitnessPublicKey) != ed25519.PublicKeySize || len(payload.RecipientPublicKey) != 32 || !validWitnessToken(payload.FormerHostID) || !validWitnessToken(payload.FormerInstanceID) || !validWitnessToken(payload.ReplacementHostID) || !validWitnessToken(payload.ReplacementInstanceID) || payload.PriorEpoch < 0 || payload.NewEpoch != payload.PriorEpoch+1 || payload.ValidFrom.IsZero() || payload.ExpiresAt.IsZero() || payload.Revoked {
		return nil, ErrWitnessUnavailable
	}
	if _, err := ecdh.X25519().NewPublicKey(payload.RecipientPublicKey); err != nil {
		return nil, ErrWitnessUnavailable
	}
	payload.ValidFrom = payload.ValidFrom.UTC()
	payload.ExpiresAt = payload.ExpiresAt.UTC()
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrWitnessUnavailable
	}
	return append([]byte(manifestDomain), data...), nil
}

// ParseSignedRecoveryManifest validates an artifact against an admin public
// key supplied by an independently protected root. Production callers must
// use LoadSystemWitnessManifest, which reads the fixed owner-only OS paths.
func ParseSignedRecoveryManifest(raw []byte, adminPublic ed25519.PublicKey, expected WitnessBinding, now time.Time) (PinnedWitness, error) {
	var zero PinnedWitness
	if len(raw) == 0 || len(raw) > 16384 || len(adminPublic) != ed25519.PublicKeySize || !validBinding(expected) {
		return zero, ErrWitnessUnavailable
	}
	var artifact SignedRecoveryManifest
	if json.Unmarshal(raw, &artifact) != nil || len(artifact.Signature) != ed25519.SignatureSize {
		return zero, ErrWitnessUnavailable
	}
	encoded, err := json.Marshal(artifact)
	if err != nil || !bytes.Equal(encoded, raw) {
		return zero, ErrWitnessUnavailable
	}
	payload := artifact.Payload
	canonical, err := CanonicalRecoveryManifest(payload)
	if err != nil || !ed25519.Verify(adminPublic, canonical, artifact.Signature) {
		return zero, ErrWitnessUnavailable
	}
	now = now.UTC()
	if payload.ValidFrom.After(now) || !now.Before(payload.ExpiresAt) || payload.ExpiresAt.Sub(payload.ValidFrom) > 24*time.Hour || payload.FormerHostID != expected.FormerHostID || payload.FormerInstanceID != expected.FormerInstanceID || payload.ReplacementHostID != expected.ReplacementHostID || payload.ReplacementInstanceID != expected.ReplacementInstanceID || payload.PriorEpoch != expected.PriorEpoch || payload.NewEpoch != expected.NewEpoch || payload.WitnessInstanceID == expected.FormerInstanceID || payload.WitnessInstanceID == expected.ReplacementInstanceID {
		return zero, ErrWitnessUnavailable
	}
	sum := sha256.Sum256(append(append([]byte(nil), canonical...), artifact.Signature...))
	pin := PinnedWitness{KeyID: payload.WitnessKeyID, WitnessInstanceID: payload.WitnessInstanceID, PublicKey: append(ed25519.PublicKey(nil), payload.WitnessPublicKey...), RecipientKeyID: payload.RecipientKeyID, RecipientPublicKey: append([]byte(nil), payload.RecipientPublicKey...), ManifestDigest: "sha256:" + hex.EncodeToString(sum[:]), AuthenticatedExternally: true, ExpiresAt: payload.ExpiresAt, manifestAuthenticated: true, manifestBinding: manifestBoundIdentity{payload.FormerHostID, payload.FormerInstanceID, payload.ReplacementHostID, payload.ReplacementInstanceID, payload.PriorEpoch, payload.NewEpoch}}
	pin.pinSeal = pin.seal()
	return pin, nil
}
