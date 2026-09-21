package recovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

const witnessDomain = "vegastack-labs.dev/recovery-witness/v1\x00"
const maxWitnessAge = 60 * time.Second

var ErrWitnessUnavailable = errors.New("independent recovery witness unavailable")
var witnessToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
var witnessDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// WitnessBinding names one exact recovery attempt. The expected value must
// come from server-owned state; accepting it from the signed artifact alone
// would let a witness choose the authority being proved.
type WitnessBinding struct {
	FormerHostID          string `json:"formerHostId"`
	FormerInstanceID      string `json:"formerInstanceId"`
	ReplacementHostID     string `json:"replacementHostId"`
	ReplacementInstanceID string `json:"replacementInstanceId"`
	DraftID               string `json:"draftId"`
	CiphertextFingerprint string `json:"ciphertextFingerprint"`
	PlanDigest            string `json:"planDigest"`
	RunID                 string `json:"runId"`
	StepID                string `json:"stepId"`
	LeaseID               string `json:"leaseId"`
	ChallengeID           string `json:"challengeId"`
	ReceiptID             string `json:"receiptId"`
	PriorEpoch            int64  `json:"priorEpoch"`
	NewEpoch              int64  `json:"newEpoch"`
	StateRevision         int64  `json:"stateRevision"`
}

// PinnedWitness is supplied only by a protected manifest authenticated by an
// infrastructure administrator outside both controllers. There is no
// production manifest loader or registry in this package.
type PinnedWitness struct {
	KeyID                   string
	WitnessInstanceID       string
	PublicKey               ed25519.PublicKey
	AuthenticatedExternally bool
	Revoked                 bool
	ExpiresAt               time.Time
}

type WitnessPayload struct {
	Binding           WitnessBinding `json:"binding"`
	KeyID             string         `json:"keyId"`
	WitnessInstanceID string         `json:"witnessInstanceId"`
	IssuedAt          time.Time      `json:"issuedAt"`
	ObservedAt        time.Time      `json:"observedAt"`
	ExpiresAt         time.Time      `json:"expiresAt"`
}

type SignedWitness struct {
	Payload   WitnessPayload `json:"payload"`
	Signature []byte         `json:"signature"`
}

// CanonicalWitnessPayload is the complete, domain-separated signed byte
// sequence. Struct-only JSON avoids map ordering and omitempty ambiguity.
func CanonicalWitnessPayload(payload WitnessPayload) ([]byte, error) {
	if !validBinding(payload.Binding) || !validWitnessToken(payload.KeyID) || !validWitnessToken(payload.WitnessInstanceID) || payload.IssuedAt.IsZero() || payload.ObservedAt.IsZero() || payload.ExpiresAt.IsZero() {
		return nil, ErrWitnessUnavailable
	}
	payload.IssuedAt = payload.IssuedAt.UTC()
	payload.ObservedAt = payload.ObservedAt.UTC()
	payload.ExpiresAt = payload.ExpiresAt.UTC()
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, ErrWitnessUnavailable
	}
	return append([]byte(witnessDomain), data...), nil
}

func VerifySignedWitness(ctx context.Context, pin PinnedWitness, expected WitnessBinding, signed SignedWitness, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return ErrWitnessUnavailable
	}
	if !pin.AuthenticatedExternally || pin.Revoked || len(pin.PublicKey) != ed25519.PublicKeySize || !validWitnessToken(pin.KeyID) || !validWitnessToken(pin.WitnessInstanceID) || !validBinding(expected) {
		return ErrWitnessUnavailable
	}
	if pin.WitnessInstanceID == expected.FormerInstanceID || pin.WitnessInstanceID == expected.ReplacementInstanceID || expected.FormerInstanceID == expected.ReplacementInstanceID || expected.FormerHostID == expected.ReplacementHostID {
		return ErrWitnessUnavailable
	}
	payload := signed.Payload
	if payload.Binding != expected || payload.KeyID != pin.KeyID || payload.WitnessInstanceID != pin.WitnessInstanceID || len(signed.Signature) != ed25519.SignatureSize {
		return ErrWitnessUnavailable
	}
	now = now.UTC()
	if pin.ExpiresAt.IsZero() || !now.Before(pin.ExpiresAt) || payload.IssuedAt.After(payload.ObservedAt) || payload.ObservedAt.After(now) || payload.IssuedAt.After(now) || now.Sub(payload.ObservedAt) > maxWitnessAge || !now.Before(payload.ExpiresAt) || payload.ExpiresAt.Sub(payload.ObservedAt) > maxWitnessAge || payload.ExpiresAt.After(pin.ExpiresAt) {
		return ErrWitnessUnavailable
	}
	canonical, err := CanonicalWitnessPayload(payload)
	if err != nil || !ed25519.Verify(pin.PublicKey, canonical, signed.Signature) {
		return ErrWitnessUnavailable
	}
	if ctx.Err() != nil {
		return ErrWitnessUnavailable
	}
	return nil
}

func validBinding(b WitnessBinding) bool {
	for _, value := range []string{b.FormerHostID, b.FormerInstanceID, b.ReplacementHostID, b.ReplacementInstanceID, b.DraftID, b.RunID, b.StepID, b.LeaseID, b.ChallengeID, b.ReceiptID} {
		if !validWitnessToken(value) {
			return false
		}
	}
	return witnessDigest.MatchString(b.CiphertextFingerprint) && witnessDigest.MatchString(b.PlanDigest) && b.PriorEpoch >= 0 && b.NewEpoch == b.PriorEpoch+1 && b.StateRevision > 0
}

func validWitnessToken(value string) bool { return witnessToken.MatchString(value) }
