package recovery

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"
)

const sourceAdmissionDomain = "vegastack-labs.dev/recovery-source-admission/v1\x00"

// SourceAdmission is the independently installed, pre-plan identity of one
// recovery source. It deliberately excludes plan/run/step/lease identifiers;
// the later WitnessBinding adds those exact execution identifiers while also
// carrying this digest.
type SourceAdmission struct {
	FormerHostID             string                `json:"formerHostId"`
	FormerInstanceID         string                `json:"formerInstanceId"`
	ReplacementHostID        string                `json:"replacementHostId"`
	ReplacementInstanceID    string                `json:"replacementInstanceId"`
	DraftID                  string                `json:"draftId"`
	CiphertextFingerprint    string                `json:"ciphertextFingerprint"`
	PriorEpoch               int64                 `json:"priorEpoch"`
	NewEpoch                 int64                 `json:"newEpoch"`
	WitnessKeyID             string                `json:"witnessKeyId"`
	WitnessInstanceID        string                `json:"witnessInstanceId"`
	RecipientKeyID           string                `json:"recipientKeyId"`
	WitnessPublicKey         []byte                `json:"witnessPublicKey"`
	RecipientPublicKey       []byte                `json:"recipientPublicKey"`
	AdminRootDigest          string                `json:"adminRootDigest"`
	FenceQualificationDigest string                `json:"fenceQualificationDigest"`
	Requirements             []BoundaryRequirement `json:"requirements"`
}

type SignedSourceAdmission struct {
	Payload   SourceAdmission `json:"payload"`
	ValidFrom time.Time       `json:"validFrom"`
	ExpiresAt time.Time       `json:"expiresAt"`
	Signature []byte          `json:"signature"`
}

type SourceAdmissionExpectation struct {
	FormerHostID, FormerInstanceID, ReplacementHostID, ReplacementInstanceID string
	DraftID, CiphertextFingerprint, SourceAdmissionDigest                    string
	FenceQualificationDigest                                                 string
	PriorEpoch, NewEpoch                                                     int64
}

func canonicalSourceAdmission(admission SourceAdmission) ([]byte, error) {
	for _, value := range []string{admission.FormerHostID, admission.FormerInstanceID, admission.ReplacementHostID, admission.ReplacementInstanceID, admission.DraftID, admission.WitnessKeyID, admission.WitnessInstanceID, admission.RecipientKeyID} {
		if !validWitnessToken(value) {
			return nil, ErrWitnessUnavailable
		}
	}
	if !witnessDigest.MatchString(admission.CiphertextFingerprint) || !witnessDigest.MatchString(admission.AdminRootDigest) || !witnessDigest.MatchString(admission.FenceQualificationDigest) || admission.PriorEpoch < 0 || admission.NewEpoch != admission.PriorEpoch+1 || len(admission.WitnessPublicKey) != 32 || !validX25519PublicKey(admission.RecipientPublicKey) || !validCompleteRequirements(admission.Requirements) {
		return nil, ErrWitnessUnavailable
	}
	admission.WitnessPublicKey = append([]byte(nil), admission.WitnessPublicKey...)
	admission.RecipientPublicKey = append([]byte(nil), admission.RecipientPublicKey...)
	admission.Requirements = append([]BoundaryRequirement(nil), admission.Requirements...)
	sort.Slice(admission.Requirements, func(i, j int) bool {
		left, right := admission.Requirements[i], admission.Requirements[j]
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		if left.SubjectID != right.SubjectID {
			return left.SubjectID < right.SubjectID
		}
		if left.TargetID != right.TargetID {
			return left.TargetID < right.TargetID
		}
		if left.AdapterID != right.AdapterID {
			return left.AdapterID < right.AdapterID
		}
		if left.FormerIdentityID != right.FormerIdentityID {
			return left.FormerIdentityID < right.FormerIdentityID
		}
		return left.ProbeID < right.ProbeID
	})
	body, err := json.Marshal(admission)
	if err != nil {
		return nil, ErrWitnessUnavailable
	}
	return append([]byte(sourceAdmissionDomain), body...), nil
}

func SourceAdmissionDigest(admission SourceAdmission) string {
	canonical, err := canonicalSourceAdmission(admission)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ParseSignedSourceAdmission(raw []byte, adminPublic ed25519.PublicKey, expected SourceAdmissionExpectation, now time.Time) (SourceAdmission, error) {
	if len(raw) == 0 || len(raw) > 65536 || len(adminPublic) != ed25519.PublicKeySize || !validSourceAdmissionExpectation(expected) || now.IsZero() {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	var signed SignedSourceAdmission
	if json.Unmarshal(raw, &signed) != nil || len(signed.Signature) != ed25519.SignatureSize {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	encoded, err := json.Marshal(signed)
	if err != nil || !bytes.Equal(encoded, raw) {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	payload, err := canonicalSourceAdmission(signed.Payload)
	if err != nil || signed.ValidFrom.IsZero() || signed.ExpiresAt.IsZero() || !signed.ValidFrom.Before(signed.ExpiresAt) || signed.ExpiresAt.Sub(signed.ValidFrom) > 24*time.Hour {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	timed, err := json.Marshal(struct {
		Payload   json.RawMessage `json:"payload"`
		ValidFrom time.Time       `json:"validFrom"`
		ExpiresAt time.Time       `json:"expiresAt"`
	}{payload, signed.ValidFrom.UTC(), signed.ExpiresAt.UTC()})
	if err != nil || !ed25519.Verify(adminPublic, append([]byte(sourceAdmissionDomain+"signed\x00"), timed...), signed.Signature) {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	admission := signed.Payload
	if admission.FormerHostID != expected.FormerHostID || admission.FormerInstanceID != expected.FormerInstanceID ||
		admission.ReplacementHostID != expected.ReplacementHostID || admission.ReplacementInstanceID != expected.ReplacementInstanceID ||
		admission.DraftID != expected.DraftID || admission.CiphertextFingerprint != expected.CiphertextFingerprint ||
		admission.FenceQualificationDigest != expected.FenceQualificationDigest || admission.PriorEpoch != expected.PriorEpoch ||
		admission.NewEpoch != expected.NewEpoch || SourceAdmissionDigest(admission) != expected.SourceAdmissionDigest ||
		admission.AdminRootDigest != recoveryAdminRootDigest(adminPublic) || signed.ValidFrom.After(now.UTC()) || !now.UTC().Before(signed.ExpiresAt) {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	return admission, nil
}

func validSourceAdmissionExpectation(expected SourceAdmissionExpectation) bool {
	for _, value := range []string{expected.FormerHostID, expected.FormerInstanceID, expected.ReplacementHostID, expected.ReplacementInstanceID, expected.DraftID} {
		if !validWitnessToken(value) {
			return false
		}
	}
	return expected.FormerHostID != expected.ReplacementHostID && expected.FormerInstanceID != expected.ReplacementInstanceID &&
		witnessDigest.MatchString(expected.CiphertextFingerprint) && witnessDigest.MatchString(expected.SourceAdmissionDigest) &&
		witnessDigest.MatchString(expected.FenceQualificationDigest) && expected.PriorEpoch >= 0 && expected.NewEpoch == expected.PriorEpoch+1
}

func validX25519PublicKey(raw []byte) bool {
	public, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return false
	}
	seed := make([]byte, 32)
	seed[0] = 1
	private, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return false
	}
	_, err = private.ECDH(public)
	return err == nil
}
