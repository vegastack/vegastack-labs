package recovery

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
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

func SourceAdmissionDigest(admission SourceAdmission) string {
	for _, value := range []string{admission.FormerHostID, admission.FormerInstanceID, admission.ReplacementHostID, admission.ReplacementInstanceID, admission.DraftID, admission.WitnessKeyID, admission.WitnessInstanceID, admission.RecipientKeyID} {
		if !validWitnessToken(value) {
			return ""
		}
	}
	if !witnessDigest.MatchString(admission.CiphertextFingerprint) || !witnessDigest.MatchString(admission.AdminRootDigest) || !witnessDigest.MatchString(admission.FenceQualificationDigest) || admission.PriorEpoch < 0 || admission.NewEpoch != admission.PriorEpoch+1 || len(admission.WitnessPublicKey) != 32 || !validX25519PublicKey(admission.RecipientPublicKey) || !validCompleteRequirements(admission.Requirements) {
		return ""
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
		return ""
	}
	sum := sha256.Sum256(append([]byte(sourceAdmissionDomain), body...))
	return "sha256:" + hex.EncodeToString(sum[:])
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
