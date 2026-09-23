package recovery

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const sourceAdmissionDomain = "vegastack-labs.dev/recovery-source-admission/v1\x00"

var (
	versionToken       = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	schemaVersionToken = regexp.MustCompile(`^[1-9][0-9]*$`)
)

// SourceAdmission is the independently installed, pre-plan identity of one
// recovery source. It deliberately excludes plan/run/step/lease identifiers;
// the later WitnessBinding adds those exact execution identifiers while also
// carrying this digest.
type SourceAdmission struct {
	FormerHostID             string                               `json:"formerHostId"`
	FormerInstanceID         string                               `json:"formerInstanceId"`
	ReplacementHostID        string                               `json:"replacementHostId"`
	ReplacementInstanceID    string                               `json:"replacementInstanceId"`
	DraftID                  string                               `json:"draftId"`
	CiphertextFingerprint    string                               `json:"ciphertextFingerprint"`
	PriorEpoch               int64                                `json:"priorEpoch"`
	NewEpoch                 int64                                `json:"newEpoch"`
	WitnessKeyID             string                               `json:"witnessKeyId"`
	WitnessInstanceID        string                               `json:"witnessInstanceId"`
	RecipientKeyID           string                               `json:"recipientKeyId"`
	WitnessPublicKey         []byte                               `json:"witnessPublicKey"`
	RecipientPublicKey       []byte                               `json:"recipientPublicKey"`
	AdminRootDigest          string                               `json:"adminRootDigest"`
	FenceQualificationDigest string                               `json:"fenceQualificationDigest"`
	TargetReleaseBuildID     string                               `json:"targetReleaseBuildId"`
	TargetToolVersion        string                               `json:"targetToolVersion"`
	TargetSchemaVersion      string                               `json:"targetSchemaVersion"`
	RequiredDependencies     []generated.RestoreDependencyBinding `json:"requiredDependencies"`
	Requirements             []BoundaryRequirement                `json:"requirements"`
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
	TargetReleaseBuildID, TargetToolVersion, TargetSchemaVersion             string
	RequiredDependencies                                                     []generated.RestoreDependencyBinding
	PriorEpoch, NewEpoch                                                     int64
}

func canonicalSourceAdmission(admission SourceAdmission) ([]byte, error) {
	for _, value := range []string{admission.FormerHostID, admission.FormerInstanceID, admission.ReplacementHostID, admission.ReplacementInstanceID, admission.DraftID, admission.WitnessKeyID, admission.WitnessInstanceID, admission.RecipientKeyID} {
		if !validWitnessToken(value) {
			return nil, ErrWitnessUnavailable
		}
	}
	if !witnessDigest.MatchString(admission.CiphertextFingerprint) || !witnessDigest.MatchString(admission.AdminRootDigest) || !witnessDigest.MatchString(admission.FenceQualificationDigest) || !validOptionalRestoreCompatibility(admission.TargetReleaseBuildID, admission.TargetToolVersion, admission.TargetSchemaVersion, admission.RequiredDependencies) || admission.PriorEpoch < 0 || admission.NewEpoch != admission.PriorEpoch+1 || len(admission.WitnessPublicKey) != 32 || !validX25519PublicKey(admission.RecipientPublicKey) || !validCompleteRequirements(admission.Requirements) {
		return nil, ErrWitnessUnavailable
	}
	admission.WitnessPublicKey = append([]byte(nil), admission.WitnessPublicKey...)
	admission.RecipientPublicKey = append([]byte(nil), admission.RecipientPublicKey...)
	admission.Requirements = append([]BoundaryRequirement(nil), admission.Requirements...)
	admission.RequiredDependencies = append([]generated.RestoreDependencyBinding(nil), admission.RequiredDependencies...)
	sort.Slice(admission.RequiredDependencies, func(i, j int) bool {
		if admission.RequiredDependencies[i].Kind != admission.RequiredDependencies[j].Kind {
			return admission.RequiredDependencies[i].Kind < admission.RequiredDependencies[j].Kind
		}
		if admission.RequiredDependencies[i].DependencyID != admission.RequiredDependencies[j].DependencyID {
			return admission.RequiredDependencies[i].DependencyID < admission.RequiredDependencies[j].DependencyID
		}
		return admission.RequiredDependencies[i].Digest < admission.RequiredDependencies[j].Digest
	})
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
	_, err = canonicalSourceAdmission(signed.Payload)
	if err != nil || signed.ValidFrom.IsZero() || signed.ExpiresAt.IsZero() || !signed.ValidFrom.Before(signed.ExpiresAt) || signed.ExpiresAt.Sub(signed.ValidFrom) > 24*time.Hour {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	timed, err := json.Marshal(struct {
		Payload   SourceAdmission `json:"payload"`
		ValidFrom time.Time       `json:"validFrom"`
		ExpiresAt time.Time       `json:"expiresAt"`
	}{signed.Payload, signed.ValidFrom.UTC(), signed.ExpiresAt.UTC()})
	if err != nil || !ed25519.Verify(adminPublic, append([]byte(sourceAdmissionDomain+"signed\x00"), timed...), signed.Signature) {
		return SourceAdmission{}, ErrWitnessUnavailable
	}
	admission := signed.Payload
	if admission.FormerHostID != expected.FormerHostID || admission.FormerInstanceID != expected.FormerInstanceID ||
		admission.ReplacementHostID != expected.ReplacementHostID || admission.ReplacementInstanceID != expected.ReplacementInstanceID ||
		admission.DraftID != expected.DraftID || admission.CiphertextFingerprint != expected.CiphertextFingerprint ||
		admission.FenceQualificationDigest != expected.FenceQualificationDigest || admission.PriorEpoch != expected.PriorEpoch ||
		admission.TargetReleaseBuildID != expected.TargetReleaseBuildID || admission.TargetToolVersion != expected.TargetToolVersion || admission.TargetSchemaVersion != expected.TargetSchemaVersion || !sameRestoreDependencies(admission.RequiredDependencies, expected.RequiredDependencies) ||
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
		witnessDigest.MatchString(expected.FenceQualificationDigest) && validOptionalRestoreCompatibility(expected.TargetReleaseBuildID, expected.TargetToolVersion, expected.TargetSchemaVersion, expected.RequiredDependencies) && expected.PriorEpoch >= 0 && expected.NewEpoch == expected.PriorEpoch+1
}

func validOptionalRestoreCompatibility(releaseBuildID, toolVersion, schemaVersion string, dependencies []generated.RestoreDependencyBinding) bool {
	if releaseBuildID == "" && toolVersion == "" && schemaVersion == "" && len(dependencies) == 0 {
		return true
	}
	return validWitnessToken(releaseBuildID) && versionToken.MatchString(toolVersion) && schemaVersionToken.MatchString(schemaVersion) && validRestoreDependencies(dependencies)
}

func validRestoreDependencies(dependencies []generated.RestoreDependencyBinding) bool {
	if len(dependencies) == 0 || len(dependencies) > 64 {
		return false
	}
	seen := make(map[string]bool, len(dependencies))
	for _, dependency := range dependencies {
		key := dependency.DependencyID
		if !validWitnessToken(dependency.DependencyID) || !map[string]bool{"binary": true, "schema": true, "config": true, "image": true, "signature": true}[dependency.Kind] || !witnessDigest.MatchString(dependency.Digest) || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

func sameRestoreDependencies(left, right []generated.RestoreDependencyBinding) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]generated.RestoreDependencyBinding(nil), left...)
	right = append([]generated.RestoreDependencyBinding(nil), right...)
	sortDependencies := func(values []generated.RestoreDependencyBinding) {
		sort.Slice(values, func(i, j int) bool {
			if values[i].Kind != values[j].Kind {
				return values[i].Kind < values[j].Kind
			}
			if values[i].DependencyID != values[j].DependencyID {
				return values[i].DependencyID < values[j].DependencyID
			}
			return values[i].Digest < values[j].Digest
		})
	}
	sortDependencies(left)
	sortDependencies(right)
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return bytes.Equal(a, b)
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
