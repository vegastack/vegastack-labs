package credentialref

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// LifecycleAction names one exact credential status effect. Each value is a
// provider-neutral core effect executed only through an exact human-authorized
// Phase 4 central plan; there is no direct setter or scheduled branch.
type LifecycleAction string

const (
	ActionStage    LifecycleAction = "credential.stage"
	ActionActivate LifecycleAction = "credential.activate"
	ActionRotate   LifecycleAction = "credential.rotate"
	ActionRevoke   LifecycleAction = "credential.revoke"
	ActionRecover  LifecycleAction = "credential.recover"
)

// MaxLifecycleConsumers bounds each declared consumer set; MaxLifecycleOverlapSeconds
// bounds rotation overlap. Both mirror the generated request contract.
const (
	MaxLifecycleConsumers      = 64
	MaxLifecycleOverlapSeconds = 3600
)

var fingerprintPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// LifecycleBinding is public, material-free metadata for one lifecycle effect.
// It is server-derived and sealed into exactly one immutable plan. It never
// carries a credential value; CiphertextFingerprint is a metadata identity, not
// key material.
type LifecycleBinding struct {
	OperationID                 string
	Action                      LifecycleAction
	DraftID                     *string
	ImportDraftStateRevision    *int64
	ImportDraftConsumerID       *string
	ImportDraftPurposeID        *string
	ReferenceID                 string
	ConsumerIDs                 []string
	RequiredDeniedConsumerIDs   []string
	NativeArtifactConsumerID    string
	NativeConsumers             []NativeConsumerBinding
	NativeDeniedReaders         []NativeDeniedReaderBinding
	MaterialVersion             string
	PriorMaterialVersion        *string
	ResolverID                  string
	TargetID                    string
	CiphertextFingerprint       string
	OverlapSeconds              int64
	StateRevision               int64
	RecoveryEpoch               int64
	PriorRecoveryEpoch          *int64
	CustodyProofDigest          *string
	FormerControllerFenceDigest *string
}

// ConsumerVerification records the result of one declared consumer's exact
// cold-start/restart observation. It carries only metadata digests, never
// material.
type ConsumerVerification struct {
	ConsumerID            string
	ProfileID             string
	RoleID                string
	MaterialVersion       string
	CiphertextFingerprint string
	EvidenceDigest        string
	RestartObserved       bool
	Result                string
	ReasonCode            string
}

// RecoveryVerification records the independent custody and former-controller
// fence evidence consumed by a clean-host recovery effect.
type RecoveryVerification struct {
	DraftID                     string
	CustodyProofDigest          string
	FormerControllerFenceDigest string
	PriorRecoveryEpoch          int64
	RecoveryEpoch               int64
	EvidenceDigest              string
}

func knownAction(action LifecycleAction) bool {
	switch action {
	case ActionStage, ActionActivate, ActionRotate, ActionRevoke, ActionRecover:
		return true
	default:
		return false
	}
}

func validIDList(values []string, minimum int) bool {
	if len(values) < minimum || len(values) > MaxLifecycleConsumers {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, err := ParseID(value); err != nil {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func disjoint(left, right []string) bool {
	present := make(map[string]struct{}, len(left))
	for _, value := range left {
		present[value] = struct{}{}
	}
	for _, value := range right {
		if _, exists := present[value]; exists {
			return false
		}
	}
	return true
}

func validDigestPointer(value *string) bool {
	return value != nil && fingerprintPattern.MatchString(*value)
}

// ValidLifecycleBinding enforces exact, action-specific structural safety.
// It rejects empty/duplicate/overlapping consumer sets, provider-shaped
// fingerprints, wrong action-nullable combinations, and non-increasing recovery
// epochs. It never inspects credential material and is not the authority for
// current-epoch or plan freshness, which the store and run seams enforce.
func ValidLifecycleBinding(binding LifecycleBinding) bool {
	if !knownAction(binding.Action) || binding.StateRevision <= 0 || binding.RecoveryEpoch < 0 {
		return false
	}
	for _, id := range []string{binding.OperationID, binding.ReferenceID, binding.ResolverID, binding.TargetID, binding.MaterialVersion} {
		if _, err := ParseID(id); err != nil {
			return false
		}
	}
	if !fingerprintPattern.MatchString(binding.CiphertextFingerprint) {
		return false
	}
	if binding.DraftID != nil {
		if _, err := ParseID(*binding.DraftID); err != nil {
			return false
		}
	}
	if binding.PriorMaterialVersion != nil {
		if _, err := ParseID(*binding.PriorMaterialVersion); err != nil {
			return false
		}
	}
	draftAction := binding.Action == ActionStage || binding.Action == ActionRotate || binding.Action == ActionRecover
	if draftAction {
		if binding.ImportDraftStateRevision == nil || *binding.ImportDraftStateRevision <= 0 || binding.ImportDraftConsumerID == nil || binding.ImportDraftPurposeID == nil {
			return false
		}
		if _, err := ParseID(*binding.ImportDraftConsumerID); err != nil {
			return false
		}
		if _, err := ParseID(*binding.ImportDraftPurposeID); err != nil {
			return false
		}
		if !slices.Contains(binding.ConsumerIDs, *binding.ImportDraftConsumerID) {
			return false
		}
	} else if binding.ImportDraftStateRevision != nil || binding.ImportDraftConsumerID != nil || binding.ImportDraftPurposeID != nil {
		return false
	}
	// Denied set is validated for every action; it must be disjoint from the
	// positive set so a consumer can never be both required-positive and
	// required-denied.
	if len(binding.RequiredDeniedConsumerIDs) > 0 && !validIDList(binding.RequiredDeniedConsumerIDs, 0) {
		return false
	}
	if !disjoint(binding.ConsumerIDs, binding.RequiredDeniedConsumerIDs) {
		return false
	}
	if !ValidNativeBindings(binding) {
		return false
	}

	switch binding.Action {
	case ActionStage:
		return binding.DraftID != nil &&
			len(binding.RequiredDeniedConsumerIDs) == 0 &&
			validIDList(binding.ConsumerIDs, 1) &&
			binding.PriorMaterialVersion == nil &&
			binding.OverlapSeconds == 0 &&
			noRecoveryFields(binding)
	case ActionActivate:
		return binding.DraftID == nil &&
			validIDList(binding.ConsumerIDs, 1) &&
			validIDList(binding.RequiredDeniedConsumerIDs, 1) &&
			binding.PriorMaterialVersion == nil &&
			binding.OverlapSeconds == 0 &&
			noRecoveryFields(binding)
	case ActionRotate:
		return binding.DraftID != nil &&
			validIDList(binding.ConsumerIDs, 1) &&
			validIDList(binding.RequiredDeniedConsumerIDs, 1) &&
			binding.PriorMaterialVersion != nil &&
			binding.OverlapSeconds >= 0 && binding.OverlapSeconds <= MaxLifecycleOverlapSeconds &&
			noRecoveryFields(binding)
	case ActionRevoke:
		// Revoke performs no secret read and no consumer verification, so it
		// carries no consumer sets. It names exactly the version to revoke.
		return binding.DraftID == nil &&
			len(binding.ConsumerIDs) == 0 &&
			len(binding.RequiredDeniedConsumerIDs) == 0 &&
			binding.PriorMaterialVersion == nil &&
			binding.OverlapSeconds == 0 &&
			noRecoveryFields(binding)
	case ActionRecover:
		return binding.DraftID != nil &&
			len(binding.RequiredDeniedConsumerIDs) == 0 &&
			validIDList(binding.ConsumerIDs, 1) &&
			binding.PriorMaterialVersion == nil &&
			binding.OverlapSeconds == 0 &&
			binding.PriorRecoveryEpoch != nil &&
			*binding.PriorRecoveryEpoch >= 0 &&
			binding.RecoveryEpoch > *binding.PriorRecoveryEpoch &&
			validDigestPointer(binding.CustodyProofDigest) &&
			validDigestPointer(binding.FormerControllerFenceDigest)
	default:
		return false
	}
}

// noRecoveryFields is true when the recovery-only fields are absent, as every
// non-recover action requires.
func noRecoveryFields(binding LifecycleBinding) bool {
	return binding.PriorRecoveryEpoch == nil && binding.CustodyProofDigest == nil && binding.FormerControllerFenceDigest == nil
}

func canonicalStringPointer(value *string) string {
	if value == nil {
		return "\x00"
	}
	return "\x01" + *value
}

func canonicalInt64Pointer(value *int64) string {
	if value == nil {
		return "\x00"
	}
	return "\x01" + strconv.FormatInt(*value, 10)
}

func canonicalIDSet(values []string) string {
	sorted := append([]string(nil), values...)
	slices.Sort(sorted)
	return strings.Join(sorted, ",")
}

// Digest binds every field of a valid binding to a stable, order-independent
// content digest. An invalid binding has no digest.
func (binding LifecycleBinding) Digest() string {
	if !ValidLifecycleBinding(binding) {
		return ""
	}
	parts := []string{
		"credential-lifecycle-binding-v3",
		binding.OperationID,
		string(binding.Action),
		canonicalStringPointer(binding.DraftID),
		canonicalInt64Pointer(binding.ImportDraftStateRevision),
		canonicalStringPointer(binding.ImportDraftConsumerID),
		canonicalStringPointer(binding.ImportDraftPurposeID),
		binding.ReferenceID,
		canonicalIDSet(binding.ConsumerIDs),
		canonicalIDSet(binding.RequiredDeniedConsumerIDs),
		binding.NativeArtifactConsumerID,
		canonicalNativeConsumers(binding.NativeConsumers),
		canonicalNativeDeniedReaders(binding.NativeDeniedReaders),
		binding.MaterialVersion,
		canonicalStringPointer(binding.PriorMaterialVersion),
		binding.ResolverID,
		binding.TargetID,
		binding.CiphertextFingerprint,
		strconv.FormatInt(binding.OverlapSeconds, 10),
		strconv.FormatInt(binding.StateRevision, 10),
		strconv.FormatInt(binding.RecoveryEpoch, 10),
		canonicalInt64Pointer(binding.PriorRecoveryEpoch),
		canonicalStringPointer(binding.CustodyProofDigest),
		canonicalStringPointer(binding.FormerControllerFenceDigest),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// LifecycleManifestDigestOf is the variadic form of LifecycleManifestDigest.
// It lets a caller seal one exact binding into a manifest digest without
// materialising a slice literal at the call site, and returns a value
// identical to LifecycleManifestDigest over the same bindings.
func LifecycleManifestDigestOf(bindings ...LifecycleBinding) string {
	return LifecycleManifestDigest(bindings)
}

// LifecycleManifestDigest binds a set of lifecycle bindings into one stable
// digest independent of insertion order. Any invalid member voids the digest.
func LifecycleManifestDigest(bindings []LifecycleBinding) string {
	if len(bindings) == 0 {
		return ""
	}
	digests := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		digest := binding.Digest()
		if digest == "" {
			return ""
		}
		digests = append(digests, digest)
	}
	slices.Sort(digests)
	sum := sha256.Sum256([]byte("credential-lifecycle-manifest-v1\x00" + strings.Join(digests, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
