package credentialref

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
)

// StepBinding is public, material-free metadata sealed into one exact plan.
type StepBinding struct {
	OperationID, AdapterID, TargetID, ReferenceID, ConsumerID, PurposeID string
	MaterialVersion, ResolverID                                          string
	StateRevision, RecoveryEpoch                                         int64
}

func ValidBinding(binding StepBinding) bool {
	if binding.StateRevision <= 0 || binding.RecoveryEpoch < 0 {
		return false
	}
	for _, id := range []string{binding.OperationID, binding.AdapterID, binding.TargetID, binding.ReferenceID, binding.ConsumerID, binding.PurposeID, binding.MaterialVersion, binding.ResolverID} {
		if _, err := ParseID(id); err != nil {
			return false
		}
	}
	return true
}

func (binding StepBinding) Digest() string {
	if !ValidBinding(binding) {
		return ""
	}
	parts := []string{"credential-step-binding-v1", binding.OperationID, binding.AdapterID, binding.TargetID, binding.ReferenceID, binding.ConsumerID, binding.PurposeID, binding.MaterialVersion, binding.ResolverID, strconv.FormatInt(binding.StateRevision, 10), strconv.FormatInt(binding.RecoveryEpoch, 10)}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ManifestDigest(bindings []StepBinding) string {
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
	// Stable digest independent of insertion order; duplicate bindings retain
	// duplicate digest entries and are rejected by the repository separately.
	slices.Sort(digests)
	sum := sha256.Sum256([]byte("credential-manifest-v1\x00" + strings.Join(digests, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// OperationManifestDigest binds one operation's input to precisely its
// credential references, without accepting a manifest for another operation.
func OperationManifestDigest(bindings []StepBinding, operationID string) string {
	var selected []StepBinding
	for _, binding := range bindings {
		if binding.OperationID == operationID {
			selected = append(selected, binding)
		}
	}
	return ManifestDigest(selected)
}
