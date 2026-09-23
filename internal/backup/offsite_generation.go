package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
)

var offsiteToken = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
var protectedGenerationParts = []string{"config", "keys", "data", "index", "snapshots"}

func ForecastGeneration(policy OffsitePolicy, point VerifiedCriticalPoint, observed adapter.RetentionObservation) (GenerationAdmission, error) {
	invalid := errors.New("offsite generation admission blocked")
	now := nowForOffsitePolicy(policy)
	if !validOffsitePolicy(policy) || observed.GenerationID != policy.GenerationID || observed.RuleLimit != policy.RuleLimit ||
		observed.RuleLimit > 1000 || observed.RuleCount < 0 || observed.RuleCount+len(protectedGenerationParts) > observed.RuleLimit ||
		observed.RetainedGenerations < 0 || observed.RetainedGenerations >= policy.MaximumRetainedGenerations ||
		observed.AvailableBytes < policy.MaximumBytes || observed.AvailablePUTs < policy.MaximumPUTs || observed.AvailableLISTs < policy.MaximumLISTs ||
		point.ObjectBytes > policy.MaximumBytes || observed.ObservedAt.IsZero() || observed.ObservedAt.After(now) ||
		now.Sub(observed.ObservedAt) > 5*time.Minute || !observed.IndefiniteProtection ||
		!validBackupManifestDigest(observed.RuleDigest) || observed.RuleDigest != DigestRetentionObservation(observed) {
		return GenerationAdmission{}, invalid
	}
	base := path.Join(policy.Prefix, policy.GenerationID)
	protected := make([]string, 0, len(protectedGenerationParts))
	for _, part := range protectedGenerationParts {
		protected = append(protected, path.Join(base, part)+map[bool]string{true: "/", false: ""}[part != "config"])
	}
	mutable := []string{path.Join(base, "locks") + "/"}
	gotProtected, gotMutable := append([]string(nil), observed.ProtectedPrefixes...), append([]string(nil), observed.MutablePrefixes...)
	slices.Sort(protected)
	slices.Sort(gotProtected)
	slices.Sort(mutable)
	slices.Sort(gotMutable)
	if !slices.Equal(protected, gotProtected) || !slices.Equal(mutable, gotMutable) {
		return GenerationAdmission{}, invalid
	}
	admission := GenerationAdmission{GenerationID: policy.GenerationID, Prefix: base + "/", RuleDigest: observed.RuleDigest,
		MaximumBytes: policy.MaximumBytes, MaximumPUTs: policy.MaximumPUTs, MaximumLISTs: policy.MaximumLISTs,
		ProtectedPrefixes: protected, MutablePrefixes: mutable}
	if !validGenerationAdmission(admission) {
		return GenerationAdmission{}, invalid
	}
	return admission, nil
}

func validGenerationAdmission(admission GenerationAdmission) bool {
	base := strings.TrimSuffix(admission.Prefix, "/")
	if !validOffsiteToken(admission.GenerationID) || admission.Prefix != base+"/" || !validOffsitePrefix(base) ||
		!strings.HasSuffix(base, "/"+admission.GenerationID) || !validBackupManifestDigest(admission.RuleDigest) ||
		admission.MaximumBytes <= 0 || admission.MaximumPUTs <= 0 || admission.MaximumLISTs <= 0 {
		return false
	}
	protected := make([]string, 0, len(protectedGenerationParts))
	for _, part := range protectedGenerationParts {
		protected = append(protected, path.Join(base, part)+map[bool]string{true: "/", false: ""}[part != "config"])
	}
	mutable := []string{path.Join(base, "locks") + "/"}
	gotProtected := append([]string(nil), admission.ProtectedPrefixes...)
	gotMutable := append([]string(nil), admission.MutablePrefixes...)
	slices.Sort(protected)
	slices.Sort(mutable)
	slices.Sort(gotProtected)
	slices.Sort(gotMutable)
	return slices.Equal(protected, gotProtected) && slices.Equal(mutable, gotMutable)
}

func validOffsiteToken(value string) bool { return offsiteToken.MatchString(value) }

func validOffsitePrefix(value string) bool {
	return value != "" && len(value) <= 512 && !strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") &&
		path.Clean(value) == value && value != "." && !strings.Contains(value, "../")
}

func DigestRetentionObservation(value adapter.RetentionObservation) string {
	protected := append([]string(nil), value.ProtectedPrefixes...)
	mutable := append([]string(nil), value.MutablePrefixes...)
	slices.Sort(protected)
	slices.Sort(mutable)
	hasher := sha256.New()
	hasher.Write([]byte("offsite-retention-observation-v1"))
	for _, item := range []string{value.GenerationID, strconv.Itoa(value.RuleCount), strconv.Itoa(value.RuleLimit), strconv.Itoa(value.RetainedGenerations),
		strconv.FormatInt(value.AvailableBytes, 10), strconv.FormatInt(value.AvailablePUTs, 10), strconv.FormatInt(value.AvailableLISTs, 10),
		strconv.FormatBool(value.IndefiniteProtection), value.ProofClass, value.ObservedAt.UTC().Format(time.RFC3339)} {
		hasher.Write([]byte{0})
		hasher.Write([]byte(item))
	}
	for _, item := range protected {
		hasher.Write([]byte("\x00protected"))
		hasher.Write([]byte{0})
		hasher.Write([]byte(item))
	}
	for _, item := range mutable {
		hasher.Write([]byte("\x00mutable"))
		hasher.Write([]byte{0})
		hasher.Write([]byte(item))
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil))
}

func nowForOffsitePolicy(policy OffsitePolicy) time.Time {
	if policy.Clock != nil {
		return policy.Clock().UTC()
	}
	return time.Now().UTC()
}
