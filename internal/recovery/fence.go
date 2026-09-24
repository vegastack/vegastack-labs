package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const fenceSetDomain = "vegastack-labs.dev/restore-fence-set/v1\x00"

// AppliedFenceScope is read from current server-owned state. It is deliberately
// separate from the signed witness: local applied state decides applicability,
// while the independently installed #135 source proves direct denial.
type AppliedFenceScope struct {
	ProfileID, ProfileVersion, PolicyID, PolicyVersion string
	ReleaseBuildID, EvaluatorVersion                   string
	FormerInstanceID, ReplacementInstanceID            string
	RecoveryEpoch                                      int64
	Boundaries                                         []AppliedFenceBoundary
}

type AppliedFenceBoundary struct {
	Boundary, SubjectID, TargetID, AdapterID, FormerIdentityID string
}

type FenceScopeReader interface {
	CurrentFenceScope(context.Context, VerifiedSource, string) (AppliedFenceScope, error)
}

type FenceRequirement struct {
	Boundary, SubjectID, FormerInstanceID, ReplacementInstanceID string
	TargetID, AdapterID, FormerIdentityID                        string
	ProfileID, ProfileVersion, PolicyID, PolicyVersion           string
	ReleaseBuildID, EvaluatorVersion                             string
	RecoveryEpoch                                                int64
	RequiredEvidenceKinds                                        []string
}

type IndependentFenceProof struct {
	ProofID, EvidenceKind, Boundary, SubjectID, TargetID string
	AdapterID, FormerIdentityID                          string
	CollectorInstanceID, ObserverID, TrustRootDigest     string
	FormerInstanceID, ReplacementInstanceID              string
	ProfileID, ProfileVersion, PolicyID, PolicyVersion   string
	ReleaseBuildID, EvaluatorVersion                     string
	RecoveryEpoch                                        int64
	ResponseDigest, SourceDigest, ManifestDigest         string
	ObservedAt, ExpiresAt                                time.Time
	ProofClass                                           string
	DirectDenial                                         bool
}

type FenceEvidenceReader interface {
	Current(context.Context, FenceRequirement) ([]IndependentFenceProof, error)
}

type FenceResult struct {
	Items          []generated.RestoreFenceItem
	FenceSetDigest string
	VerifiedAt     time.Time
}

type FenceEvaluator struct {
	Scopes   FenceScopeReader
	Evidence FenceEvidenceReader
	Clock    func() time.Time
}

func (evaluator FenceEvaluator) Requirements(ctx context.Context, source VerifiedSource, formerInstanceID string) ([]FenceRequirement, error) {
	if ctx == nil || ctx.Err() != nil || evaluator.Scopes == nil || formerInstanceID == "" || source.Binding.PointID == "" {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-scope", false)
	}
	scope, err := evaluator.Scopes.CurrentFenceScope(ctx, source, formerInstanceID)
	if err != nil {
		return nil, err
	}
	if !validFenceScope(scope, source, formerInstanceID) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-scope", false)
	}
	requirements := make([]FenceRequirement, 0, len(scope.Boundaries))
	seen := make(map[string]bool, len(scope.Boundaries))
	for _, boundary := range scope.Boundaries {
		probes := allowedProbes[boundary.Boundary]
		if len(probes) == 0 {
			return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-scope", false)
		}
		kinds := make([]string, 0, len(probes))
		for probe := range probes {
			kinds = append(kinds, probe)
		}
		sort.Strings(kinds)
		requirement := FenceRequirement{
			Boundary: boundary.Boundary, SubjectID: boundary.SubjectID, FormerInstanceID: scope.FormerInstanceID,
			ReplacementInstanceID: scope.ReplacementInstanceID, TargetID: boundary.TargetID, AdapterID: boundary.AdapterID,
			FormerIdentityID: boundary.FormerIdentityID, ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion,
			PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, ReleaseBuildID: scope.ReleaseBuildID,
			EvaluatorVersion: scope.EvaluatorVersion, RecoveryEpoch: scope.RecoveryEpoch, RequiredEvidenceKinds: kinds,
		}
		key := fenceRequirementKey(requirement)
		if seen[key] {
			return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-scope", false)
		}
		seen[key] = true
		requirements = append(requirements, requirement)
	}
	sort.Slice(requirements, func(i, j int) bool {
		return fenceRequirementKey(requirements[i]) < fenceRequirementKey(requirements[j])
	})
	return requirements, nil
}

func (evaluator FenceEvaluator) Verify(ctx context.Context, requirements []FenceRequirement) (FenceResult, error) {
	blocked := func() (FenceResult, error) {
		return FenceResult{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-evidence", false)
	}
	if ctx == nil || ctx.Err() != nil || evaluator.Evidence == nil || evaluator.Clock == nil || len(requirements) == 0 || len(requirements) > 256 {
		return blocked()
	}
	now := evaluator.Clock().UTC()
	if now.IsZero() {
		return blocked()
	}
	ordered := append([]FenceRequirement(nil), requirements...)
	sort.Slice(ordered, func(i, j int) bool { return fenceRequirementKey(ordered[i]) < fenceRequirementKey(ordered[j]) })
	items := make([]generated.RestoreFenceItem, 0, len(ordered))
	seenRequirements := make(map[string]bool, len(ordered))
	for _, requirement := range ordered {
		key := fenceRequirementKey(requirement)
		if seenRequirements[key] || !validFenceRequirement(requirement) {
			return blocked()
		}
		seenRequirements[key] = true
		proofs, err := evaluator.Evidence.Current(ctx, requirement)
		if err != nil {
			return FenceResult{}, err
		}
		item, denied, err := verifyFenceProofs(requirement, proofs, now)
		if denied {
			return FenceResult{}, failure.New(generated.ErrorCodeAuthorizationDenied, "restore-fence-evidence", false)
		}
		if err != nil {
			return blocked()
		}
		items = append(items, item)
	}
	digest, err := canonicalFenceSetDigest(ordered)
	if err != nil {
		return blocked()
	}
	return FenceResult{Items: items, FenceSetDigest: digest, VerifiedAt: now}, nil
}

// RequiredFenceSet binds the exact server-derived fence requirements into an
// immutable plan without accepting a caller assertion that live denial has
// already been observed. Live evidence replaces these required items only at
// Run, while retaining the same requirement-set digest.
func RequiredFenceSet(requirements []FenceRequirement, sourceAdmissionDigest, fenceQualificationDigest string) (FenceResult, error) {
	if len(requirements) == 0 || !restoreDigest.MatchString(sourceAdmissionDigest) || !restoreDigest.MatchString(fenceQualificationDigest) {
		return FenceResult{}, ErrWitnessUnavailable
	}
	ordered := append([]FenceRequirement(nil), requirements...)
	sort.Slice(ordered, func(i, j int) bool { return fenceRequirementKey(ordered[i]) < fenceRequirementKey(ordered[j]) })
	items := make([]generated.RestoreFenceItem, 0, len(ordered))
	seen := make(map[string]bool, len(ordered))
	for _, requirement := range ordered {
		key := fenceRequirementKey(requirement)
		if seen[key] || !validFenceRequirement(requirement) {
			return FenceResult{}, ErrWitnessUnavailable
		}
		seen[key] = true
		raw, err := json.Marshal(struct {
			Domain      string
			Requirement FenceRequirement
		}{"vegastack-labs.dev/restore-fence-requirement/v1", requirement})
		if err != nil {
			return FenceResult{}, err
		}
		sum := sha256.Sum256(raw)
		item := generated.RestoreFenceItem{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: requirement.Boundary, SubjectID: requirement.SubjectID, TargetID: requirement.TargetID, AdapterID: requirement.AdapterID, FormerIdentityID: requirement.FormerIdentityID, ProfileID: requirement.ProfileID, ProfileVersion: requirement.ProfileVersion, PolicyID: requirement.PolicyID, PolicyVersion: requirement.PolicyVersion, ReleaseBuildID: requirement.ReleaseBuildID, EvaluatorVersion: requirement.EvaluatorVersion, RecoveryEpoch: requirement.RecoveryEpoch, RequiredEvidenceKinds: append([]string(nil), requirement.RequiredEvidenceKinds...), Required: true, EvidenceIDs: []string{sourceAdmissionDigest, fenceQualificationDigest}, EvidenceDigest: "sha256:" + hex.EncodeToString(sum[:]), Status: "required"}
		encoded, err := json.Marshal(item)
		if err != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreFenceItem, encoded, generated.ContractExact) != nil {
			return FenceResult{}, ErrWitnessUnavailable
		}
		items = append(items, item)
	}
	digest, err := canonicalFenceSetDigest(ordered)
	return FenceResult{Items: items, FenceSetDigest: digest}, err
}

func validFenceScope(scope AppliedFenceScope, source VerifiedSource, former string) bool {
	for _, token := range []string{scope.ProfileID, scope.ProfileVersion, scope.PolicyID, scope.PolicyVersion, scope.ReleaseBuildID, scope.EvaluatorVersion, scope.FormerInstanceID, scope.ReplacementInstanceID} {
		if !validWitnessToken(token) {
			return false
		}
	}
	return len(scope.Boundaries) > 0 && len(scope.Boundaries) <= 64 && scope.FormerInstanceID == former && scope.FormerInstanceID != scope.ReplacementInstanceID && scope.RecoveryEpoch == source.Binding.RecoveryEpoch
}

func validFenceRequirement(requirement FenceRequirement) bool {
	for _, token := range []string{requirement.Boundary, requirement.SubjectID, requirement.FormerInstanceID, requirement.ReplacementInstanceID, requirement.TargetID, requirement.AdapterID, requirement.FormerIdentityID, requirement.ProfileID, requirement.ProfileVersion, requirement.PolicyID, requirement.PolicyVersion, requirement.ReleaseBuildID, requirement.EvaluatorVersion} {
		if !validWitnessToken(token) {
			return false
		}
	}
	probes := allowedProbes[requirement.Boundary]
	if requirement.FormerInstanceID == requirement.ReplacementInstanceID || requirement.RecoveryEpoch < 0 || len(probes) == 0 || len(requirement.RequiredEvidenceKinds) != len(probes) || !sort.StringsAreSorted(requirement.RequiredEvidenceKinds) {
		return false
	}
	seen := make(map[string]bool, len(requirement.RequiredEvidenceKinds))
	for _, kind := range requirement.RequiredEvidenceKinds {
		if seen[kind] || !allowedProbes[requirement.Boundary][kind] {
			return false
		}
		seen[kind] = true
	}
	return true
}

func fenceRequirementKey(requirement FenceRequirement) string {
	return requirement.Boundary + "\x00" + requirement.SubjectID + "\x00" + requirement.TargetID + "\x00" + requirement.AdapterID + "\x00" + requirement.FormerIdentityID
}

func verifyFenceProofs(requirement FenceRequirement, proofs []IndependentFenceProof, now time.Time) (generated.RestoreFenceItem, bool, error) {
	item := generated.RestoreFenceItem{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: requirement.Boundary, SubjectID: requirement.SubjectID, TargetID: requirement.TargetID, AdapterID: requirement.AdapterID, FormerIdentityID: requirement.FormerIdentityID, ProfileID: requirement.ProfileID, ProfileVersion: requirement.ProfileVersion, PolicyID: requirement.PolicyID, PolicyVersion: requirement.PolicyVersion, ReleaseBuildID: requirement.ReleaseBuildID, EvaluatorVersion: requirement.EvaluatorVersion, RecoveryEpoch: requirement.RecoveryEpoch, RequiredEvidenceKinds: append([]string(nil), requirement.RequiredEvidenceKinds...), Required: true, Status: "verified"}
	if len(proofs) != len(requirement.RequiredEvidenceKinds) {
		return item, false, ErrWitnessUnavailable
	}
	byKind := make(map[string]IndependentFenceProof, len(proofs))
	oldest := now
	for _, proof := range proofs {
		if proof.CollectorInstanceID == requirement.FormerInstanceID || proof.CollectorInstanceID == requirement.ReplacementInstanceID || proof.ObserverID == requirement.FormerInstanceID || proof.ObserverID == requirement.ReplacementInstanceID || proof.ObserverID == requirement.FormerIdentityID {
			return item, true, ErrWitnessUnavailable
		}
		if byKind[proof.EvidenceKind].ProofID != "" || proof.Boundary != requirement.Boundary || proof.SubjectID != requirement.SubjectID || proof.TargetID != requirement.TargetID || proof.AdapterID != requirement.AdapterID || proof.FormerIdentityID != requirement.FormerIdentityID || proof.FormerInstanceID != requirement.FormerInstanceID || proof.ReplacementInstanceID != requirement.ReplacementInstanceID || proof.ProfileID != requirement.ProfileID || proof.ProfileVersion != requirement.ProfileVersion || proof.PolicyID != requirement.PolicyID || proof.PolicyVersion != requirement.PolicyVersion || proof.ReleaseBuildID != requirement.ReleaseBuildID || proof.EvaluatorVersion != requirement.EvaluatorVersion || proof.RecoveryEpoch != requirement.RecoveryEpoch || proof.ProofClass != "live" || !proof.DirectDenial || !allowedProbes[requirement.Boundary][proof.EvidenceKind] || !restoreDigest.MatchString(proof.ResponseDigest) || !restoreDigest.MatchString(proof.SourceDigest) || !restoreDigest.MatchString(proof.ManifestDigest) || !restoreDigest.MatchString(proof.TrustRootDigest) || !validWitnessToken(proof.ProofID) || !validWitnessToken(proof.CollectorInstanceID) || !validWitnessToken(proof.ObserverID) || proof.ObservedAt.IsZero() || proof.ObservedAt.After(now) || now.Sub(proof.ObservedAt) > maxWitnessAge || !now.Before(proof.ExpiresAt) {
			return item, false, ErrWitnessUnavailable
		}
		byKind[proof.EvidenceKind] = proof
		if proof.ObservedAt.Before(oldest) {
			oldest = proof.ObservedAt
		}
	}
	canonical := make([]IndependentFenceProof, 0, len(requirement.RequiredEvidenceKinds))
	for _, kind := range requirement.RequiredEvidenceKinds {
		proof, found := byKind[kind]
		if !found {
			return item, false, ErrWitnessUnavailable
		}
		canonical = append(canonical, proof)
		item.EvidenceIDs = append(item.EvidenceIDs, proof.ProofID)
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return item, false, err
	}
	sum := sha256.Sum256(append([]byte("vegastack-labs.dev/restore-fence-item/v1\x00"), raw...))
	item.EvidenceDigest = "sha256:" + hex.EncodeToString(sum[:])
	observedAt := oldest.UTC().Format(time.RFC3339)
	item.ObservedAt = &observedAt
	encoded, err := json.Marshal(item)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreFenceItem, encoded, generated.ContractExact) != nil {
		return item, false, ErrWitnessUnavailable
	}
	return item, false, nil
}

func canonicalFenceSetDigest(requirements []FenceRequirement) (string, error) {
	payload := struct {
		Domain       string
		Requirements []FenceRequirement
	}{fenceSetDomain, requirements}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
