package recovery

import (
	"sort"

	"github.com/vegastack/vegastack-labs/internal/store"
)

// AdmissionFenceRequirements derives the plan-time requirement set from the
// independently signed source admission and current applied profile. It does
// not claim that any direct-denial probe has run; that proof is checked again
// from the exact plan/run-bound witness package during execution.
func AdmissionFenceRequirements(admission SourceAdmission, profile store.GateAppliedProfile, source VerifiedSource, releaseBuildID, evaluatorVersion string) ([]FenceRequirement, error) {
	if SourceAdmissionDigest(admission) == "" || profile.ProfileID == "" || profile.ProfileVersion == "" || profile.PolicyID == "" || profile.PolicyVersion == "" ||
		profile.RecoveryEpoch != admission.PriorEpoch || source.Binding.RecoveryEpoch != admission.PriorEpoch || releaseBuildID == "" || evaluatorVersion == "" {
		return nil, ErrWitnessUnavailable
	}
	type groupKey struct {
		kind, subject, target, adapter, former string
	}
	groups := make(map[groupKey]map[string]bool)
	for _, item := range admission.Requirements {
		key := groupKey{item.Kind, item.SubjectID, item.TargetID, item.AdapterID, item.FormerIdentityID}
		if groups[key] == nil {
			groups[key] = make(map[string]bool)
		}
		if groups[key][item.ProbeID] {
			return nil, ErrWitnessUnavailable
		}
		groups[key][item.ProbeID] = true
	}
	result := make([]FenceRequirement, 0, len(groups))
	for key, probes := range groups {
		kinds := make([]string, 0, len(probes))
		for probe := range probes {
			kinds = append(kinds, probe)
		}
		sort.Strings(kinds)
		requirement := FenceRequirement{
			Boundary: key.kind, SubjectID: key.subject, TargetID: key.target, AdapterID: key.adapter, FormerIdentityID: key.former,
			FormerInstanceID: admission.FormerInstanceID, ReplacementInstanceID: admission.ReplacementInstanceID,
			ProfileID: profile.ProfileID, ProfileVersion: profile.ProfileVersion, PolicyID: profile.PolicyID, PolicyVersion: profile.PolicyVersion,
			ReleaseBuildID: releaseBuildID, EvaluatorVersion: evaluatorVersion, RecoveryEpoch: admission.PriorEpoch, RequiredEvidenceKinds: kinds,
		}
		if !validFenceRequirement(requirement) {
			return nil, ErrWitnessUnavailable
		}
		result = append(result, requirement)
	}
	sort.Slice(result, func(i, j int) bool { return fenceRequirementKey(result[i]) < fenceRequirementKey(result[j]) })
	if len(result) == 0 {
		return nil, ErrWitnessUnavailable
	}
	return result, nil
}
