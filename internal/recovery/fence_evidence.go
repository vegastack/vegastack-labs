package recovery

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// InstalledFenceEvidence verifies the final #135 package once, then exposes
// only the independently authenticated public denial transcripts. It does not
// implement a second evidence verifier or open the protected recovery material.
type InstalledFenceEvidence struct {
	proofs map[string][]IndependentFenceProof
}

func VerifyInstalledFenceEvidence(ctx context.Context, binding WitnessBinding, requirements []FenceRequirement, installed InstalledPackage, qualified QualifiedAdapters, now time.Time) (*InstalledFenceEvidence, error) {
	boundaryRequirements, err := expandFenceRequirements(requirements)
	if err != nil {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-source", false)
	}
	// The administrator manifest order is part of #135's admission digest. The
	// server-derived set must match it exactly, but must not rewrite that order.
	if !sameBoundaryRequirementSet(boundaryRequirements, installed.Pin.Requirements) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-source", false)
	}
	handoff, err := VerifyInstalledSource(ctx, binding, installed.Pin.Requirements, installed, qualified, now)
	if err != nil {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-source", false)
	}
	reader := &InstalledFenceEvidence{proofs: make(map[string][]IndependentFenceProof, len(requirements))}
	byBoundary := make(map[BoundaryRequirement]DirectDenialTranscript, len(installed.Witness.Payload.Transcripts))
	for _, transcript := range installed.Witness.Payload.Transcripts {
		byBoundary[transcript.Requirement] = transcript
	}
	for _, requirement := range requirements {
		key := fenceRequirementKey(requirement)
		for _, kind := range requirement.RequiredEvidenceKinds {
			boundary := BoundaryRequirement{Kind: requirement.Boundary, SubjectID: requirement.SubjectID, TargetID: requirement.TargetID, AdapterID: requirement.AdapterID, FormerIdentityID: requirement.FormerIdentityID, ProbeID: kind}
			transcript, found := byBoundary[boundary]
			if !found {
				return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-source", false)
			}
			reader.proofs[key] = append(reader.proofs[key], IndependentFenceProof{
				ProofID: binding.ChallengeID + ":" + kind, EvidenceKind: kind, Boundary: requirement.Boundary,
				SubjectID: requirement.SubjectID, TargetID: requirement.TargetID, AdapterID: requirement.AdapterID,
				FormerIdentityID: requirement.FormerIdentityID, CollectorInstanceID: installed.Pin.WitnessInstanceID,
				ObserverID: transcript.ObserverID, TrustRootDigest: installed.Pin.adminRootDigest,
				FormerInstanceID: requirement.FormerInstanceID, ReplacementInstanceID: requirement.ReplacementInstanceID,
				ProfileID: requirement.ProfileID, ProfileVersion: requirement.ProfileVersion, PolicyID: requirement.PolicyID,
				PolicyVersion: requirement.PolicyVersion, ReleaseBuildID: requirement.ReleaseBuildID,
				EvaluatorVersion: requirement.EvaluatorVersion, RecoveryEpoch: requirement.RecoveryEpoch,
				ResponseDigest: transcript.ResponseDigest, SourceDigest: handoff.SourceDigest, ManifestDigest: handoff.ManifestDigest,
				ObservedAt: transcript.ObservedAt.UTC(), ExpiresAt: transcript.ExpiresAt.UTC(), ProofClass: "live", DirectDenial: transcript.Denied,
			})
		}
	}
	return reader, nil
}

func sameBoundaryRequirementSet(left, right []BoundaryRequirement) bool {
	if len(left) != len(right) {
		return false
	}
	expected := make(map[BoundaryRequirement]bool, len(left))
	for _, item := range left {
		if expected[item] {
			return false
		}
		expected[item] = true
	}
	for _, item := range right {
		if !expected[item] {
			return false
		}
		delete(expected, item)
	}
	return len(expected) == 0
}

func (reader *InstalledFenceEvidence) Current(ctx context.Context, requirement FenceRequirement) ([]IndependentFenceProof, error) {
	if reader == nil || ctx == nil || ctx.Err() != nil || !validFenceRequirement(requirement) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-evidence", false)
	}
	proofs := reader.proofs[fenceRequirementKey(requirement)]
	if len(proofs) == 0 {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "restore-fence-evidence", false)
	}
	return append([]IndependentFenceProof(nil), proofs...), nil
}

func expandFenceRequirements(requirements []FenceRequirement) ([]BoundaryRequirement, error) {
	if len(requirements) == 0 || len(requirements) > 64 {
		return nil, ErrWitnessUnavailable
	}
	result := make([]BoundaryRequirement, 0, len(requirements)*3)
	for _, requirement := range requirements {
		if !validFenceRequirement(requirement) {
			return nil, ErrWitnessUnavailable
		}
		for _, kind := range requirement.RequiredEvidenceKinds {
			result = append(result, BoundaryRequirement{Kind: requirement.Boundary, SubjectID: requirement.SubjectID, TargetID: requirement.TargetID, AdapterID: requirement.AdapterID, FormerIdentityID: requirement.FormerIdentityID, ProbeID: kind})
		}
	}
	if !validCompleteRequirements(result) {
		return nil, ErrWitnessUnavailable
	}
	return result, nil
}
