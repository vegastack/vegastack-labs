package recovery

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type fenceScopeFixture struct {
	scope AppliedFenceScope
	err   error
}

func (fixture fenceScopeFixture) CurrentFenceScope(context.Context, VerifiedSource, string) (AppliedFenceScope, error) {
	return fixture.scope, fixture.err
}

type fenceEvidenceFixture struct {
	proofs map[string][]IndependentFenceProof
}

func (fixture fenceEvidenceFixture) Current(_ context.Context, requirement FenceRequirement) ([]IndependentFenceProof, error) {
	return append([]IndependentFenceProof(nil), fixture.proofs[fenceRequirementKey(requirement)]...), nil
}

func assertFenceCode(t *testing.T, err error, want string) {
	t.Helper()
	stable, ok := failure.As(err)
	if !ok || stable.Code != want {
		t.Fatalf("error = %v, want %s", err, want)
	}
}

func hostFenceRequirement(binding WitnessBinding) FenceRequirement {
	return FenceRequirement{
		Boundary: "host-service", SubjectID: "subject-1", FormerInstanceID: binding.FormerInstanceID,
		ReplacementInstanceID: binding.ReplacementInstanceID, TargetID: "target-1", AdapterID: "adapter-1",
		FormerIdentityID: "old-identity", ProfileID: "vegastack-labs", ProfileVersion: "1.0.0",
		PolicyID: "policy-a", PolicyVersion: "1.0.0", ReleaseBuildID: "release-a", EvaluatorVersion: "1.0.0",
		RecoveryEpoch: binding.PriorEpoch, RequiredEvidenceKinds: []string{"alternate-process-denied", "service-denied"},
	}
}

func TestFenceRequirementsComeFromCurrentServerScope(t *testing.T) {
	binding := WitnessBinding{FormerInstanceID: "old-instance", ReplacementInstanceID: "new-instance", PriorEpoch: 3}
	scope := AppliedFenceScope{
		ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0",
		ReleaseBuildID: "release-a", EvaluatorVersion: "1.0.0", FormerInstanceID: binding.FormerInstanceID,
		ReplacementInstanceID: binding.ReplacementInstanceID, RecoveryEpoch: binding.PriorEpoch,
		Boundaries: []AppliedFenceBoundary{
			{Boundary: "backup-writer", SubjectID: "backup-a", TargetID: "repository-a", AdapterID: "backup-fence", FormerIdentityID: "writer-old"},
			{Boundary: "host-service", SubjectID: "subject-1", TargetID: "target-1", AdapterID: "adapter-1", FormerIdentityID: "old-identity"},
		},
	}
	evaluator := FenceEvaluator{Scopes: fenceScopeFixture{scope: scope}}
	source := VerifiedSource{Binding: generated.RestoreSourceBinding{PointID: "point-a", RecoveryEpoch: binding.PriorEpoch}}
	requirements, err := evaluator.Requirements(context.Background(), source, binding.FormerInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(requirements) != 2 || requirements[0].Boundary != "backup-writer" || len(requirements[0].RequiredEvidenceKinds) != 3 || requirements[1].Boundary != "host-service" || len(requirements[1].RequiredEvidenceKinds) != 2 {
		t.Fatalf("requirements = %#v", requirements)
	}
	scope.RecoveryEpoch++
	evaluator.Scopes = fenceScopeFixture{scope: scope}
	_, err = evaluator.Requirements(context.Background(), source, binding.FormerInstanceID)
	assertFenceCode(t, err, generated.ErrorCodePrerequisiteBlocked)
}

func TestFenceRequiresEveryApplicableIndependentBoundary(t *testing.T) {
	installed, _, qualified, binding, now, _ := installedSourceFixture(t)
	requirement := hostFenceRequirement(binding)
	reader, err := VerifyInstalledFenceEvidence(context.Background(), binding, []FenceRequirement{requirement}, installed, qualified, now)
	if err != nil {
		t.Fatal(err)
	}
	evaluator := FenceEvaluator{Evidence: reader, Clock: func() time.Time { return now }}
	result, err := evaluator.Verify(context.Background(), []FenceRequirement{requirement})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 1 || result.Items[0].Boundary != "host-service" || result.Items[0].Status != "verified" || !restoreDigest.MatchString(result.FenceSetDigest) || !result.VerifiedAt.Equal(now) {
		t.Fatalf("result = %#v", result)
	}

	proofs, err := reader.Current(context.Background(), requirement)
	if err != nil {
		t.Fatal(err)
	}
	partial := fenceEvidenceFixture{proofs: map[string][]IndependentFenceProof{fenceRequirementKey(requirement): proofs[:1]}}
	evaluator.Evidence = partial
	_, err = evaluator.Verify(context.Background(), []FenceRequirement{requirement})
	assertFenceCode(t, err, generated.ErrorCodePrerequisiteBlocked)

	proofs[0].CollectorInstanceID = binding.FormerInstanceID
	self := fenceEvidenceFixture{proofs: map[string][]IndependentFenceProof{fenceRequirementKey(requirement): proofs}}
	evaluator.Evidence = self
	_, err = evaluator.Verify(context.Background(), []FenceRequirement{requirement})
	assertFenceCode(t, err, generated.ErrorCodeAuthorizationDenied)
}

func TestFenceRejectsWrongAttributionAndFixtureProof(t *testing.T) {
	installed, _, qualified, binding, now, _ := installedSourceFixture(t)
	requirement := hostFenceRequirement(binding)
	reader, err := VerifyInstalledFenceEvidence(context.Background(), binding, []FenceRequirement{requirement}, installed, qualified, now)
	if err != nil {
		t.Fatal(err)
	}
	base, err := reader.Current(context.Background(), requirement)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func([]IndependentFenceProof){
		"fixture":      func(proofs []IndependentFenceProof) { proofs[0].ProofClass = "fixture" },
		"wrong-target": func(proofs []IndependentFenceProof) { proofs[0].TargetID = "other-target" },
		"wrong-epoch":  func(proofs []IndependentFenceProof) { proofs[0].RecoveryEpoch++ },
		"wrong-profile": func(proofs []IndependentFenceProof) {
			proofs[0].ProfileVersion = "2.0.0"
		},
		"expired": func(proofs []IndependentFenceProof) { proofs[0].ExpiresAt = now.Add(-time.Second) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			proofs := append([]IndependentFenceProof(nil), base...)
			mutate(proofs)
			evaluator := FenceEvaluator{Evidence: fenceEvidenceFixture{proofs: map[string][]IndependentFenceProof{fenceRequirementKey(requirement): proofs}}, Clock: func() time.Time { return now }}
			_, err := evaluator.Verify(context.Background(), []FenceRequirement{requirement})
			assertFenceCode(t, err, generated.ErrorCodePrerequisiteBlocked)
		})
	}
}
