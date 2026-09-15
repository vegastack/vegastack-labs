package gate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type fixtureEvidenceReader struct {
	rows map[string][]generated.GateEvidence
}

type testOnlyVerifier struct{}

func (testOnlyVerifier) Verify(_ context.Context, _ Definition, _ generated.GateEvidence) (ProofResult, error) {
	return ProofResult{Verified: true}, nil
}

func validAppliedFixture(at time.Time) generated.GateEvidence {
	digest := "sha256:" + strings.Repeat("a", 64)
	return generated.GateEvidence{Schema: generated.SchemaIDGateEvidence, SchemaVersion: "1.1.0", EvidenceID: "evidence-a", GateID: "platform-safety", SubjectID: "site-a", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ReleaseBuildID: "build-a", ToolVersion: "1.0.0", ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", DeclarationID: "decl-a", DeclarationRevision: 1, StateRevision: 3, SourceKind: "local", ProofClass: "live", CollectorID: "collector-a", HumanID: "human-a", ArtifactDigest: digest, BundleDigest: digest, ObservedAt: at.Add(-time.Minute).Format(time.RFC3339), AppliedAt: at.Add(-30 * time.Second).Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), RecoveryEpoch: 0, Status: "applied"}
}

func (reader fixtureEvidenceReader) ListAppliedGateEvidence(_ context.Context, gateID, subjectID string) ([]generated.GateEvidence, error) {
	return reader.rows[gateID+"/"+subjectID], nil
}

func TestFixtureAndInapplicablePrerequisiteNeverPass(t *testing.T) {
	clock := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	scope := ResolvedScope{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", StateRevision: 3}
	subject := Subject{ID: "site-a", Kind: "site", StateRevision: 3, ReleaseBuildID: "build-a", ToolVersion: "1.0.0", DeclarationID: "decl-a", DeclarationRevision: 1}
	reader := fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{}}
	registry := NewProofRegistry()
	got, err := Evaluate(context.Background(), reader, scope, subject, "G-008", clock, registry)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome == "passed" {
		t.Fatal("unverified proof or missing prerequisite passed")
	}
	minimal := scope
	minimal.ProfileID = "minimal-no-account"
	got, err = Evaluate(context.Background(), reader, minimal, subject, "G-008", clock, registry)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "not-applicable" {
		t.Fatalf("profile mismatch: %s", got.Outcome)
	}
}

func TestAppliedEvidenceRequiresRegisteredVerifierAndCurrentBindings(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	scope := ResolvedScope{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", StateRevision: 3}
	subject := Subject{ID: "site-a", Kind: "site", StateRevision: 3, ReleaseBuildID: "build-a", ToolVersion: "1.0.0", DeclarationID: "decl-a", DeclarationRevision: 1, ArtifactDigest: "sha256:" + strings.Repeat("a", 64)}
	base := validAppliedFixture(at)
	registry := NewProofRegistry()
	reader := fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{"platform-safety/site-a": {base}}}
	result, err := Evaluate(context.Background(), reader, scope, subject, "platform-safety", at, registry)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "blocked" || result.ReasonCode != "proof-unverified" {
		t.Fatalf("unregistered proof: %+v", result)
	}
	registry.Register("platform-safety", "local", testOnlyVerifier{})
	result, err = Evaluate(context.Background(), reader, scope, subject, "platform-safety", at, registry)
	if err != nil || result.Outcome != "passed" {
		t.Fatalf("test-only proof: %+v %v", result, err)
	}
	tests := []struct {
		name, reason string
		change       func(*generated.GateEvidence)
	}{
		{"fixture", "evidence-fixture-or-legacy", func(e *generated.GateEvidence) { e.SourceKind, e.ProofClass = "fixture", "fixture" }},
		{"future", "evidence-future-or-invalid-time", func(e *generated.GateEvidence) { e.ObservedAt = at.Add(time.Minute).Format(time.RFC3339) }},
		{"expired", "evidence-expired", func(e *generated.GateEvidence) { e.ExpiresAt = at.Add(-time.Second).Format(time.RFC3339) }},
		{"subject", "evidence-wrong-subject", func(e *generated.GateEvidence) { e.SubjectID = "site-b" }},
		{"profile", "evidence-wrong-version", func(e *generated.GateEvidence) { e.ProfileVersion = "1.1.0" }},
		{"state", "evidence-wrong-revision", func(e *generated.GateEvidence) { e.StateRevision = 2 }},
		{"epoch", "evidence-wrong-epoch", func(e *generated.GateEvidence) { e.RecoveryEpoch = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := base
			test.change(&row)
			reader.rows["platform-safety/site-a"] = []generated.GateEvidence{row}
			got, err := Evaluate(context.Background(), reader, scope, subject, "platform-safety", at, registry)
			if err != nil {
				t.Fatal(err)
			}
			if got.Outcome == "passed" || got.ReasonCode != test.reason {
				t.Fatalf("%s: %+v", test.name, got)
			}
		})
	}
	reader.rows["platform-safety/site-a"] = []generated.GateEvidence{base}
	revoke := base
	revoke.EvidenceID, revoke.Status, revoke.RevokesEvidenceID, revoke.StateRevision = "evidence-revoke", "revoked", &base.EvidenceID, 4
	reader.rows["platform-safety/site-a"] = append(reader.rows["platform-safety/site-a"], revoke)
	got, err := Evaluate(context.Background(), reader, scope, subject, "platform-safety", at, registry)
	if err != nil || got.Outcome == "passed" {
		t.Fatalf("revoked proof: %+v %v", got, err)
	}
	rolled := scope
	rolled.RecoveryEpoch++
	got, err = Evaluate(context.Background(), fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{"platform-safety/site-a": {base}}}, rolled, subject, "platform-safety", at, registry)
	if err != nil || got.ReasonCode != "evidence-wrong-epoch" {
		t.Fatalf("epoch rollover: %+v %v", got, err)
	}
}
