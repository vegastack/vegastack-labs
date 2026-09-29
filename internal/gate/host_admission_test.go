package gate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// Phase 6 host admission reuses the shared gate evaluator: host.hardening-baseline
// and host.role-admission derive readiness from applied evidence for a node
// subject, fail closed on stale/foreign/fixture proof, and require the hardening
// baseline before a role is admitted. Fixtures reuse evaluator_test.go helpers
// (validAppliedFixture, fixtureEvidenceReader, testOnlyVerifier, NewProofRegistry).

func hostRow(gateID, subjectID string, at time.Time) generated.GateEvidence {
	row := validAppliedFixture(at)
	row.GateID = gateID
	row.SubjectID = subjectID
	row.EvidenceID = "ev." + strings.ReplaceAll(gateID, "-", ".") + "." + subjectID
	return row
}

func hostSubject() Subject {
	return Subject{ID: "node-a", Kind: "node", StateRevision: 3, ReleaseBuildID: "build-a", ToolVersion: "1.0.0", DeclarationID: "decl-a", DeclarationRevision: 1, ArtifactDigest: "sha256:" + strings.Repeat("a", 64)}
}

func labsHostScope() ResolvedScope {
	return ResolvedScope{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", StateRevision: 3}
}

func hostRegistry() ProofRegistry {
	registry := NewProofRegistry()
	registry.Register("platform-safety", "local", testOnlyVerifier{})
	registry.Register("host.hardening-baseline", "local", testOnlyVerifier{})
	registry.Register("host.role-admission", "local", testOnlyVerifier{})
	return registry
}

func TestHostHardeningAdmitsHardenedNode(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	reader := fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{
		"platform-safety/node-a":         {hostRow("platform-safety", "node-a", at)},
		"host.hardening-baseline/node-a": {hostRow("host.hardening-baseline", "node-a", at)},
	}}
	got, err := Evaluate(context.Background(), reader, labsHostScope(), hostSubject(), "host.hardening-baseline", at, hostRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "passed" {
		t.Fatalf("hardened node should pass: %+v", got)
	}
}

func TestHostRoleAdmissionRequiresHardeningBaseline(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	// Full chain present -> role-admission passes.
	full := fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{
		"platform-safety/node-a":         {hostRow("platform-safety", "node-a", at)},
		"host.hardening-baseline/node-a": {hostRow("host.hardening-baseline", "node-a", at)},
		"host.role-admission/node-a":     {hostRow("host.role-admission", "node-a", at)},
	}}
	got, err := Evaluate(context.Background(), full, labsHostScope(), hostSubject(), "host.role-admission", at, hostRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "passed" {
		t.Fatalf("fully hardened node should admit role: %+v", got)
	}
	// Hardening evidence absent -> role-admission is blocked on the prerequisite.
	missing := fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{
		"platform-safety/node-a":     {hostRow("platform-safety", "node-a", at)},
		"host.role-admission/node-a": {hostRow("host.role-admission", "node-a", at)},
	}}
	got, err = Evaluate(context.Background(), missing, labsHostScope(), hostSubject(), "host.role-admission", at, hostRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome == "passed" || got.ReasonCode != "prerequisite-not-passed" {
		t.Fatalf("role must block without hardening baseline: %+v", got)
	}
}

func TestHostHardeningDeniesStaleAndForeignEvidence(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	cases := map[string]func(*generated.GateEvidence){
		"expired":       func(e *generated.GateEvidence) { e.ExpiresAt = at.Add(-time.Second).Format(time.RFC3339) },
		"wrong-epoch":   func(e *generated.GateEvidence) { e.RecoveryEpoch = 1 },
		"wrong-subject": func(e *generated.GateEvidence) { e.SubjectID = "node-b" },
		"fixture":       func(e *generated.GateEvidence) { e.SourceKind, e.ProofClass = "fixture", "fixture" },
		"malformed":     func(e *generated.GateEvidence) { e.SchemaVersion = "999" },
		"undated":       func(e *generated.GateEvidence) { e.ObservedAt = "not-a-timestamp" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			row := hostRow("host.hardening-baseline", "node-a", at)
			mutate(&row)
			reader := fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{
				"platform-safety/node-a":         {hostRow("platform-safety", "node-a", at)},
				"host.hardening-baseline/node-a": {row},
			}}
			got, err := Evaluate(context.Background(), reader, labsHostScope(), hostSubject(), "host.hardening-baseline", at, hostRegistry())
			if err != nil {
				t.Fatal(err)
			}
			if got.Outcome == "passed" {
				t.Fatalf("%s evidence must not pass: %+v", name, got)
			}
		})
	}
}

func TestHostGateNotApplicableToNonNodeSubject(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	// Host gates are node-scoped; a service subject must not resolve them, so no
	// evidence can admit it (non-applicable, fails closed).
	subject := hostSubject()
	subject.Kind = "service"
	reader := fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{
		"host.hardening-baseline/node-a": {hostRow("host.hardening-baseline", "node-a", at)},
	}}
	got, err := Evaluate(context.Background(), reader, labsHostScope(), subject, "host.hardening-baseline", at, hostRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome == "passed" || got.ReasonCode != "definition-unresolved" {
		t.Fatalf("host gate must not apply to a non-node subject: %+v", got)
	}
}

func TestHostGateInertWithoutEvidence(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	// Defining the gate does not self-admit: with the platform prerequisite met but
	// no hardening evidence, the baseline is blocked on missing evidence, not passed.
	reader := fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{
		"platform-safety/node-a": {hostRow("platform-safety", "node-a", at)},
	}}
	got, err := Evaluate(context.Background(), reader, labsHostScope(), hostSubject(), "host.hardening-baseline", at, hostRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome == "passed" || got.ReasonCode != "evidence-missing" {
		t.Fatalf("gate must be inert without evidence: %+v", got)
	}
}

func TestHostHardeningAdmitsMinimalNonLabsNode(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	// host.hardening-baseline is a platform-layer gate (no profile gating), so a
	// minimal/non-Labs node admits with no Labs value present.
	scope := ResolvedScope{ProfileID: "minimal-no-account", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", StateRevision: 3}
	minimalRow := func(gateID string) generated.GateEvidence {
		row := hostRow(gateID, "node-a", at)
		row.ProfileID = "minimal-no-account"
		return row
	}
	reader := fixtureEvidenceReader{rows: map[string][]generated.GateEvidence{
		"platform-safety/node-a":         {minimalRow("platform-safety")},
		"host.hardening-baseline/node-a": {minimalRow("host.hardening-baseline")},
	}}
	got, err := Evaluate(context.Background(), reader, scope, hostSubject(), "host.hardening-baseline", at, hostRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "passed" {
		t.Fatalf("minimal non-Labs node should pass hardening: %+v", got)
	}
}
