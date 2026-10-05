package gate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// Phase 6.1 defines host-gate shapes only. Until Issue 6.8 binds an applied
// host profile and hardening fact, even a generic live proof with a registered
// verifier cannot admit a workload host.

func hostRow(gateID, subjectID, profileID string, at time.Time) generated.GateEvidence {
	row := validAppliedFixture(at)
	row.GateID = gateID
	row.SubjectID = subjectID
	row.ProfileID = profileID
	row.EvidenceID = "ev." + strings.ReplaceAll(gateID, "-", ".") + "." + subjectID
	return row
}

func hostSubject() Subject {
	return Subject{ID: "node-a", Kind: "node", StateRevision: 3, ReleaseBuildID: "build-a", ToolVersion: "1.0.0", DeclarationID: "decl-a", DeclarationRevision: 1, ArtifactDigest: "sha256:" + strings.Repeat("a", 64)}
}

func hostScope(profileID string) ResolvedScope {
	return ResolvedScope{ProfileID: profileID, ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", StateRevision: 3}
}

func hostRegistry() ProofRegistry {
	registry := NewProofRegistry()
	for _, gateID := range []string{"platform-safety", "host.hardening-baseline", "host.role-admission"} {
		registry.Register(gateID, "local", testOnlyVerifier{})
	}
	return registry
}

func TestHostAdmissionRemainsDeferred(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	for _, profileID := range []string{"vegastack-labs", "minimal-no-account"} {
		for _, withHostEvidence := range []bool{false, true} {
			name := profileID + "/without-host-evidence"
			if withHostEvidence {
				name = profileID + "/with-generic-host-evidence"
			}
			t.Run(name, func(t *testing.T) {
				rows := map[string][]generated.GateEvidence{
					"platform-safety/node-a": {hostRow("platform-safety", "node-a", profileID, at)},
				}
				if withHostEvidence {
					rows["host.hardening-baseline/node-a"] = []generated.GateEvidence{hostRow("host.hardening-baseline", "node-a", profileID, at)}
					rows["host.role-admission/node-a"] = []generated.GateEvidence{hostRow("host.role-admission", "node-a", profileID, at)}
				}
				reader := fixtureEvidenceReader{rows: rows}
				for _, gateID := range []string{"host.hardening-baseline", "host.role-admission"} {
					got, err := Evaluate(context.Background(), reader, hostScope(profileID), hostSubject(), gateID, at, hostRegistry())
					if err != nil {
						t.Fatal(err)
					}
					if got.Outcome != "not-applicable" || got.ReasonCode != "deferred" || got.ReadyForInput || len(got.EvidenceIDs) != 0 {
						t.Fatalf("%s admitted or read generic evidence: %+v", gateID, got)
					}
				}
				platform, err := Evaluate(context.Background(), reader, hostScope(profileID), hostSubject(), "platform-safety", at, hostRegistry())
				if err != nil {
					t.Fatal(err)
				}
				if platform.Outcome != "passed" || platform.ReasonCode != "proof-verified" {
					t.Fatalf("existing platform gate changed: %+v", platform)
				}
			})
		}
	}
}

func TestHostAdmissionGateUnresolvedForNonNode(t *testing.T) {
	at := time.Date(2026, 9, 16, 0, 0, 0, 0, time.UTC)
	subject := hostSubject()
	subject.Kind = "service"
	got, err := Evaluate(context.Background(), fixtureEvidenceReader{}, hostScope("vegastack-labs"), subject, "host.hardening-baseline", at, hostRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "unknown" || got.ReasonCode != "definition-unresolved" {
		t.Fatalf("host gate resolved for a non-node subject: %+v", got)
	}
}
