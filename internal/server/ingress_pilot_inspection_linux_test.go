//go:build linux

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestIngressPilotSavedInspectionPreservesBlockersAndLineage(t *testing.T) {
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, item := range []struct{ name, reason string }{
		{"missing", "evidence-missing"}, {"saved", "proof-unverified"}, {"expired", "evidence-expired"}, {"revoked", "evidence-revoked-or-replaced"}, {"replaced", "proof-unverified"},
	} {
		t.Run(item.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "control.db")
			authority, err := store.Open(context.Background(), store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "1.0.0", BuildVersion: "build-a"})
			if err != nil {
				t.Fatal(err)
			}
			defer authority.Close()
			db, err := sql.Open("sqlite3", "file:"+path+"?mode=rw")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			row := generated.GateEvidence{Schema: generated.SchemaIDGateEvidence, SchemaVersion: "1.1.0", EvidenceID: "evidence-a", GateID: "platform-safety", SubjectID: "scope", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ReleaseBuildID: "build-a", ToolVersion: "1.0.0", ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", DeclarationID: "decl-a", DeclarationRevision: 1, StateRevision: 3, SourceKind: "local", ProofClass: "live", CollectorID: ingress.PilotCollectorID, HumanID: "human-a", ArtifactDigest: digest, BundleDigest: digest, ObservedAt: at.Add(-time.Minute).Format(time.RFC3339), AppliedAt: at.Add(-30 * time.Second).Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), RecoveryEpoch: 0, Status: "applied"}
			insert := func(e generated.GateEvidence) {
				t.Helper()
				raw, err := json.Marshal(e)
				if err != nil {
					t.Fatal(err)
				}
				if err := generated.ValidateContractJSON(generated.SchemaIDGateEvidence, raw, generated.ContractExact); err != nil {
					t.Fatal(err)
				}
				bundle, err := json.Marshal(ingress.PilotBundle([]generated.GateEvidenceFact{}, at.Add(-time.Minute)))
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`INSERT INTO gate_evidence_drafts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, "draft-"+e.EvidenceID, e.EvidenceID, e.GateID, e.SubjectID, e.DefinitionVersion, e.EvaluatorVersion, e.SourceKind, e.ProofClass, e.SupersedesEvidenceID, e.RevokesEvidenceID, e.ArtifactDigest, e.BundleDigest, bundle, e.ObservedAt, e.StateRevision, e.RecoveryEpoch, e.HumanID, e.AppliedAt)
				if err != nil {
					t.Fatal(err)
				}
				_, err = db.Exec(`INSERT INTO gate_applied_evidence VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, e.EvidenceID, "draft-"+e.EvidenceID, e.GateID, e.SubjectID, e.Status, e.SourceKind, e.ProofClass, e.BundleDigest, raw, e.StateRevision, e.RecoveryEpoch, e.DeclarationID, e.DeclarationRevision, "plan-a", digest, "run-a", "step-a", "lease-a", e.SupersedesEvidenceID, e.RevokesEvidenceID, e.AppliedAt)
				if err != nil {
					t.Fatal(err)
				}
			}
			if item.name != "missing" {
				if item.name == "expired" {
					row.ExpiresAt = at.Add(-time.Second).Format(time.RFC3339)
				}
				insert(row)
				if item.name == "revoked" || item.name == "replaced" {
					next := row
					next.EvidenceID = "evidence-b"
					next.StateRevision++
					if item.name == "revoked" {
						next.Status = "revoked"
						next.RevokesEvidenceID = &row.EvidenceID
					} else {
						next.SupersedesEvidenceID = &row.EvidenceID
					}
					insert(next)
				}
			}
			c := &ingressAuthority{gates: store.NewGateRepository(authority), build: result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "build-a"}, pilot: &ingressPilotComposition{profile: serverconfig.Profile{IngressControllerReadPilot: &generated.IngressControllerReadPilot{}}}}
			scope := gate.ResolvedScope{ProfileID: row.ProfileID, ProfileVersion: row.ProfileVersion, PolicyID: row.PolicyID, PolicyVersion: row.PolicyVersion, Capabilities: []string{ingress.PilotCapability}, StateRevision: 99}
			// No source, credential backend, identity client or origin probe is supplied:
			// saved inspection must not need any live observation dependency.
			got, handled, err := c.InspectPilot(context.Background(), scope, "scope", "platform-safety", at)
			if err != nil || !handled || got.Outcome == "passed" || got.ReasonCode != item.reason {
				t.Fatalf("saved inspection: %+v handled=%v err=%v", got, handled, err)
			}
			if item.name != "missing" && !slices.Contains(got.EvidenceIDs, "evidence-a") {
				t.Fatalf("lineage lost: %+v", got)
			}
			if (item.name == "revoked" || item.name == "replaced") && !slices.Contains(got.EvidenceIDs, "evidence-b") {
				t.Fatalf("replacement/revocation lost: %+v", got)
			}
			// Check/apply's evaluator still requires fresh facts. Stored rows
			// cannot satisfy a deliberately incomplete live pilot policy.
			c.pilot.store, c.pilot.source = authority, c
			fresh, err := c.pilot.evaluate(context.Background(), scope, "platform-safety", at)
			if err == nil || fresh.Outcome == "passed" {
				t.Fatalf("saved evidence replaced fresh validation: %+v %v", fresh, err)
			}
		})
	}
}
