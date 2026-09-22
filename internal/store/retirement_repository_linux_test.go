//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/backupidentity"
)

func retirementStageFixture(t *testing.T, authority *Store, risk, branch string) LocalRetirementStageRequest {
	t.Helper()
	request := LocalRetirementStageRequest{RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard",
		CatalogDigest: testDigest, ExpectedInventoryDigest: testDigest,
		Targets:        []LocalRetirementTarget{{PointID: "old-point", SnapshotID: strings.Repeat("a", 64), ManifestDigest: testDigest, DependencyDigest: testDigest}},
		Survivors:      []LocalRetirementSurvivor{{PointID: "good-point", SnapshotID: strings.Repeat("b", 64), ManifestDigest: testDigest, DependencyDigest: testDigest, ProofDigest: testDigest}},
		SourceRevision: 2, StateRevision: 2, RecoveryEpoch: 0, MaxWorkObjects: 10, MaxMutationBytes: 1024, MaxRepackBytes: 1024,
		Attribution: validDeclarationStoreRequest().Attribution}
	_, digest, err := canonicalRetirementSelection(request)
	if err != nil {
		t.Fatal(err)
	}
	request.SelectionDigest = digest
	draft := validDeclarationStoreRequest()
	draft.Document.DeclarationType = "backup.retirement"
	draft.Document.Operations[0].OperationType = "backup.local.retire"
	draft.Document.Operations[0].AdapterID = "local.retention"
	draft.Document.Operations[0].TargetID = request.RepositoryID
	draft.Document.Operations[0].InputDigest = digest
	draft.Document.Operations[0].ArtifactDigest = request.ExpectedInventoryDigest
	draft.Document.ContentDigest = declarationContentDigest(draft.Document, draft.ReasonDigest)
	created, err := NewDeclarationRepository(authority).CreateRevision(context.Background(), draft)
	if err != nil {
		t.Fatal(err)
	}
	commit := validPlanStoreRequest(created.Document)
	commit.Plan.Risk, commit.Plan.AuthorizationBranch = risk, branch
	commit.Plan.Binding.TargetDigest = digest
	commit.Plan.Operations[0].OperationType = "backup.local.retire"
	commit.Plan.Operations[0].AdapterID = "local.retention"
	commit.Plan.Operations[0].TargetID = request.RepositoryID
	commit.Plan.Operations[0].InputDigest = digest
	commit.Plan.Operations[0].ArtifactDigest = request.ExpectedInventoryDigest
	commit.Plan.PlanID, commit.Plan.PlanDigest = "", ""
	preimage, err := json.Marshal(commit.Plan)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(preimage)
	commit.Plan.PlanDigest = "sha256:" + hex.EncodeToString(sum[:])
	commit.Plan.PlanID = "plan-" + hex.EncodeToString(sum[:16])
	commit.CanonicalBytes, err = json.Marshal(commit.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPlanRepository(authority).CommitDeclarationAndPlan(context.Background(), commit); err != nil {
		t.Fatal(err)
	}
	request.PlanID, request.PlanDigest = commit.Plan.PlanID, commit.Plan.PlanDigest
	return request
}

func openRetirementTestStore(t *testing.T) *Store {
	t.Helper()
	config := testConfig(t)
	config.Clock = func() time.Time { return time.Date(2026, 9, 12, 18, 30, 0, 0, time.UTC) }
	authority, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	return authority
}

func TestLocalRetirementStageIsInertExactAndAppendOnly(t *testing.T) {
	authority := openRetirementTestStore(t)
	request := retirementStageFixture(t, authority, "destructive", "human")
	repository := NewLocalRetirementRepository(authority)
	intent, err := repository.StageLocalRetirement(context.Background(), request)
	if err != nil || intent.IntentID == "" || intent.Request.SelectionDigest != request.SelectionDigest {
		t.Fatalf("stage intent: %#v %v", intent, err)
	}
	if replay, err := repository.StageLocalRetirement(context.Background(), request); err != nil || replay.IntentID != intent.IntentID {
		t.Fatalf("idempotent replay: %#v %v", replay, err)
	}
	otherActor := request
	otherActor.Attribution.AuthenticatedPrincipalID = "other-human"
	if _, err := repository.StageLocalRetirement(context.Background(), otherActor); err == nil {
		t.Fatal("another human replayed the same plan intent")
	}
	for _, table := range []string{"backup_retirement_leases", "backup_retirement_mutation_attempts", "backup_retirement_successor_generations", "backup_retirement_finalizations"} {
		var count int
		if err := authority.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("staging activated %s: count=%d err=%v", table, count, err)
		}
	}
	if _, err := authority.conn.ExecContext(context.Background(), `UPDATE backup_retirement_intents SET selection_digest=? WHERE intent_id=?`, testDigest, intent.IntentID); err == nil {
		t.Fatal("immutable retirement intent updated")
	}
	if _, err := authority.conn.ExecContext(context.Background(), `DELETE FROM backup_retirement_intents WHERE intent_id=?`, intent.IntentID); err == nil {
		t.Fatal("immutable retirement intent deleted")
	}
}

func TestLocalRetirementStageRejectsStaleOrNonHumanPlan(t *testing.T) {
	for _, test := range []struct{ name, risk, branch string }{
		{"routine", "routine", "human"},
		{"preauthorized", "destructive", "preauthorized"},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority := openRetirementTestStore(t)
			request := retirementStageFixture(t, authority, test.risk, test.branch)
			if _, err := NewLocalRetirementRepository(authority).StageLocalRetirement(context.Background(), request); err == nil {
				t.Fatal("non-human destructive plan staged retirement")
			}
		})
	}
	authority := openRetirementTestStore(t)
	request := retirementStageFixture(t, authority, "destructive", "human")
	repository := NewLocalRetirementRepository(authority)
	invalid := request
	invalid.Survivors = append([]LocalRetirementSurvivor(nil), request.Survivors...)
	invalid.Survivors[0].ProofDigest = ""
	if _, err := repository.StageLocalRetirement(context.Background(), invalid); err == nil {
		t.Fatal("unproved survivor staged")
	}
	invalid = request
	invalid.StateRevision--
	if _, err := repository.StageLocalRetirement(context.Background(), invalid); err == nil {
		t.Fatal("stale state revision staged")
	}
	invalid = request
	invalid.PlanID = "plan-forged"
	if _, err := repository.StageLocalRetirement(context.Background(), invalid); err == nil {
		t.Fatal("unstored plan staged")
	}
	var count int
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM backup_retirement_intents`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("denial wrote intent: %d %v", count, err)
	}
}

func TestLocalRetirementStageRequiresExactPointSets(t *testing.T) {
	authority := openRetirementTestStore(t)
	request := retirementStageFixture(t, authority, "destructive", "human")
	repository := NewLocalRetirementRepository(authority)
	for name, mutate := range map[string]func(*LocalRetirementStageRequest){
		"target-survivor-overlap": func(r *LocalRetirementStageRequest) { r.Targets[0].PointID = r.Survivors[0].PointID },
		"duplicate-snapshot":      func(r *LocalRetirementStageRequest) { r.Targets[0].SnapshotID = r.Survivors[0].SnapshotID },
		"wrong-repository":        func(r *LocalRetirementStageRequest) { r.RepositoryID = "other" },
		"malformed-snapshot":      func(r *LocalRetirementStageRequest) { r.Targets[0].SnapshotID = "short" },
		"missing-proof":           func(r *LocalRetirementStageRequest) { r.Survivors[0].ProofDigest = "" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := request
			invalid.Targets = append([]LocalRetirementTarget(nil), request.Targets...)
			invalid.Survivors = append([]LocalRetirementSurvivor(nil), request.Survivors...)
			mutate(&invalid)
			_, digest, err := canonicalRetirementSelection(invalid)
			if err == nil {
				invalid.SelectionDigest = digest
			}
			if _, err := repository.StageLocalRetirement(context.Background(), invalid); err == nil {
				t.Fatal("ambiguous point selection staged")
			}
		})
	}
}
