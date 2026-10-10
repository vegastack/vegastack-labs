//go:build linux

package server

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// This stored-row fixture tests only startup routing, not restore approval.
// A candidate for a distinct host must never be locally promoted on restart.
func TestReplacementSourceStartupRetainsFormerAuthority(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "control.db")
	cfg := store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), BusyTimeout: time.Second, ToolVersion: "test", BuildVersion: "test"}
	s, e := store.Open(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	prior, e := s.CurrentAuthority(ctx)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	a := processOldAuthorityArtifacts(t)
	seedProcessOldAuthorityArtifacts(t, path, a)
	b := processRecoveryBinding(prior.InstanceID, prior.RecoveryEpoch)
	b.PlanID = a.Plan.PlanID
	b.PlanDigest = a.Plan.PlanDigest
	b.HumanAcknowledgementID = a.Acknowledgement.AcknowledgementID
	b.ReplacementContinuity = &generated.HostReplacementContinuityReference{Schema: generated.SchemaIDHostReplacementContinuityReference, SchemaVersion: "1.0.0", ReplacementID: "replacement-startup", Digest: processRecoveryDigest("4"), SourcePointID: b.PointID, SourceBindingDigest: processRecoveryDigest("5"), SourceAliasHighWatermark: 1, CurrentAliasHighWatermark: 2}
	db, e := sql.Open("sqlite3", path)
	if e != nil {
		t.Fatal(e)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := db.Exec(q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO restore_sessions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, b.PlanID, b.PlanDigest, a.Plan.DeclarationID, 1, b.HumanAcknowledgementID, b.PointID, b.Source.PointDigest, processRecoveryDigest("6"), b.FenceSetDigest, b.AuditDecisionDigest, b.TargetDigest, b.CandidateDigest, b.PriorInstanceID, b.NewInstanceID, b.PriorRecoveryEpoch, b.NextRecoveryEpoch, 1, processJSON(t, b), "now")
	exec(`INSERT INTO restore_transitions(plan_id,from_status,to_status,plan_digest,evidence_digest,state_revision,recovery_epoch,created_at) VALUES(?,'restoring','verification-required',?,?,1,0,'now')`, b.PlanID, b.PlanDigest, b.CandidateDigest)
	exec(`INSERT INTO recovery_candidates VALUES(?,?,?,?,?,?,?,?,?,1,0,'now')`, "candidate-startup", b.PlanID, b.CandidateDigest, processRecoveryDigest("7"), b.FenceSetDigest, b.AuditDecisionDigest, processRecoveryDigest("8"), processRecoveryDigest("9"), processRecoveryDigest("a"))
	db.Close()
	paths, e := recovery.DeriveCandidatePaths(path, b.PlanID)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(paths.Candidate, []byte("untouched staged replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	opens := 0
	op := &Operations{databasePath: path, build: result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, openStore: func(ctx context.Context, c store.Config) (*store.Store, error) { opens++; return store.Open(ctx, c) }}
	got, e := op.openAuthorityWithPromotion(ctx, serverconfig.Profile{SocketOwnerUID: uint32(os.Geteuid())})
	if e != nil {
		t.Fatal(e)
	}
	defer got.Close()
	current, e := got.CurrentAuthority(ctx)
	if e != nil || opens != 1 || current.InstanceID != prior.InstanceID || current.RecoveryEpoch != prior.RecoveryEpoch {
		t.Fatalf("source cutover: opens=%d current=%+v error=%v", opens, current, e)
	}
	raw, e := os.ReadFile(paths.Candidate)
	if e != nil || string(raw) != "untouched staged replacement" {
		t.Fatal("candidate consumed or modified")
	}
	if _, e = os.Lstat(paths.PreservedAuthority); !os.IsNotExist(e) {
		t.Fatal("source was moved to former path")
	}
}
