//go:build linux

package store

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const phase5ConcurrencySeed = "phase5-concurrency-v1"

// TestPhase5AcceptanceSeededConcurrency races the six distinct Phase 5
// authorities directly. Each case inspects its own append-only domain rows;
// the generic run engine is deliberately absent from this selector.
func TestPhase5AcceptanceSeededConcurrency(t *testing.T) {
	repeat := requirePhase5ConcurrencyEnvironment(t)
	t.Run("gate-draft-apply", func(t *testing.T) { phase5ConcurrentGateApply(t, repeat, 0) })
	t.Run("credential-import-lifecycle", func(t *testing.T) { phase5ConcurrentCredentialLifecycle(t, repeat, 1) })
	t.Run("backup-writer", func(t *testing.T) { phase5ConcurrentBackupWriter(t, repeat, 2) })
	t.Run("audit-chain", func(t *testing.T) { phase5ConcurrentAuditChain(t, repeat, 3) })
	t.Run("restore-authority", func(t *testing.T) { phase5ConcurrentRestoreAuthority(t, repeat, 4) })
	t.Run("schedule-slot", func(t *testing.T) { phase5ConcurrentScheduleSlot(t, repeat, 5) })
}

func phase5ConcurrentGateApply(t *testing.T, repeat, family int) {
	repository := openGateTestStore(t)
	scope := GateAppliedProfile{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", Capabilities: []string{}}
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local"}
	draft, err := repository.PutProfileDraft(context.Background(), ProfileDraftRequest{
		BindingID: "binding-phase5", Scope: scope, Expected: RevisionToken{},
		KeyDigest: gateDigest([]byte("phase5-gate-draft-key")), RequestDigest: gateDigest([]byte("phase5-gate-draft-request")), Attribution: attribution,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := ProfileApplyRequest{
		BindingID: draft.BindingID, Scope: draft.Scope, Expected: RevisionToken{StateRevision: draft.StateRevision, RecoveryEpoch: draft.RecoveryEpoch},
		PlanID: "plan-phase5-gate", PlanDigest: string(gateDigest([]byte("phase5-gate-plan"))), RunID: "run-phase5-gate", StepID: "step-phase5-gate", LeaseID: "lease-phase5-gate",
		DeclarationID: "declaration-phase5-gate", DeclarationRevision: 1,
		KeyDigest: gateDigest([]byte("phase5-gate-apply-key")), RequestDigest: gateDigest([]byte("phase5-gate-apply-request")), Attribution: attribution,
	}
	seedGateExactStep(t, repository, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.LeaseID, request.DeclarationID, scope.ProfileID, draft.ScopeDigest, "gate.profile.bind", request.Expected.StateRevision)

	results := phase5Race(t, repeat, family, 12, func(int) (string, error) {
		applied, err := repository.ApplyProfileBinding(context.Background(), request)
		return applied.ProfileID, err
	})
	success, rejected := phase5CountAllowed(t, results, generated.ErrorCodePlanStale, generated.ErrorCodeStateConflict)
	if success < 1 || success+rejected != len(results) {
		t.Fatalf("gate apply outcomes success=%d rejected=%d", success, rejected)
	}
	assertPhase5SuccessfulValues(t, results, scope.ProfileID)
	var rows int
	if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM gate_applied_profiles WHERE binding_id=?`, request.BindingID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("applied gate profiles=%d err=%v", rows, err)
	}
	current, err := repository.GetAppliedProfileScope(context.Background())
	if err != nil || current.ProfileID != scope.ProfileID || current.StateRevision != draft.StateRevision+1 {
		t.Fatalf("current gate profile=%#v err=%v", current, err)
	}
}

func phase5ConcurrentCredentialLifecycle(t *testing.T, repeat, family int) {
	repository := openCredentialStore(t)
	stage := seedCredentialLifecycleStep(t, repository, credentialref.ActionStage, stagedReference(2), 2, ackConsumed)
	binding := stageBinding()
	results := phase5Race(t, repeat, family, 12, func(int) (string, error) {
		version, err := repository.ApplyCredentialLifecycle(context.Background(), CredentialLifecycleApplyRequest{Binding: binding, Stage: stage})
		return version.ReferenceID + "/" + version.MaterialVersion, err
	})
	success, rejected := 0, 0
	for _, result := range results {
		if result.err == nil {
			success++
			continue
		}
		if code := Code(result.err); code != generated.ErrorCodeStateConflict && code != generated.ErrorCodePlanStale {
			t.Fatalf("unexpected credential concurrency code=%q err=%v", code, result.err)
		}
		rejected++
	}
	if success < 1 || success+rejected != len(results) {
		t.Fatalf("credential lifecycle outcomes success=%d rejected=%d", success, rejected)
	}
	assertPhase5SuccessfulValues(t, results, "reference-a/version-a")
	if got := tableCount(t, repository, "credential_reference_versions"); got != 1 {
		t.Fatalf("credential versions=%d, want 1", got)
	}
	if got := tableCount(t, repository, "credential_import_drafts"); got != 1 {
		t.Fatalf("credential import drafts=%d, want 1", got)
	}
	stored, err := repository.GetCredentialVersion(context.Background(), "reference-a", "version-a")
	if err != nil || stored.Status != "staged" || stored.StateRevision != 3 {
		t.Fatalf("stored credential=%#v err=%v", stored, err)
	}
}

func phase5ConcurrentBackupWriter(t *testing.T, repeat, family int) {
	repository := openBackupStore(t)
	policyDigest := seededDraftDigest(t, repository)
	results := phase5Race(t, repeat, family, 12, func(index int) (string, error) {
		suffix := strconv.Itoa(index)
		err := repository.AcquireBackupWriterLease(context.Background(), BackupWriterLeaseRequest{
			LeaseID: "phase5-backup-lease-" + suffix, JobID: "phase5-backup-job-" + suffix,
			PolicyID: "policy-a", PolicyDigest: policyDigest, PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("a", 64),
			RunID: "phase5-backup-run-" + suffix, StepID: "phase5-backup-step-" + suffix,
			RepositoryID: backupidentity.StandardRepository, RepositoryClass: "standard", TargetID: "target-a", RecoveryEpoch: 0, SourceRevision: 3,
			MaximumExpiresAt: repository.store.config.Clock().UTC().Add(time.Hour),
		})
		return "active", err
	})
	success, conflict := phase5ResultCounts(t, results, generated.ErrorCodeStateConflict)
	if success != 1 || conflict != 11 {
		t.Fatalf("backup writer outcomes success=%d conflict=%d", success, conflict)
	}
	var leases, jobs int
	if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM backup_writer_leases WHERE repository_id=? AND released_at IS NULL`, backupidentity.StandardRepository).Scan(&leases); err != nil {
		t.Fatal(err)
	}
	if err := repository.store.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM backup_jobs WHERE status='running'`).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if leases != 1 || jobs != 1 {
		t.Fatalf("backup authority leases=%d running-jobs=%d", leases, jobs)
	}
}

func phase5ConcurrentAuditChain(t *testing.T, repeat, family int) {
	authority := openAuditTestStore(t)
	const writers = 12
	results := phase5Race(t, repeat, family, writers, func(index int) (string, error) {
		request := chainTestIntent(t, index)
		businessID := fmt.Sprintf("phase5-chain-business-%d", index)
		intent, err := authority.writeIntent(context.Background(), request, func(ctx context.Context, tx *sql.Tx) error {
			_, err := tx.ExecContext(ctx, `INSERT INTO audit_business(id) VALUES(?)`, businessID)
			return err
		})
		return strconv.FormatInt(int64(intent.EventID), 10), err
	})
	if success, conflict := phase5ResultCounts(t, results, ""); success != writers || conflict != 0 {
		t.Fatalf("audit writer outcomes success=%d failure=%d", success, conflict)
	}
	rows, err := authority.conn.QueryContext(context.Background(), `SELECT event_id,segment_sequence,previous_digest,link_digest FROM audit_chain_links ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	var prior audit.Fingerprint
	for rows.Next() {
		var eventID audit.EventID
		var sequence int64
		var predecessor, digest audit.Fingerprint
		if err := rows.Scan(&eventID, &sequence, &predecessor, &digest); err != nil {
			t.Fatal(err)
		}
		count++
		if eventID != audit.EventID(count) || sequence != int64(count) || !audit.ValidFingerprint(digest) || (count > 1 && predecessor != prior) {
			t.Fatalf("forked audit row event=%d sequence=%d", eventID, sequence)
		}
		prior = digest
	}
	if err := rows.Err(); err != nil || count != writers {
		t.Fatalf("audit links=%d err=%v", count, err)
	}
}

func phase5ConcurrentRestoreAuthority(t *testing.T, repeat, family int) {
	authority := openRecoveryArtifactStore(t)
	prior, err := authority.CurrentAuthority(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	plan := generated.Plan{PlanID: "plan-recovery-artifact", PlanDigest: testDigest, Binding: generated.PlanBinding{TargetDigest: testDigest}}
	binding := testRestoreBinding(plan, prior.InstanceID, "ack-recovery-artifact")
	binding.CanaryRunID, binding.CanaryStepID, binding.CanaryLeaseID = "canary-run-a", "canary-step-a", "canary-lease-a"
	binding.CanaryChallengeID, binding.CanaryReceiptID, binding.CanaryBindingDigest = "canary-challenge-a", "canary-receipt-a", testDigest
	if !validRestoreBinding(binding) {
		t.Fatalf("restore binding fixture is invalid: %#v", binding)
	}
	results := phase5Race(t, repeat, family, 12, func(int) (string, error) {
		err := authority.PrepareRecoveredAuthority(context.Background(), binding, digestForText("phase5-prior-checkpoint"))
		return binding.NewInstanceID, err
	})
	success, rejected := phase5CountAllowed(t, results, generated.ErrorCodeStateConflict, generated.ErrorCodePrerequisiteBlocked)
	if success != 1 || rejected != 11 {
		t.Fatalf("restore authority outcomes success=%d rejected=%d", success, rejected)
	}
	current, err := authority.CurrentAuthority(context.Background())
	if err != nil || current.InstanceID != binding.NewInstanceID || current.RecoveryEpoch != binding.NextRecoveryEpoch || current.Mode != "recovery-required" {
		t.Fatalf("current recovery authority=%#v err=%v", current, err)
	}
	var promoted int
	if err := authority.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM recovery_authority_journal WHERE plan_id=? AND transition='promoted'`, binding.PlanID).Scan(&promoted); err != nil || promoted != 1 {
		t.Fatalf("promoted authority rows=%d err=%v", promoted, err)
	}
}

func phase5ConcurrentScheduleSlot(t *testing.T, repeat, family int) {
	ctx := context.Background()
	authority := openTestStore(t)
	repository := NewScheduleRepository(authority)
	policy := scheduledPolicyFixture()
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	draft, err := repository.StageDraft(ctx, policy, attribution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.conn.ExecContext(ctx, `UPDATE system_meta SET state_revision=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	seedScheduleActivationPlan(t, authority, policy)
	attribution.ResponsibleHumanPrincipalID = &attribution.AuthenticatedPrincipalID
	if _, err := repository.Activate(ctx, ScheduleActivationRequest{DraftID: draft.DraftID, AuthorizationBranch: "human", ExecutingOperation: "schedule.policy.activate", PlanID: "plan-a", PlanDigest: policy.RetentionRuleDigest, AcknowledgementID: "ack-a", ApprovedByHumanID: "human-a", Expected: RevisionToken{StateRevision: 1}, Attribution: attribution}); err != nil {
		t.Fatal(err)
	}
	due := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	results := phase5Race(t, repeat, family, 12, func(index int) (string, error) {
		suffix := strconv.Itoa(index)
		job, err := repository.ClaimOccurrence(ctx, OccurrenceClaim{Policy: policy, ScheduledAt: due, WindowClosesAt: due.Add(30 * time.Minute), OccurrenceToken: "phase5-token-" + suffix, TargetDigest: policy.RetentionRuleDigest, IdempotencyKey: "phase5-key-" + suffix, Expected: RevisionToken{StateRevision: 1}})
		return job.JobID, err
	})
	want := results[0].value
	if want == "" {
		for _, result := range results {
			if result.err == nil {
				want = result.value
				break
			}
		}
	}
	assertAllPhase5Results(t, results, want)
	var occurrences int
	if err := authority.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM scheduled_occurrences WHERE policy_id=? AND scheduled_at=?`, policy.PolicyID, due.Format(time.RFC3339)).Scan(&occurrences); err != nil || occurrences != 1 {
		t.Fatalf("scheduled occurrences=%d err=%v", occurrences, err)
	}
}

type phase5RaceResult struct {
	value string
	err   error
}

func phase5Race(t *testing.T, repeat, family, writers int, operation func(int) (string, error)) []phase5RaceResult {
	t.Helper()
	order := rand.New(rand.NewSource(int64(0x5eed0000 + repeat*97 + family))).Perm(writers)
	starts := make([]chan struct{}, writers)
	launched := make(chan int, writers)
	run := make(chan struct{})
	results := make([]phase5RaceResult, writers)
	var group sync.WaitGroup
	for index := range writers {
		starts[index] = make(chan struct{})
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-starts[index]
			launched <- index
			<-run
			results[index].value, results[index].err = operation(index)
		}(index)
	}
	for _, index := range order {
		close(starts[index])
		if got := <-launched; got != index {
			t.Fatalf("seeded launch order got=%d want=%d", got, index)
		}
	}
	close(run)
	group.Wait()
	return results
}

func requirePhase5ConcurrencyEnvironment(t *testing.T) int {
	t.Helper()
	seed, seedSet := os.LookupEnv("VSK_PHASE5_SEED")
	raw, repeatSet := os.LookupEnv("VSK_PHASE5_REPEAT")
	run, repeat, err := phase5ConcurrencyEnvironment(seed, seedSet, raw, repeatSet)
	if err != nil {
		t.Fatal(err)
	}
	if !run {
		t.Skip("Phase 5 seeded concurrency runs only through the acceptance catalog")
	}
	return repeat
}

func phase5ConcurrencyEnvironment(seed string, seedSet bool, raw string, repeatSet bool) (bool, int, error) {
	if !seedSet && !repeatSet {
		return false, 0, nil
	}
	if !seedSet || !repeatSet {
		return false, 0, fmt.Errorf("VSK_PHASE5_SEED and VSK_PHASE5_REPEAT must be set together")
	}
	if seed != phase5ConcurrencySeed {
		return false, 0, fmt.Errorf("VSK_PHASE5_SEED=%q, want %q", seed, phase5ConcurrencySeed)
	}
	repeat, err := strconv.Atoi(raw)
	if err != nil || repeat < 0 || repeat > 63 || strconv.Itoa(repeat) != raw {
		return false, 0, fmt.Errorf("invalid VSK_PHASE5_REPEAT=%q", raw)
	}
	return true, repeat, nil
}

func TestPhase5ConcurrencyEnvironment(t *testing.T) {
	tests := []struct {
		name      string
		seed      string
		seedSet   bool
		repeat    string
		repeatSet bool
		wantRun   bool
		wantValue int
		wantError bool
	}{
		{name: "generic go test skips"},
		{name: "seed only fails", seed: phase5ConcurrencySeed, seedSet: true, wantError: true},
		{name: "repeat only fails", repeat: "0", repeatSet: true, wantError: true},
		{name: "wrong seed fails", seed: "wrong", seedSet: true, repeat: "0", repeatSet: true, wantError: true},
		{name: "malformed repeat fails", seed: phase5ConcurrencySeed, seedSet: true, repeat: "01", repeatSet: true, wantError: true},
		{name: "negative repeat fails", seed: phase5ConcurrencySeed, seedSet: true, repeat: "-1", repeatSet: true, wantError: true},
		{name: "catalog environment runs", seed: phase5ConcurrencySeed, seedSet: true, repeat: "2", repeatSet: true, wantRun: true, wantValue: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run, value, err := phase5ConcurrencyEnvironment(test.seed, test.seedSet, test.repeat, test.repeatSet)
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v, wantError=%t", err, test.wantError)
			}
			if run != test.wantRun || value != test.wantValue {
				t.Fatalf("run=%t repeat=%d, want run=%t repeat=%d", run, value, test.wantRun, test.wantValue)
			}
		})
	}
}

func assertAllPhase5Results(t *testing.T, results []phase5RaceResult, want string) {
	t.Helper()
	for index, result := range results {
		if result.err != nil || result.value != want {
			t.Fatalf("writer %d value=%q err=%v, want %q", index, result.value, result.err, want)
		}
	}
}

func assertPhase5SuccessfulValues(t *testing.T, results []phase5RaceResult, want string) {
	t.Helper()
	for index, result := range results {
		if result.err == nil && result.value != want {
			t.Fatalf("successful writer %d value=%q, want %q", index, result.value, want)
		}
	}
}

func phase5ResultCounts(t *testing.T, results []phase5RaceResult, allowedCode string) (int, int) {
	t.Helper()
	var success, allowed int
	for _, result := range results {
		if result.err == nil {
			success++
			continue
		}
		if Code(result.err) != allowedCode {
			t.Fatalf("unexpected concurrency error code=%q err=%v", Code(result.err), result.err)
		}
		allowed++
	}
	return success, allowed
}

func phase5CountAllowed(t *testing.T, results []phase5RaceResult, allowedCodes ...string) (int, int) {
	t.Helper()
	allowedSet := make(map[string]struct{}, len(allowedCodes))
	for _, code := range allowedCodes {
		allowedSet[code] = struct{}{}
	}
	var success, rejected int
	for _, result := range results {
		if result.err == nil {
			success++
			continue
		}
		if _, ok := allowedSet[Code(result.err)]; !ok {
			t.Fatalf("unexpected concurrency error code=%q err=%v", Code(result.err), result.err)
		}
		rejected++
	}
	return success, rejected
}
