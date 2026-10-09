//go:build linux

package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/sys/unix"
)

// Only systemd/process/enrollment-policy OS reads and restart are substituted.
// The existing fixture then executes its loopback host action using the actual
// native resolver returned by normal credential lifecycle activation below.
func TestNativeRestartLifecycleAcceptance(t *testing.T) {
	for _, mode := range []string{"success", "wrong-attempt", "source-drift", "invocation-drift", "epoch-drift", "revoked-authority", "expired-lease"} {
		t.Run(mode, func(t *testing.T) {
			hostActionAcceptance(t, "success", hostActionAcceptanceHooks{EnrollmentOnly: mode != "success", Enrollment: func(t *testing.T, f hostActionEnrollmentFixture) adapter.CredentialResolver {
				return nativeRestartEnrollment(t, f, mode)
			}})
		})
	}
}

type nativeRestartSoftwareOS struct {
	advance                                func(time.Duration)
	t                                      *testing.T
	source, loaded, journal, machine, name string
	uid, gid                               uint32
	unit                                   nativecredential.AppliedUnitSnapshot
	db                                     *sql.DB
	expire                                 bool
}

func (o *nativeRestartSoftwareOS) ObserveAppliedUnit(context.Context, string) (nativecredential.AppliedUnitSnapshot, error) {
	return o.unit, nil
}
func (o *nativeRestartSoftwareOS) Restart(context.Context, string) (nativecredential.RestartReceipt, error) {
	return nativecredential.RestartReceipt{}, fmt.Errorf("synchronous restart forbidden")
}
func (o *nativeRestartSoftwareOS) EnqueueRestart(_ context.Context, unit string) error {
	if unit != o.unit.UnitName {
		return fmt.Errorf("wrong unit")
	}
	file, err := os.OpenFile(o.journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(unit + "\n")
	if err == nil {
		err = file.Sync()
	}
	return err
}
func (o *nativeRestartSoftwareOS) Probe(_ context.Context, r nativecredential.AccessProbeRequest) (nativecredential.AccessProbeResult, error) {
	if r.UnitName != o.unit.UnitName || r.CredentialName != o.name || r.MainPID != int(o.unit.MainPID) || r.BootID != o.unit.BootID {
		return nativecredential.AccessProbeResult{}, fmt.Errorf("wrong process")
	}
	if r.UID != o.uid || r.GID != o.gid {
		return nativecredential.AccessProbeResult{Status: nativecredential.AccessProbeDenied}, nil
	}
	var s unix.Stat_t
	if err := unix.Stat(filepath.Join(o.loaded, o.name), &s); err != nil {
		return nativecredential.AccessProbeResult{}, err
	}
	return nativecredential.AccessProbeResult{Status: nativecredential.AccessProbeOpened, NamespaceDevice: 1, NamespaceInode: 2, Device: uint64(s.Dev), Inode: s.Ino, OwnerUID: s.Uid, OwnerGID: s.Gid, Mode: s.Mode}, nil
}
func (o *nativeRestartSoftwareOS) process(_ context.Context, u nativecredential.AppliedUnitSnapshot, _ credentialref.NativeConsumerBinding) (nativecredential.ProcessIdentity, error) {
	if o.expire {
		o.expire = false
		o.advance(2 * time.Minute)
	}
	return nativecredential.ProcessIdentity{MainPID: u.MainPID, StartTicks: u.ExecMainStartMonotonicUSec, UID: o.uid, GID: o.gid, NamespaceDevice: 1, NamespaceInode: 2}, nil
}
func (o *nativeRestartSoftwareOS) policy() ([]byte, error) {
	return json.Marshal(map[string]any{"version": 1, "machine_id": o.machine, "units": []string{o.unit.UnitName}, "probes": []any{map[string]any{"unit_name": o.unit.UnitName, "credential_name": o.name, "uid": o.uid, "gid": o.gid}, map[string]any{"unit_name": o.unit.UnitName, "credential_name": o.name, "uid": o.uid + 10000, "gid": o.gid + 10000}}})
}

func nativeRestartEnrollment(t *testing.T, f hostActionEnrollmentFixture, mode string) adapter.CredentialResolver {
	t.Helper()
	ctx := f.Context
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.DB.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	refs := store.NewCredentialRepository(f.Authority)
	revisions := store.NewPlanRepository(f.Authority)
	policy := store.NewEffectiveAuthorizationRepository(f.Authority)
	evaluator := authorization.NewEvaluator(policy)
	principal := identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	grant := func(id, action, capability, kind, target string, branch any) {
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, action, capability, kind, target, branch)
	}
	grant("native-author", "author", "credential.lifecycle.author", "credential-reference", "action-key", nil)
	grant("native-stage", "execute", "credential.stage", "execution-target", "synthetic-host", "human")
	grant("native-activate", "execute", "credential.activate", "execution-target", "synthetic-host", "human")
	grant("native-ack", "acknowledge", "plan.acknowledge", "plan-target", "synthetic-host", "human")
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	source := filepath.Join(root, "ciphertext")
	loaded := filepath.Join(root, "loaded")
	for _, dir := range []string{source, loaded} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	name := credentialref.LoadedNameForVersion("host-action", "action-key", "version-a")
	ciphertext := []byte("synthetic encrypted bytes at the OS boundary")
	if err := os.WriteFile(filepath.Join(source, name), ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid = 1001
	}
	if gid == 0 {
		gid = 1001
	}
	o := &nativeRestartSoftwareOS{t: t, source: source, loaded: loaded, journal: filepath.Join(root, "restart-journal"), machine: strings.TrimSpace(string(machine)), name: name, uid: uid, gid: gid, db: f.DB, advance: f.AdvanceClock}
	o.unit = nativecredential.AppliedUnitSnapshot{UnitName: "synthetic-control.service", MachineID: o.machine, BootID: "00000000-0000-0000-0000-000000000001", InvocationID: strings.Repeat("a", 32), ActiveState: "active", MainPID: uint32(os.Getpid()), ExecMainStartMonotonicUSec: 1, User: strconv.FormatUint(uint64(uid), 10), Group: strconv.FormatUint(uint64(gid), 10), EncryptedSources: []nativecredential.CredentialSource{{ID: name, AbsolutePath: filepath.Join(source, name)}}}
	native, err := nativecredential.NewNativeLifecycleVerifierWithObservation(o, o, source, uint32(os.Geteuid()), nativecredential.NativeOSObservation{PolicyBytes: o.policy, Process: o.process})
	if err != nil {
		t.Fatal(err)
	}
	observer, err := nativecredential.NewLoadedObserver(native, refs)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := nativecredential.NewResolver(loaded, uint32(os.Geteuid()), refs, observer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Close() })
	lifecycle, err := api.NewCredentialLifecycleService(refs, revisions, f.Declarations, evaluator, nativeRestartPlanner{references: refs, native: native})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterCredentialLifecycleOperation(f.App, api.CredentialLifecycleOperations{Lifecycle: lifecycle, Results: f.Results}); err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{HostActionCredentials: refs, Repository: revisions, Observations: observations, Clock: f.Clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	acknowledger, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(f.Authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: evaluator, Clock: f.Clock})
	if err != nil {
		t.Fatal(err)
	}
	gate := hostActionGate{targets: store.NewHostActionRepository(f.Authority), credentials: refs, allowed: []string{f.DestinationIdentity}}
	core, err := runengine.NewCoreCredentialEffect(refs, store.NewAcknowledgementRepository(f.Authority), gate, nativeLifecycleRunVerifier{native}, runengine.UnavailableCredentialRecoveryVerifier{}, f.Clock)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(f.Authority), Plans: plans, Admission: runengine.NewAdmissionGate(acknowledger, f.Clock), Adapters: adapter.NewRegistry(), CredentialCore: core, Clock: f.Clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterRunOperations(f.App, api.RunOperationConfig{Runs: engine, Plans: plans, Acknowledgements: acknowledger, Results: f.Results, Authorization: api.EffectiveAuthorizationConfig{Authorizer: evaluator, Recorder: policy, Clock: f.Clock}}); err != nil {
		t.Fatal(err)
	}
	request := func(path string, input any) (int, []byte) {
		t.Helper()
		raw, _ := json.Marshal(input)
		req := httptest.NewRequest("POST", path, bytes.NewReader(raw)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		f.App.ServeHTTP(response, req)
		return response.Code, response.Body.Bytes()
	}
	current := func() store.RevisionToken {
		t.Helper()
		v, err := revisions.CurrentRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	inputImport := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: current().StateRevision, RecoveryEpoch: current().RecoveryEpoch, IdempotencyKey: "native-import", ReferenceID: "action-key", ConsumerID: "host-action", PurposeID: "host-action-ssh", TargetID: "synthetic-host", ResolverID: "native-systemd", MaterialVersion: "version-a"}
	inputImport.TargetDigest = credentialref.ImportTargetDigest(inputImport)
	imported, err := refs.PutImportDraft(ctx, store.CredentialImportDraftRequest{Input: inputImport, DraftID: "native-import", CiphertextName: name, CiphertextFingerprint: hostaction.BytesDigest(ciphertext), Expected: current(), Attribution: nativeRestartAttribution(), KeyDigest: hostaction.Digest("native-import-key"), RequestDigest: hostaction.Digest("native-import-request")})
	if err != nil {
		t.Fatal(err)
	}
	makeInput := func(action, key string) generated.CredentialLifecycleRequest {
		v := current()
		in := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", ExpectedStateRevision: v.StateRevision, RecoveryEpoch: v.RecoveryEpoch, IdempotencyKey: key, Action: action, ReferenceID: "action-key", ConsumerIDs: []string{"host-action"}, RequiredDeniedConsumerIDs: []string{}, MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "synthetic-host"}
		if action == "credential.stage" {
			in.DraftID = &imported.DraftID
		} else {
			in.RequiredDeniedConsumerIDs = []string{"denied-a"}
			in.NativeConsumers = &[]generated.CredentialNativeConsumer{{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "host-action", TargetID: in.TargetID, HostMachineID: o.machine, UnitName: o.unit.UnitName, ServiceUID: int64(uid), ServiceGID: int64(gid), ProfileID: "synthetic-profile", RoleID: "controller"}}
			in.NativeDeniedReaders = &[]generated.CredentialNativeDeniedReader{{Schema: generated.SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "denied-a", TargetID: in.TargetID, HostMachineID: o.machine, ReaderUID: int64(uid + 10000), ReaderGID: int64(gid + 10000), ProfileID: "synthetic-profile", RoleID: "denied"}}
			in.HostActionConsole = &generated.HostActionCredentialConfirmation{Schema: generated.SchemaIDHostActionCredentialConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: f.TargetDigest, HostIdentityDigest: f.DestinationIdentity, TargetRevision: 1, NativeConsumerMachineID: o.machine}
		}
		in.TargetDigest = credentialref.LifecycleTargetDigest(in)
		return in
	}
	draftPlan := func(in generated.CredentialLifecycleRequest) generated.Plan {
		t.Helper()
		in.TargetDigest = credentialref.LifecycleTargetDigest(in)
		status, raw := request("/api/v1/credential-lifecycle-drafts", in)
		if status >= 300 {
			t.Fatalf("draft %s failed %d: %s", in.Action, status, raw)
		}
		var envelope struct {
			Data generated.CredentialLifecycleSubmission `json:"data"`
		}
		if json.Unmarshal(raw, &envelope) != nil {
			t.Fatal("invalid draft")
		}
		decl, err := f.Declarations.Get(ctx, envelope.Data.ChangeID, 1)
		if err != nil {
			t.Fatal(err)
		}
		fp, err := observations.CurrentFingerprint(ctx, decl.DeclarationID, decl.Operations)
		if err != nil {
			t.Fatal(err)
		}
		v := current()
		made, err := plans.Create(ctx, planengine.AuthorScope{PrincipalID: principal.ID, PrincipalMethod: principal.Method, AgentSessionID: "native-session"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: decl.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: v.StateRevision, RecoveryEpoch: v.RecoveryEpoch, ObservationFingerprint: fp, IdempotencyKey: "plan-" + in.IdempotencyKey, Extensions: decl.Extensions})
		if err != nil {
			t.Fatal(err)
		}
		return made.Plan
	}
	acknowledge := func(p generated.Plan, key string) {
		t.Helper()
		human := identity.Principal{ID: "operator-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
		card, err := acknowledger.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "nonce-" + key}, p.PlanID)
		if err != nil {
			t.Fatal(err)
		}
		hostActionAcceptanceSlackApproval(t, acknowledger, card)
	}
	execute := func(p generated.Plan, key string) generated.Run {
		t.Helper()
		acknowledge(p, key)
		_, raw := request("/api/v1/plans/"+p.PlanID+"/execute", generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, RecoveryEpoch: p.Binding.RecoveryEpoch, IdempotencyKey: key, Extensions: []generated.ContractExtension{}})
		var persisted []byte
		if err := f.DB.QueryRow(`SELECT canonical_bytes FROM plan_runs WHERE plan_id=?`, p.PlanID).Scan(&persisted); err != nil {
			t.Fatalf("no persisted run: %v response=%s", err, raw)
		}
		var run generated.Run
		if json.Unmarshal(persisted, &run) != nil {
			t.Fatal("invalid run")
		}
		return run
	}
	stage := execute(draftPlan(makeInput("credential.stage", "native-stage")), "native-stage-run")
	if stage.Status != "succeeded" {
		t.Fatalf("stage=%s", stage.Status)
	}
	stepBinding := func() credentialref.StepBinding {
		v := current()
		return credentialref.StepBinding{OperationID: "native-use", AdapterID: "host-action", TargetID: "synthetic-host", ReferenceID: "action-key", ConsumerID: "host-action", PurposeID: "host-action-ssh", MaterialVersion: "version-a", ResolverID: "native-systemd", StateRevision: v.StateRevision, RecoveryEpoch: v.RecoveryEpoch}
	}
	if value, err := resolver.Resolve(ctx, stepBinding()); err == nil {
		value.Close()
		t.Fatal("unverified staged credential resolved")
	}
	first := execute(draftPlan(makeInput("credential.activate", "native-first")), "native-first-run")
	if first.Status != "partial" {
		t.Fatalf("restart intent not partial: %s", first.Status)
	}
	if err := engine.Startup(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(o.journal)
	if err != nil || string(before) != o.unit.UnitName+"\n" {
		var n int
		_ = f.DB.QueryRow(`SELECT COUNT(*) FROM plan_run_steps WHERE run_id=? AND native_restart_pending_bytes IS NOT NULL`, first.RunID).Scan(&n)
		t.Fatalf("restart journal missing: %v pending=%d run=%+v", err, n, first)
	}
	if _, err := refs.ReadNativeRestartPending(ctx, first.RunID, first.Steps[0].StepID); err != nil {
		t.Fatal("pending intent missing", err)
	}
	if err := os.WriteFile(filepath.Join(loaded, name), f.Key, 0400); err != nil {
		t.Fatal(err)
	}
	var mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		t.Fatal(err)
	}
	o.unit.InvocationID = strings.Repeat("b", 32)
	o.unit.ExecMainStartMonotonicUSec = uint64(mono.Nano()/1000) + 1
	next := makeInput("credential.activate", "native-complete")
	next.NativeRestart = &generated.NativeRestartSelector{Schema: generated.SchemaIDNativeRestartSelector, SchemaVersion: "1.0.0", PriorRunID: first.RunID, PriorStepID: first.Steps[0].StepID}
	next.TargetDigest = credentialref.LifecycleTargetDigest(next)
	if mode == "wrong-attempt" {
		next.NativeRestart.PriorRunID = "unrelated-run"
		next.TargetDigest = credentialref.LifecycleTargetDigest(next)
		status, _ := request("/api/v1/credential-lifecycle-drafts", next)
		if status < 300 {
			t.Fatal("unrelated pending attempt accepted")
		}
		assertNativeRestartUnconsumed(t, f.DB, first.RunID, o.journal, before)
		return resolver
	}
	fresh := draftPlan(next)
	if mode == "epoch-drift" || mode == "revoked-authority" {
		acknowledge(fresh, "native-denied")
	}
	switch mode {
	case "source-drift":
		if err := os.WriteFile(filepath.Join(source, name), []byte("changed synthetic encrypted source bytes"), 0600); err != nil {
			t.Fatal(err)
		}
	case "invocation-drift":
		o.unit.InvocationID = strings.Repeat("c", 32)
	case "epoch-drift":
		exec(`UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`)
	case "revoked-authority":
		exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='native-activate'`)
	case "expired-lease":
		o.expire = true
	}
	if mode == "epoch-drift" || mode == "revoked-authority" {
		status, _ := request("/api/v1/plans/"+fresh.PlanID+"/execute", generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: fresh.PlanID, PlanDigest: fresh.PlanDigest, RecoveryEpoch: fresh.Binding.RecoveryEpoch, IdempotencyKey: "native-denied", Extensions: []generated.ContractExtension{}})
		if status < 300 {
			t.Fatal("stale authority accepted")
		}
		assertNativeRestartUnconsumed(t, f.DB, first.RunID, o.journal, before)
		return resolver
	}
	completed := execute(fresh, "native-complete-run")
	if mode == "expired-lease" {
		var expired int
		if err := f.DB.QueryRow(`SELECT COUNT(*) FROM target_execution_leases WHERE run_id=? AND expires_at<=?`, completed.RunID, f.Clock().UTC().Format(time.RFC3339)).Scan(&expired); err != nil || expired != 1 {
			t.Fatalf("denial did not exercise actual expired lease: %d %v", expired, err)
		}
	}
	if mode != "success" {
		if completed.Status == "succeeded" {
			t.Fatal("invalid completion succeeded")
		}
		assertNativeRestartUnconsumed(t, f.DB, first.RunID, o.journal, before)
		return resolver
	}
	if completed.Status != "succeeded" {
		t.Fatalf("completion=%s", completed.Status)
	}
	active, err := refs.GetActiveVersion(ctx, "action-key", 0)
	if err != nil || active.Status != "active" {
		t.Fatal("normal activation missing", err)
	}
	receipt, err := refs.ReadNativeLoadedReceipt(ctx, stepBinding())
	if err != nil || receipt.RunID != completed.RunID || receipt.Proof.InvocationID != o.unit.InvocationID {
		t.Fatal("durable loaded receipt missing", err)
	}
	value, err := resolver.Resolve(ctx, stepBinding())
	if err != nil {
		t.Fatal("native resolver blocked actual receipt", err)
	}
	value.Close()
	var oldStatus, consumed string
	if err := f.DB.QueryRow(`SELECT r.status,s.native_restart_consumed_run_id FROM plan_runs r JOIN plan_run_steps s ON s.run_id=r.run_id WHERE r.run_id=?`, first.RunID).Scan(&oldStatus, &consumed); err != nil || oldStatus != "partial" || consumed != completed.RunID {
		t.Fatal("old attempt rewritten or unconsumed", err)
	}
	if _, err := refs.ReadNativeRestartPending(ctx, first.RunID, first.Steps[0].StepID); err == nil {
		t.Fatal("consumed pending reusable")
	}
	replay := makeInput("credential.activate", "native-replay")
	replay.NativeRestart = next.NativeRestart
	replay.TargetDigest = credentialref.LifecycleTargetDigest(replay)
	status, _ := request("/api/v1/credential-lifecycle-drafts", replay)
	if status < 300 {
		t.Fatal("active continuation replayed")
	}
	after, _ := os.ReadFile(o.journal)
	if !bytes.Equal(before, after) {
		t.Fatal("completion/replay repeated restart")
	}
	return resolver
}
func nativeRestartAttribution() audit.Attribution {
	return audit.Attribution{AuthenticatedPrincipalID: "operator-a", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod}
}
func assertNativeRestartUnconsumed(t *testing.T, db *sql.DB, runID, journal string, before []byte) {
	t.Helper()
	var active, receipts, consumed int
	for _, q := range []struct {
		sql string
		n   *int
	}{{`SELECT COUNT(*) FROM credential_reference_versions WHERE reference_id='action-key' AND status='active'`, &active}, {`SELECT COUNT(*) FROM credential_consumer_verifications WHERE reference_id='action-key'`, &receipts}, {`SELECT COUNT(*) FROM plan_run_steps WHERE run_id=? AND native_restart_consumed_run_id IS NOT NULL`, &consumed}} {
		var err error
		if strings.Contains(q.sql, "?") {
			err = db.QueryRow(q.sql, runID).Scan(q.n)
		} else {
			err = db.QueryRow(q.sql).Scan(q.n)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if active != 0 || receipts != 0 || consumed != 0 {
		t.Fatalf("denial persisted authority: active=%d receipts=%d consumed=%d", active, receipts, consumed)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM plan_runs WHERE run_id=?`, runID).Scan(&status); err != nil || status != "partial" {
		t.Fatal("prior partial run changed", err)
	}
	after, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("denial repeated restart", err)
	}
}
