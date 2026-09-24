//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type durableSchedulePlans struct{ repository *store.PlanRepository }

type durableAcknowledgementPlans struct{ repository *store.PlanRepository }

func (source durableAcknowledgementPlans) Get(ctx context.Context, planID string) (generated.Plan, error) {
	stored, err := source.repository.GetPlan(ctx, planID)
	return stored.Plan, err
}
func (source durableAcknowledgementPlans) ValidateCurrent(ctx context.Context, plan generated.Plan) error {
	return (durableSchedulePlans{repository: source.repository}).ValidateCurrent(ctx, plan)
}

func (source durableSchedulePlans) Get(ctx context.Context, planID string) (store.PlanCommitResult, error) {
	return source.repository.GetPlan(ctx, planID)
}
func (source durableSchedulePlans) ValidateCurrent(ctx context.Context, plan generated.Plan) error {
	stored, err := source.repository.GetPlan(ctx, plan.PlanID)
	if err != nil || stored.Plan.PlanDigest != plan.PlanDigest {
		return errors.New("durable plan changed")
	}
	current, err := source.repository.CurrentRevision(ctx)
	if err != nil || current.StateRevision != plan.Binding.StateRevision || current.RecoveryEpoch != plan.Binding.RecoveryEpoch {
		return errors.New("durable plan revision changed")
	}
	return nil
}

type durableScheduleAuthorizer struct {
	evaluator *authorization.Evaluator
	calls     int
}

func (source *durableScheduleAuthorizer) AuthorizeScheduled(ctx context.Context, principalID string, plan generated.Plan) (generated.AuthorizationDecision, error) {
	source.calls++
	principal := identity.Principal{ID: principalID, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalPolicy}
	target := authorization.Target{Capability: plan.Operations[0].OperationType, ResourceKind: "execution-target", ResourceID: plan.Operations[0].TargetID}
	decision, err := source.evaluator.Authorize(ctx, principal, authorization.Request{Action: authorization.ActionExecute, Target: target, Plan: &plan, Branches: []authorization.Branch{authorization.BranchPreauthorized}})
	if err != nil || !decision.Allowed || decision.Branch == nil {
		return generated.AuthorizationDecision{}, errors.New("durable scheduled grant denied")
	}
	branch := string(*decision.Branch)
	return generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-scheduled-" + plan.PlanID, PrincipalID: principalID, Action: string(authorization.ActionExecute), TargetID: target.ResourceID, Allowed: true, Branch: &branch, ReasonCode: decision.ReasonCode, GrantRevision: decision.GrantRevision, RecoveryEpoch: decision.RecoveryEpoch, PlanDigest: plan.PlanDigest, DecidedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), Extensions: []generated.ContractExtension{}}, nil
}

type scheduleCredentialProfile struct{ scope store.GateAppliedProfile }

func (profile *scheduleCredentialProfile) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return profile.scope, nil
}

type scheduleCredentialResolver struct{ calls int }

func (resolver *scheduleCredentialResolver) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	resolver.calls++
	return credentialref.NewValue([]byte("schedule-backup-fixture-secret"))
}

type scheduleBackupAdapter struct{ calls int }

func (implementation *scheduleBackupAdapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, errors.New("scheduled backup bypassed credential boundary")
}
func (implementation *scheduleBackupAdapter) ExecuteBoundWithCredentials(_ context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	if len(values) != 1 || len(values[0].Bytes()) == 0 || binding.PlanID == "" || operation.AdapterID != "local.backup" {
		return adapter.Effect{}, errors.New("scheduled backup credential binding unavailable")
	}
	implementation.calls++
	return adapter.Effect{Status: "succeeded", ResultDigest: operation.ArtifactDigest, Changed: true, EffectObserved: true}, nil
}
func (*scheduleBackupAdapter) Verify(_ context.Context, operation adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: effect.Status == "succeeded" && effect.ResultDigest == operation.ArtifactDigest, Digest: effect.ResultDigest}, nil
}

type durableScheduleFixture struct {
	t                *testing.T
	ctx              context.Context
	now              time.Time
	path             string
	authority        *store.Store
	plans            *store.PlanRepository
	policies         *store.ScheduleRepository
	backups          *store.BackupRepository
	credentials      *store.CredentialRepository
	acknowledgements *store.AcknowledgementRepository
	acknowledger     *acknowledgement.Service
	attribution      audit.Attribution
	policy           generated.ScheduledJobPolicy
	policyDigest     string
	backupDigest     string
	point            store.PendingRecoveryPoint
	authorizer       *durableScheduleAuthorizer
	prerequisites    *schedulePrerequisiteReader
	profile          *scheduleCredentialProfile
	resolver         *scheduleCredentialResolver
	adapter          *scheduleBackupAdapter
	engine           *runengine.Engine
}

func scheduleTestDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func newDurableScheduleFixture(t *testing.T, action string) *durableScheduleFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	directory, err := os.MkdirTemp("/var/tmp", "vsk109-schedule-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "control.db")
	authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "schedule-acceptance", BuildVersion: "schedule-acceptance", Clock: func() time.Time { return now }, Filesystem: acceptanceFilesystem{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	fixture := &durableScheduleFixture{t: t, ctx: ctx, now: now, path: path, authority: authority, plans: store.NewPlanRepository(authority), policies: store.NewScheduleRepository(authority), backups: store.NewBackupRepository(authority), credentials: store.NewCredentialRepository(authority), acknowledgements: store.NewAcknowledgementRepository(authority), attribution: audit.Attribution{AuthenticatedPrincipalID: "human-109", AuthenticatedPrincipalMethod: "local-os-peer"}}
	fixture.seedBackupPolicy()
	fixture.activateSchedulePolicy(action)
	fixture.seedRecoveryQualification()
	fixture.seedCredentialAndGrant()
	fixture.composeEngine()
	return fixture
}

func (fixture *durableScheduleFixture) seedBackupPolicy() {
	repositoryID, encryption, recoveryKey := backupidentity.StandardRepository, "enc-a", "recovery-a"
	policy := generated.BackupPolicy{Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.2.0", PolicyID: "policy-a", OwnerID: "owner-a", SourceID: backupidentity.ControlDatabaseSource, SourceSelectors: []string{backupidentity.ControlDatabaseSelector}, ConsistencyHookID: "sqlite-online", RepositoryID: &repositoryID, RepositoryClass: "standard", ScheduleIntent: "daily", ExpectedBytes: 1024, ExpectedGrowthBytes: 1, MinimumFreeBytes: 1, EncryptionKeyReferenceID: &encryption, RecoveryKeyReferenceID: &recoveryKey, RetentionDays: 14, RestoreTargetID: "restore-a", Dependencies: []generated.BackupDependency{}, FunctionalTestRequired: true, FullPayloadIntervalHours: 24, FunctionalTestIntervalHours: 24, RecoveryEpoch: 0, Revision: 1}
	_, sum, err := stateexport.CanonicalJSON(policy)
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.backupDigest = "sha256:" + hex.EncodeToString(sum[:])
	_, err = fixture.backups.CreateBackupPolicyDraft(fixture.ctx, generated.BackupPolicyDraftRequest{Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: fixture.backupDigest, IdempotencyKey: "backup-policy-109", Policy: policy}, fixture.attribution)
	if err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *durableScheduleFixture) activateSchedulePolicy(action string) {
	operationType, target := "backup.local.create", "restore-a"
	if action == "backup-integrity-verify" {
		operationType, target = "backup.local.verify", "point-a"
	}
	policy := generated.ScheduledJobPolicy{Schema: generated.SchemaIDScheduledJobPolicy, SchemaVersion: "1.1.0", PolicyID: "schedule-" + action, Revision: 1, DeclarationID: "schedule-declaration-" + action, DeclarationRevision: 2, ActionKind: action, OperationType: operationType, AdapterID: "local.backup", ExactSourceIDs: []string{backupidentity.ControlDatabaseSource, "policy-a"}, ExactSubjectIDs: []string{"owner-a"}, ExactTargetIDs: []string{target}, MaximumWork: 1, CredentialReferenceIDs: []string{"enc-a"}, GrantRevision: 7, StateRevision: 3, RecoveryEpoch: 0, PolicyVersion: "1.0.0", RetentionRuleDigest: fixture.backupDigest, AnchorAt: fixture.now.Add(-time.Hour).Format(time.RFC3339), IntervalSeconds: 3600, WindowSeconds: 1800, CatchUp: "latest", Concurrency: "forbid", MaxAttempts: 1, InitialBackoffSeconds: 1, MaximumBackoffSeconds: 1, ExpiresAt: fixture.now.Add(24 * time.Hour).Format(time.RFC3339), Enabled: true}
	_, policyDigest, err := schedule.CanonicalPolicy(policy)
	if err != nil {
		fixture.t.Fatal(err)
	}
	draftID := "schedule-draft-" + strings.TrimPrefix(policyDigest, "sha256:")[:32]
	operation := generated.DeclarationOperation{Sequence: 1, OperationID: "activate-" + action, OperationType: "schedule.policy.activate", AdapterID: "core.schedule", TargetID: draftID, InputDigest: policyDigest, ArtifactDigest: policyDigest, Idempotent: true}
	reason := scheduleTestDigest("schedule-activation-reason-" + action)
	document := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: policy.DeclarationID, DeclarationType: "scheduled-policy", Revision: 1, StateRevision: 2, RecoveryEpoch: 0, Status: "draft", Operations: []generated.DeclarationOperation{operation}, CreatedAt: fixture.now.Format(time.RFC3339), CreatedBy: "human-109", AgentSessionID: "session-109", Extensions: []generated.ContractExtension{{Name: "x-scheduled-policy", ValueDigest: policyDigest}}}
	document.ContentDigest = acceptanceDeclarationDigest(document, reason)
	created, err := store.NewDeclarationRepository(fixture.authority).CreateRevision(fixture.ctx, store.DeclarationRevisionRequest{Document: document, ReasonDigest: reason, Expected: store.RevisionToken{StateRevision: 1, RecoveryEpoch: 0}, KeyDigest: scheduleTestDigest("schedule-declaration-key-" + action), RequestDigest: scheduleTestDigest("schedule-declaration-request-" + action), Attribution: fixture.attribution})
	if err != nil {
		fixture.t.Fatal(err)
	}
	draft, err := fixture.policies.StageDraft(fixture.ctx, policy, fixture.attribution)
	if err != nil || draft.DraftID != draftID {
		fixture.t.Fatalf("schedule draft=%+v err=%v", draft, err)
	}
	desired := created.Document
	desired.Revision, desired.StateRevision, desired.Status = 2, 3, "committed"
	readable := "activate scheduled backup policy\n"
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: policy.DeclarationID, Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 2, StateRevision: 3, DeclarationRevision: 2, ObservationFingerprint: scheduleTestDigest("activation-observation-" + action), TargetDigest: scheduleTestDigest("activation-target-" + action), ReasonDigest: reason, PolicyVersion: "1.0.0", ToolVersion: "schedule-acceptance", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: operation.OperationID, OperationType: operation.OperationType, AdapterID: operation.AdapterID, ExecutorID: "executor-central", TargetID: operation.TargetID, InputDigest: operation.InputDigest, ArtifactDigest: operation.ArtifactDigest, Idempotent: true}}, Status: "planned", Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: fixture.now.Format(time.RFC3339), ExpiresAt: fixture.now.Add(30 * time.Minute).Format(time.RFC3339), ReadableDigest: scheduleTestDigest(readable), Extensions: document.Extensions}
	preimage, _ := json.Marshal(plan)
	plan.PlanDigest = scheduleTestDigest(string(preimage))
	plan.PlanID = "plan-" + strings.TrimPrefix(plan.PlanDigest, "sha256:")[:32]
	canonical, _ := json.Marshal(plan)
	committed, err := fixture.plans.CommitDeclarationAndPlan(fixture.ctx, store.PlanCommitRequest{Plan: plan, DesiredDeclaration: desired, SourceDeclarationRevision: 1, ReasonDigest: reason, CanonicalBytes: canonical, Readable: readable, Expected: store.RevisionToken{StateRevision: 2, RecoveryEpoch: 0}, KeyDigest: scheduleTestDigest("activation-plan-key-" + action), RequestDigest: scheduleTestDigest("activation-plan-request-" + action), Attribution: fixture.attribution})
	if err != nil {
		fixture.t.Fatal(err)
	}
	approved := authorizeAcceptancePlan(fixture.t, fixture.ctx, fixture.authority, committed.Plan, fixture.attribution, fixture.now)
	acknowledger, err := acknowledgement.NewService(acknowledgement.Config{Repository: fixture.acknowledgements, Plans: durableAcknowledgementPlans{fixture.plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: func() time.Time { return fixture.now }})
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.acknowledger = acknowledger
	core, err := runengine.NewSchedulePolicyEffect(fixture.policies, fixture.acknowledgements)
	if err != nil {
		fixture.t.Fatal(err)
	}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(fixture.authority), Plans: durableSchedulePlans{fixture.plans}, Admission: runengine.NewAdmissionGate(acknowledger, func() time.Time { return fixture.now }), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{Schedule: core}, Clock: func() time.Time { return fixture.now }, ExecutionContext: fixture.ctx})
	if err != nil {
		fixture.t.Fatal(err)
	}
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-activate-" + action, PrincipalID: "human-109", Action: "execute", TargetID: draftID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, RecoveryEpoch: 0, PlanDigest: committed.Plan.PlanDigest, DecidedAt: fixture.now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	human := "human-109"
	run, err := engine.Submit(fixture.ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: committed.Plan.PlanID, PlanDigest: committed.Plan.PlanDigest, RecoveryEpoch: 0, IdempotencyKey: "activate-" + action, Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: human, AuthenticatedPrincipalMethod: "local-os-peer", ResponsibleHumanPrincipalID: &human}})
	if err != nil || run.Status != "succeeded" {
		fixture.t.Fatalf("durable activation run=%+v err=%v", run, err)
	}
	fixture.policy, fixture.policyDigest = policy, policyDigest
}

func (fixture *durableScheduleFixture) seedRecoveryQualification() {
	point, receipt := seedAcceptancePointAtRevision(fixture.t, fixture.ctx, fixture.backups, fixture.backupDigest, "point-a", 0, fixture.now, 3, backupidentity.StandardRepository, "standard")
	if err := fixture.backups.AdvanceLocalLastGood(fixture.ctx, receipt, store.RevisionToken{StateRevision: 3, RecoveryEpoch: 0}, ""); err != nil {
		fixture.t.Fatal(err)
	}
	fixture.point = point
}

func (fixture *durableScheduleFixture) seedCredentialAndGrant() {
	database, err := sql.Open("sqlite3", fixture.path)
	if err != nil {
		fixture.t.Fatal(err)
	}
	defer database.Close()
	target := fixture.policy.ExactTargetIDs[0]
	activated := fixture.now.Format(time.RFC3339)
	verified, _ := json.Marshal([]string{"local.backup"})
	if _, err := database.ExecContext(fixture.ctx, `INSERT INTO credential_reference_versions(version_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at) VALUES(?,?,?,?,?,'native-systemd','v1',?,'active',3,0,?,?,'credential-declaration',1,'credential-plan',?,'credential-run','credential-step','credential-lease','human-109',?)`, "credential-version-enc-a", "enc-a", "local.backup", "backup-encryption", target, scheduleTestDigest("credential-fingerprint"), activated, verified, scheduleTestDigest("credential-plan"), activated); err != nil {
		fixture.t.Fatal(err)
	}
	if _, err := database.ExecContext(fixture.ctx, `INSERT INTO effective_authorization_principals(principal_id,principal_kind,status,grant_revision,created_at,updated_at) VALUES('schedule-runner','policy','active',7,?,?)`, activated, activated); err != nil {
		fixture.t.Fatal(err)
	}
	if _, err := database.ExecContext(fixture.ctx, `INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES('grant-schedule-runner','schedule-runner','automation','execute',?,'execution-target',?,'preauthorized',7,'active',?,?)`, fixture.policy.OperationType, target, activated, activated); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *durableScheduleFixture) composeEngine() {
	fixture.authorizer = &durableScheduleAuthorizer{evaluator: authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(fixture.authority))}
	fixture.prerequisites = &schedulePrerequisiteReader{authority: fixture.authority, policies: fixture.policies, gates: store.NewGateRepository(fixture.authority), backups: fixture.backups, offsite: recovery.SQLOffsiteSourceReader{Local: fixture.backups, Offsite: store.NewOffsiteRepository(fixture.authority)}, clock: func() time.Time { return fixture.now }, backupReady: true, auditReady: false}
	admission := scheduleAdmission{repository: fixture.policies, declarations: store.NewDeclarationRepository(fixture.authority), authorizer: fixture.authorizer, principalID: "schedule-runner", prerequisites: fixture.prerequisites}
	fixture.profile = &scheduleCredentialProfile{scope: store.GateAppliedProfile{ProfileID: "profile-backup", ProfileVersion: "1.0.0", PolicyID: "profile-policy", PolicyVersion: "1.0.0", Capabilities: []string{"credential.native.read"}, StateRevision: 3, RecoveryEpoch: 0}}
	fixture.resolver, fixture.adapter = &scheduleCredentialResolver{}, &scheduleBackupAdapter{}
	registry := adapter.NewRegistry()
	if err := registry.Register("local.backup", fixture.adapter); err != nil {
		fixture.t.Fatal(err)
	}
	if err := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: "local.backup", ProfileID: "profile-backup", CapabilityID: "credential.native.read", Enabled: true}, fixture.resolver); err != nil {
		fixture.t.Fatal(err)
	}
	credentialStep := &runengine.CredentialStep{Bindings: fixture.credentials, Resolvers: registry, Profiles: fixture.profile, Plans: durableSchedulePlans{fixture.plans}, ScheduledPlans: admission, Clock: func() time.Time { return fixture.now }}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(fixture.authority), Plans: durableSchedulePlans{fixture.plans}, Admission: runengine.NewAdmissionGate(nil, func() time.Time { return fixture.now }), Adapters: registry, SecretGate: scheduledBackupLiveGate{admission: admission, fallback: runengine.UnavailableGateVerifier{}, clock: func() time.Time { return fixture.now }}, CredentialStep: credentialStep, Clock: func() time.Time { return fixture.now }, ExecutionContext: fixture.ctx, Scheduled: admission})
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.engine = engine
}

func (fixture *durableScheduleFixture) planOccurrence() (generated.Plan, generated.AuthorizationDecision, generated.ScheduledJob) {
	targetDigest, err := schedule.ExactTargetDigest(fixture.policy)
	if err != nil {
		fixture.t.Fatal(err)
	}
	job, err := fixture.policies.ClaimOccurrence(fixture.ctx, store.OccurrenceClaim{Policy: fixture.policy, ScheduledAt: fixture.now, WindowClosesAt: fixture.now.Add(30 * time.Minute), OccurrenceToken: "occurrence-token", TargetDigest: targetDigest, IdempotencyKey: "occurrence-key", Expected: store.RevisionToken{StateRevision: 3, RecoveryEpoch: 0}})
	if err != nil {
		fixture.t.Fatal(err)
	}
	leaseID := job.JobID + "-lease-1"
	if err := fixture.policies.AcquireOccurrenceLease(fixture.ctx, job.JobID, leaseID, "schedule:"+fixture.policy.PolicyID, fixture.now.Add(30*time.Minute)); err != nil {
		fixture.t.Fatal(err)
	}
	occurrenceDigest, err := fixture.policies.ScheduledOccurrenceDigest(fixture.ctx, job.JobID)
	if err != nil {
		fixture.t.Fatal(err)
	}
	planner, err := planengine.NewScheduledService(fixture.plans, func() time.Time { return fixture.now }, "schedule-acceptance", "1.0.0", "executor-central", scheduledActionResolver{backups: fixture.backups, audit: fixture.authority, credentials: fixture.credentials, policies: fixture.policies})
	if err != nil {
		fixture.t.Fatal(err)
	}
	created, err := planner.CreateScheduled(fixture.ctx, planengine.ScheduledRequest{Policy: fixture.policy, PolicyDigest: fixture.policyDigest, JobID: job.JobID, OccurrenceDigest: occurrenceDigest, ObservationFingerprint: scheduleTestDigest("scheduled-observation"), Attempt: 1, ScheduledAt: fixture.now, WindowClosesAt: fixture.now.Add(30 * time.Minute), Expected: store.RevisionToken{StateRevision: 3, RecoveryEpoch: 0}})
	if err != nil {
		fixture.t.Fatal(err)
	}
	decision, err := fixture.authorizer.AuthorizeScheduled(fixture.ctx, "schedule-runner", created.Plan)
	if err != nil {
		fixture.t.Fatal(err)
	}
	runID := "run-" + strings.TrimPrefix(scheduleTestDigest(created.Plan.PlanID+"/attempt-1"), "sha256:")[:32]
	if err := fixture.policies.AppendAttempt(fixture.ctx, store.ScheduledAttempt{AttemptID: job.JobID + "-attempt-1", JobID: job.JobID, Attempt: 1, Status: "running", PlanID: created.Plan.PlanID, RunID: runID, RecordedAt: fixture.now}); err != nil {
		fixture.t.Fatal(err)
	}
	running, err := fixture.policies.TransitionOccurrence(fixture.ctx, job.JobID, "queued", "running", "attempt-started", &created.Plan.PlanID, &runID)
	if err != nil {
		fixture.t.Fatal(err)
	}
	return created.Plan, decision, running
}

func (fixture *durableScheduleFixture) submit(plan generated.Plan, decision generated.AuthorizationDecision, suffix string) (generated.Run, error) {
	return fixture.engine.Submit(fixture.ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: 0, IdempotencyKey: "scheduled-" + suffix, Extensions: []generated.ContractExtension{}}, Authorization: decision, Attribution: audit.Attribution{AuthenticatedPrincipalID: "schedule-runner", AuthenticatedPrincipalMethod: "local-os-peer", ResponsibleHumanPrincipalID: func() *string { value := "human-109"; return &value }()}})
}

func TestScheduledBackupActionsUseDurableProductionAuthority(t *testing.T) {
	for _, action := range []string{"backup-create", "backup-integrity-verify"} {
		t.Run(action, func(t *testing.T) {
			fixture := newDurableScheduleFixture(t, action)
			plan, decision, _ := fixture.planOccurrence()
			run, err := fixture.submit(plan, decision, action)
			if err != nil || run.Status != "succeeded" || fixture.adapter.calls != 1 || fixture.resolver.calls != 1 || fixture.authorizer.calls < 2 {
				t.Fatalf("run=%+v adapter=%d resolver=%d authorization=%d err=%v", run, fixture.adapter.calls, fixture.resolver.calls, fixture.authorizer.calls, err)
			}
		})
	}
}

func TestScheduledBackupPostPlanAuthorityChangesFailBeforeEffect(t *testing.T) {
	for _, rejection := range []string{"state", "lease", "grant", "qualification", "credential-capability"} {
		t.Run(rejection, func(t *testing.T) {
			fixture := newDurableScheduleFixture(t, "backup-create")
			plan, decision, job := fixture.planOccurrence()
			database, err := sql.Open("sqlite3", fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			switch rejection {
			case "state":
				_, err = database.ExecContext(fixture.ctx, `UPDATE system_meta SET state_revision=4 WHERE id=1`)
			case "lease":
				err = fixture.policies.ReleaseOccurrenceLease(fixture.ctx, job.JobID, job.JobID+"-lease-1")
			case "grant":
				_, err = database.ExecContext(fixture.ctx, `UPDATE effective_authorization_grants SET status='revoked',grant_revision=8,updated_at=? WHERE grant_id='grant-schedule-runner'`, fixture.now.Format(time.RFC3339))
			case "qualification":
				fixture.prerequisites.backupReady = false
			case "credential-capability":
				fixture.profile.scope.Capabilities = []string{}
			}
			if err != nil {
				t.Fatal(err)
			}
			run, submitErr := fixture.submit(plan, decision, rejection)
			if submitErr == nil && run.Status == "succeeded" || fixture.adapter.calls != 0 {
				t.Fatalf("rejection=%s run=%+v adapter=%d err=%v", rejection, run, fixture.adapter.calls, submitErr)
			}
		})
	}
}

func TestScheduledAuditRemainsUnavailableWithoutProductionDependencies(t *testing.T) {
	policy := generated.ScheduledJobPolicy{ActionKind: "audit-checkpoint-export"}
	if statuses, err := (&schedulePrerequisiteReader{auditReady: false, clock: time.Now}).Current(context.Background(), schedule.Requirements(policy)); err == nil || len(statuses) != 0 {
		t.Fatalf("incomplete audit composition became available: statuses=%+v err=%v", statuses, err)
	}
}
