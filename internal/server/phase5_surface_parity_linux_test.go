package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/cli"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type phase5ParityFacts struct {
	GateID, GateStatus, GateReason                 string
	BackupStatus, BackupReason, RecoveryPoint      string
	AuditStatus, AuditReason                       string
	RestorePoint, RestorePlan, RestoreStatus       string
	RestoreReason                                  string
	SchedulePolicy, ScheduleStatus, ScheduleReason string
	StateRevision, RecoveryEpoch                   int64
}

type phase5ParityFile struct{ content []byte }

func (file phase5ParityFile) Read(context.Context, string, int64) ([]byte, error) {
	return append([]byte(nil), file.content...), nil
}

type phase5ParityControl struct {
	*Operations
	client  localapi.Client
	profile serverconfig.Profile
}

func (control *phase5ParityControl) GetGate(ctx context.Context, _ string, gateID string) (localapi.TypedResponse[generated.GateView], error) {
	return control.client.GetGate(ctx, control.profile, gateID)
}
func (control *phase5ParityControl) BackupStatus(ctx context.Context, _ string) (localapi.TypedResponse[generated.BrowserBackupStatusData], error) {
	return control.client.BackupStatus(ctx, control.profile)
}
func (control *phase5ParityControl) VerifyAudit(ctx context.Context, _ string) (localapi.TypedResponse[generated.BrowserAuditVerificationData], error) {
	return control.client.VerifyAudit(ctx, control.profile)
}
func (control *phase5ParityControl) PlanRestore(ctx context.Context, _ string, input generated.RestoreRequest) (localapi.TypedResponse[generated.RestoreBinding], error) {
	return control.client.PlanRestore(ctx, control.profile, input)
}
func (control *phase5ParityControl) InspectScheduledPolicy(ctx context.Context, _, policyID string) (localapi.TypedResponse[generated.BrowserScheduledJobPolicy], error) {
	return control.client.InspectScheduledPolicy(ctx, control.profile, policyID)
}

type phase5ParityReadAuthorizer struct{}

func (phase5ParityReadAuthorizer) AuthorizeRead(_ context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
	return authorization.ReadScope{PrincipalID: principal.ID, Capability: target.Capability, ResourceKind: target.ResourceKind, GrantRevision: 1, ScopeDigest: "sha256:" + strings.Repeat("d", 64)}, nil
}

type phase5ParityReads struct {
	*store.ReadRepository
	revision store.RevisionToken
}

func (reads phase5ParityReads) CurrentRevision(context.Context, authorization.ReadScope) (store.RevisionToken, error) {
	return reads.revision, nil
}

type phase5ParityEffective struct{}

func (phase5ParityEffective) Authorize(_ context.Context, principal identity.Principal, request authorization.Request) (authorization.Decision, error) {
	scope := authorization.EffectiveScope{PrincipalID: principal.ID, Action: request.Action, Capability: request.Target.Capability, ResourceKind: request.Target.ResourceKind, ResourceID: request.Target.ResourceID, Role: authorization.RoleInfrastructureAdmin, GrantRevision: 1, ScopeDigest: "sha256:" + strings.Repeat("e", 64)}
	return authorization.Decision{PrincipalID: principal.ID, Action: request.Action, Target: request.Target, Allowed: true, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, Scope: scope}, nil
}
func (phase5ParityEffective) RecordDecision(context.Context, authorization.DecisionRecord) error {
	return nil
}

type phase5ParityBackupDraft struct{}

func (phase5ParityBackupDraft) CreateBackupPolicyDraft(context.Context, generated.BackupPolicyDraftRequest, audit.Attribution) (generated.BackupPolicyDraftSubmission, error) {
	return generated.BackupPolicyDraftSubmission{}, errors.New("unused")
}

type phase5ParityRunPorts struct{}

func (phase5ParityRunPorts) Submit(context.Context, runengine.SubmitRequest) (generated.Run, error) {
	return generated.Run{}, errors.New("unused")
}
func (phase5ParityRunPorts) Existing(context.Context, generated.PlanReferenceRequest) (generated.Run, bool, error) {
	return generated.Run{}, false, errors.New("unused")
}
func (phase5ParityRunPorts) Get(context.Context, string) (generated.Run, error) {
	return generated.Run{}, errors.New("unused")
}
func (phase5ParityRunPorts) MutateAs(context.Context, string, generated.RunReferenceRequest, audit.Attribution) (generated.Run, error) {
	return generated.Run{}, errors.New("unused")
}
func (phase5ParityRunPorts) GetPlan(context.Context, string) (store.PlanCommitResult, error) {
	return store.PlanCommitResult{}, errors.New("unused")
}
func (phase5ParityRunPorts) Status(context.Context, string) (generated.Acknowledgement, error) {
	return generated.Acknowledgement{}, errors.New("unused")
}

type phase5ParityBackupStatus struct {
	data  generated.BackupStatusData
	point generated.BrowserRecoveryPoint
	token store.RevisionToken
}

func (status phase5ParityBackupStatus) ReadLocalBackupStatus(context.Context) (generated.BackupStatusData, error) {
	return status.data, nil
}
func (status phase5ParityBackupStatus) ReadLocalBackupStatusScoped(context.Context, authorization.ReadScope) (generated.BackupStatusData, error) {
	return status.data, nil
}
func (status phase5ParityBackupStatus) CurrentBackupRevision(context.Context, authorization.ReadScope) (store.RevisionToken, error) {
	return status.token, nil
}
func (status phase5ParityBackupStatus) ListRecoveryPoints(context.Context, authorization.ReadScope, string, int) ([]generated.BrowserRecoveryPoint, store.RevisionToken, error) {
	return []generated.BrowserRecoveryPoint{status.point}, status.token, nil
}

type phase5ParityAudit struct {
	verification generated.AuditVerificationData
}

func (phase5ParityAudit) ListAuditCheckpoints(context.Context) ([]generated.AuditCheckpoint, error) {
	return []generated.AuditCheckpoint{}, nil
}
func (phase5ParityAudit) ListAuditCheckpointsPageScoped(context.Context, authorization.ReadScope, store.RevisionToken, string, int) ([]generated.AuditCheckpoint, error) {
	return []generated.AuditCheckpoint{}, nil
}
func (auditRepo phase5ParityAudit) VerifyAuditHistory(context.Context, adapter.CheckpointReader) (generated.AuditVerificationData, error) {
	return auditRepo.verification, nil
}
func (phase5ParityAudit) ChainRange(context.Context, audit.EventID, audit.EventID) (audit.ChainRange, error) {
	return audit.ChainRange{}, errors.New("unused")
}

type phase5ParityRestoreOperations struct {
	binding generated.RestoreBinding
	status  generated.BrowserRestoreStatus
}

func (operations phase5ParityRestoreOperations) Plan(context.Context, generated.RestoreRequest, identity.Principal) (generated.RestoreBinding, error) {
	return operations.binding, nil
}
func (phase5ParityRestoreOperations) Run(context.Context, generated.RestoreRunRequest, identity.Principal) (generated.RestoreBinding, error) {
	return generated.RestoreBinding{}, errors.New("unused")
}
func (phase5ParityRestoreOperations) Verify(context.Context, generated.RestoreVerifyRequest, identity.Principal) (generated.RestoreVerification, error) {
	return generated.RestoreVerification{}, errors.New("unused")
}
func (operations phase5ParityRestoreOperations) Get(context.Context, string) (generated.BrowserRestoreStatus, error) {
	return operations.status, nil
}
func (operations phase5ParityRestoreOperations) List(_ context.Context, _ authorization.ReadScope, snapshot store.RevisionToken, _ string, _ int) ([]generated.BrowserRestoreStatus, store.RevisionToken, error) {
	return []generated.BrowserRestoreStatus{operations.status}, snapshot, nil
}
func (phase5ParityRestoreOperations) AuthorizationPlan(context.Context, string) (generated.Plan, error) {
	return generated.Plan{}, errors.New("unused")
}

type phase5ParityScheduleStore struct {
	policy generated.ScheduledJobPolicy
	token  store.RevisionToken
}

func (phase5ParityScheduleStore) StageDraft(context.Context, generated.ScheduledJobPolicy, audit.Attribution) (store.ScheduledPolicyDraft, error) {
	return store.ScheduledPolicyDraft{}, errors.New("unused")
}
func (fixture phase5ParityScheduleStore) GetActivePolicy(context.Context, string) (generated.ScheduledJobPolicy, error) {
	return fixture.policy, nil
}
func (fixture phase5ParityScheduleStore) ListActivePolicies(_ context.Context, _ authorization.ReadScope, snapshot store.RevisionToken, _ string, _ int) ([]generated.ScheduledJobPolicy, store.RevisionToken, error) {
	return []generated.ScheduledJobPolicy{fixture.policy}, snapshot, nil
}
func (phase5ParityScheduleStore) ListOccurrences(_ context.Context, _ authorization.ReadScope, snapshot store.RevisionToken, _ string, _ int) ([]generated.ScheduledJob, store.RevisionToken, error) {
	return []generated.ScheduledJob{}, snapshot, nil
}
func (fixture phase5ParityScheduleStore) CurrentScheduleRevision(context.Context) (schedule.Revision, error) {
	return schedule.Revision{StateRevision: fixture.token.StateRevision, RecoveryEpoch: fixture.token.RecoveryEpoch}, nil
}

type phase5ParityScheduleDispatch struct{}

func (phase5ParityScheduleDispatch) Dispatch(context.Context, schedule.DispatchRequest) (generated.ScheduledJob, error) {
	return generated.ScheduledJob{}, errors.New("unused")
}
func (phase5ParityScheduleDispatch) Cancel(context.Context, string) (generated.ScheduledJob, error) {
	return generated.ScheduledJob{}, errors.New("unused")
}

type phase5ParityScheduleRunner struct{}

func (phase5ParityScheduleRunner) Run(context.Context, generated.ScheduledJob, audit.Attribution) (generated.ScheduledJob, error) {
	return generated.ScheduledJob{}, errors.New("unused")
}

func TestPhase5SurfacesAgreeAndBrowserCannotReachProtectedEffects(t *testing.T) {
	runPhase5SurfaceParity(t)
}

func runPhase5SurfaceParity(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the acceptance fixture exercises the local Unix-socket transport")
	}
	const stateRevision, recoveryEpoch = int64(0), int64(0)
	token := store.RevisionToken{StateRevision: stateRevision, RecoveryEpoch: recoveryEpoch}
	digest := "sha256:" + strings.Repeat("a", 64)
	lastGood := "point-last-good"
	verifiedAt := "2026-09-24T05:30:00Z"
	recoveryPoint := generated.BrowserRecoveryPoint{Schema: generated.SchemaIDBrowserRecoveryPoint, SchemaVersion: "1.0.0", PointID: lastGood, SourceKind: "local", ProofClass: "live", ContentDigest: digest, ManifestDigest: digest, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: &verifiedAt, VerificationStatus: "verified", ReasonCode: "verified", RecoveryEpoch: recoveryEpoch}
	backupStatus := generated.BackupStatusData{Schema: generated.SchemaIDBackupStatusData, SchemaVersion: "1.3.0", Policies: []generated.BackupPolicy{}, Jobs: []generated.BackupJob{}, Verifications: []generated.BackupVerificationAttempt{}, LastGood: []generated.BackupLastGood{{Schema: generated.SchemaIDBackupLastGood, SchemaVersion: "1.1.0", RepositoryClass: "local", PointID: lastGood, VerificationID: "verification-a", ManifestDigest: digest, RecoveryEpoch: recoveryEpoch}}, Retirements: []generated.BackupLocalRetirementStatus{}, Offsite: []generated.BackupOffsiteStatus{}, RecoveryEpoch: recoveryEpoch}
	auditStatus := generated.AuditVerificationData{Schema: generated.SchemaIDAuditVerificationData, SchemaVersion: "1.1.0", Status: "degraded", InstanceID: "instance-a", RecoveryEpoch: recoveryEpoch, LocalDigest: digest, IndependentMatch: false, LastAnchoredSequence: 0, ReasonCode: "no-independent-anchor", PreAnchor: false}
	restoreRequest, restoreBinding := phase5ParityRestore(t, digest, stateRevision, recoveryEpoch, lastGood)
	restoreStatus := generated.BrowserRestoreStatus{Schema: generated.SchemaIDBrowserRestoreStatus, SchemaVersion: "1.0.0", PointID: lastGood, PlanID: restoreBinding.PlanID, PlanDigest: restoreBinding.PlanDigest, TargetDigest: restoreBinding.TargetDigest, Status: restoreBinding.Status, ReasonCode: "restore-planned", RecoveryEpoch: restoreBinding.NextRecoveryEpoch, VerificationStatus: "pending", SafeNextAction: "continue with the exact approved restore plan"}
	schedulePolicy := generated.ScheduledJobPolicy{Schema: generated.SchemaIDScheduledJobPolicy, SchemaVersion: "1.1.0", PolicyID: "policy-a", Revision: 3, DeclarationID: "declaration-a", DeclarationRevision: 1, ActionKind: "gate-check", OperationType: "schedule.gate.check", AdapterID: "core.schedule-observe", ExactSourceIDs: []string{"source-a"}, ExactSubjectIDs: []string{"subject-a"}, ExactTargetIDs: []string{"target-a"}, MaximumWork: 1, CredentialReferenceIDs: []string{}, GrantRevision: 1, StateRevision: stateRevision, RecoveryEpoch: recoveryEpoch, PolicyVersion: "1.0.0", RetentionRuleDigest: digest, AnchorAt: "2026-09-24T00:00:00Z", IntervalSeconds: 3600, WindowSeconds: 1800, CatchUp: "none", Concurrency: "forbid", MaxAttempts: 1, InitialBackoffSeconds: 1, MaximumBackoffSeconds: 1, ExpiresAt: "2026-09-25T00:00:00Z", Enabled: true}

	application, localHandler, browserHandler, profile, factory := phase5ParityApplication(t, token, backupStatus, recoveryPoint, auditStatus, restoreBinding, restoreStatus, schedulePolicy)
	defer func() { _ = application.Shutdown(context.Background()) }()
	client := localapi.NewClient(factory)
	definition := generated.GeneratedGateDefinitions[7]
	apiGate, err := client.GetGate(context.Background(), profile, definition.GateID)
	if err != nil {
		t.Fatal(err)
	}
	apiBackup, err := client.BackupStatus(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	apiAudit, err := client.VerifyAudit(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}
	apiRestore, err := client.PlanRestore(context.Background(), profile, restoreRequest)
	if err != nil {
		t.Fatal(err)
	}
	apiSchedule, err := client.InspectScheduledPolicy(context.Background(), profile, "policy-a")
	if err != nil {
		t.Fatal(err)
	}
	apiFacts := phase5ParityFactsFrom(apiGate.Data, apiBackup.Data, apiAudit.Data, apiRestore.Data, apiSchedule.Data)

	operations := &phase5ParityControl{Operations: NewOperations(result.BuildInfo{ToolVersion: "phase5-test", ReleaseBuildID: "phase5-test"}, func() (string, error) { return "request-phase5-cli", nil }), client: client, profile: profile}
	cliGate := runPhase5ParityCLI[generated.GateView](t, operations, nil, "phase5-profile.json", "gate", "inspect", "--gate-id", definition.GateID)
	cliBackup := runPhase5ParityCLI[generated.BrowserBackupStatusData](t, operations, nil, "phase5-profile.json", "backup", "status")
	cliAudit := runPhase5ParityCLI[generated.BrowserAuditVerificationData](t, operations, nil, "phase5-profile.json", "audit", "verify")
	restoreRaw, _ := json.Marshal(restoreRequest)
	cliRestore := runPhase5ParityCLI[generated.RestoreBinding](t, operations, phase5ParityFile{content: restoreRaw}, "phase5-profile.json", "restore", "plan", "--file", "restore.json")
	cliSchedule := runPhase5ParityCLI[generated.BrowserScheduledJobPolicy](t, operations, nil, "phase5-profile.json", "schedule", "inspect", "--policy-id", "policy-a")
	cliFacts := phase5ParityFactsFrom(cliGate, cliBackup, cliAudit, cliRestore, cliSchedule)

	browserGate := phase5BrowserData[generated.GateView](t, browserHandler, "/api/v1/gates/"+definition.GateID)
	browserBackup := phase5BrowserData[generated.BrowserBackupStatusData](t, browserHandler, "/api/v1/backups/status")
	browserRecovery := phase5BrowserData[generated.BrowserRecoveryPointListData](t, browserHandler, "/api/v1/recovery-points")
	browserAudit := phase5BrowserData[generated.BrowserAuditVerificationData](t, browserHandler, "/api/v1/audit-history/verification")
	browserRestores := phase5BrowserData[generated.BrowserRestoreStatusListData](t, browserHandler, "/api/v1/restore-plans")
	browserSchedule := phase5BrowserData[generated.BrowserScheduledJobPolicy](t, browserHandler, "/api/v1/scheduled-job-policies/policy-a")
	if len(browserRecovery.Items) != 1 || len(browserRestores.Items) != 1 || browserRecovery.Items[0].ReasonCode != "verified" || browserRestores.Items[0].ReasonCode != "restore-planned" {
		t.Fatalf("browser fixture mismatch: recovery=%#v restore=%#v", browserRecovery, browserRestores)
	}
	apiRecovery := phase5LocalData[generated.BrowserRecoveryPointListData](t, localHandler, "/api/v1/recovery-points")
	apiRestores := phase5LocalData[generated.BrowserRestoreStatusListData](t, localHandler, "/api/v1/restore-plans")
	if !reflect.DeepEqual(apiRecovery, browserRecovery) || !reflect.DeepEqual(apiRestores, browserRestores) {
		t.Fatalf("recovery/restore API and browser projections differ:\napi=%#v/%#v\nbrowser=%#v/%#v", apiRecovery, apiRestores, browserRecovery, browserRestores)
	}
	browserFacts := phase5ParityFactsFromBrowser(browserGate, browserBackup, browserRecovery.Items[0], browserAudit, browserRestores.Items[0], browserSchedule)
	if !reflect.DeepEqual(apiFacts, cliFacts) || !reflect.DeepEqual(apiFacts, browserFacts) {
		t.Fatalf("surface mismatch:\napi=%#v\ncli=%#v\nbrowser=%#v", apiFacts, cliFacts, browserFacts)
	}
	for _, path := range []string{"/api/v1/backup-policies/policy-a/jobs", "/api/v1/restore-plans/restore-a/runs", "/api/v1/database/exports"} {
		request := authorizedBrowserRequest(t, http.MethodPost, path, strings.Repeat("A", 43))
		response := httptest.NewRecorder()
		browserHandler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "private-phase5-canary") {
			t.Fatalf("browser protected effect %s = %d %s", path, response.Code, response.Body.String())
		}
	}
}

func phase5ParityApplication(t *testing.T, token store.RevisionToken, backup generated.BackupStatusData, point generated.BrowserRecoveryPoint, auditStatus generated.AuditVerificationData, binding generated.RestoreBinding, restoreStatus generated.BrowserRestoreStatus, policy generated.ScheduledJobPolicy) (*api.Application, http.Handler, http.Handler, serverconfig.Profile, *result.Factory) {
	t.Helper()
	testRoot := os.Getenv("VSK_PHASE5_TEST_ROOT")
	if testRoot == "" {
		testRoot = os.TempDir()
	}
	directory, err := os.MkdirTemp(testRoot, "vsk-p5-real-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Getuid()), ToolVersion: "phase5-test", BuildVersion: "phase5-test"})
	if err != nil {
		t.Fatal(err)
	}
	sequence := atomic.Int64{}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "phase5-test", ReleaseBuildID: "phase5-test"}, func() (string, error) { return "request-phase5-" + string(rune('a'+sequence.Add(1))), nil })
	reads := phase5ParityReads{ReadRepository: store.NewReadRepository(authority), revision: token}
	application, err := api.NewApplication(api.Config{Authority: authority, Authorizer: phase5ParityReadAuthorizer{}, Reads: reads, Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), func() time.Time { return time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	plans := store.NewPlanRepository(authority)
	if err := api.RegisterGateOperations(application, api.GateOperations{Gates: store.NewGateRepository(authority), Revisions: plans, Declarations: declarations, Results: factory, Build: result.BuildInfo{ToolVersion: "phase5-test", ReleaseBuildID: "phase5-test"}, Clock: func() time.Time { return time.Date(2026, 9, 24, 6, 0, 0, 0, time.UTC) }}); err != nil {
		t.Fatal(err)
	}
	effective := phase5ParityEffective{}
	runs := phase5ParityRunPorts{}
	backupService := phase5ParityBackupStatus{data: backup, point: point, token: token}
	if err := api.RegisterBackupOperations(application, api.BackupOperations{Drafts: phase5ParityBackupDraft{}, Status: backupService, Runs: api.RunOperationConfig{Runs: runs, Plans: runs, Acknowledgements: runs, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: time.Now}}, Results: factory}); err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterAuditOperations(application, api.AuditOperations{Audit: phase5ParityAudit{verification: auditStatus}, Revisions: plans, Declarations: declarations, Results: factory}); err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterRestoreOperations(application, api.RestoreConfig{Operations: phase5ParityRestoreOperations{binding: binding, status: restoreStatus}, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: time.Now}}); err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterScheduleOperations(application, api.ScheduleOperations{Policies: phase5ParityScheduleStore{policy: policy, token: token}, Dispatch: phase5ParityScheduleDispatch{}, Runner: phase5ParityScheduleRunner{}, Results: factory}); err != nil {
		t.Fatal(err)
	}
	principal := identity.Principal{ID: "principal.phase5", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	localHandler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		application.ServeHTTP(writer, request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal)))
	})
	socketPath := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: localHandler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close() })
	authenticator, _, _ := newBrowserAuthFixture(t)
	browserHandler, err := NewBrowserHandler(application, testConsoleHandler(t), authenticator)
	if err != nil {
		t.Fatal(err)
	}
	return application, localHandler, browserHandler, serverconfig.Profile{SocketPath: socketPath}, factory
}

func phase5ParityFactsFrom(gate generated.GateView, backup generated.BrowserBackupStatusData, auditData generated.BrowserAuditVerificationData, restore generated.RestoreBinding, scheduleData generated.BrowserScheduledJobPolicy) phase5ParityFacts {
	point := ""
	if backup.LastGoodPointID != nil {
		point = *backup.LastGoodPointID
	}
	return phase5ParityFacts{GateID: gate.Definition.GateID, GateStatus: gate.Evaluation.Outcome, GateReason: gate.Evaluation.ReasonCode, BackupStatus: backup.Status, BackupReason: backup.ReasonCode, RecoveryPoint: point, AuditStatus: auditData.Status, AuditReason: auditData.ReasonCode, RestorePoint: restore.PointID, RestorePlan: restore.PlanID, RestoreStatus: restore.Status, RestoreReason: "restore-" + restore.Status, SchedulePolicy: scheduleData.PolicyID, ScheduleStatus: scheduleData.Status, ScheduleReason: scheduleData.ReasonCode, StateRevision: backup.StateRevision, RecoveryEpoch: backup.RecoveryEpoch}
}

func phase5ParityFactsFromBrowser(gate generated.GateView, backup generated.BrowserBackupStatusData, recoveryPoint generated.BrowserRecoveryPoint, auditData generated.BrowserAuditVerificationData, restore generated.BrowserRestoreStatus, scheduleData generated.BrowserScheduledJobPolicy) phase5ParityFacts {
	return phase5ParityFacts{GateID: gate.Definition.GateID, GateStatus: gate.Evaluation.Outcome, GateReason: gate.Evaluation.ReasonCode, BackupStatus: backup.Status, BackupReason: backup.ReasonCode, RecoveryPoint: recoveryPoint.PointID, AuditStatus: auditData.Status, AuditReason: auditData.ReasonCode, RestorePoint: restore.PointID, RestorePlan: restore.PlanID, RestoreStatus: restore.Status, RestoreReason: restore.ReasonCode, SchedulePolicy: scheduleData.PolicyID, ScheduleStatus: scheduleData.Status, ScheduleReason: scheduleData.ReasonCode, StateRevision: backup.StateRevision, RecoveryEpoch: backup.RecoveryEpoch}
}

func runPhase5ParityCLI[T any](t *testing.T, operations cli.ControlOperations, files interface {
	Read(context.Context, string, int64) ([]byte, error)
}, configPath string, args ...string) T {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := cli.New(&stdout, &stderr, result.BuildInfo{ToolVersion: "phase5-test", ReleaseBuildID: "phase5-test"}, func() (string, error) { return "request-phase5-cli", nil }, cli.WithControlOperations(operations, files))
	arguments := append(append([]string(nil), args...), "--config", configPath, "--output", "json")
	if code := app.Run(context.Background(), arguments); code != 0 || stderr.Len() != 0 {
		t.Fatalf("CLI %v code=%d stderr=%s stdout=%s", arguments, code, stderr.String(), stdout.String())
	}
	var envelope struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

func phase5BrowserData[T any](t *testing.T, handler http.Handler, path string) T {
	t.Helper()
	_, _, sessions := newBrowserAuthFixture(t)
	request := authorizedBrowserRequest(t, http.MethodGet, path, sessions.raw)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("browser GET %s: %d %s", path, response.Code, response.Body.String())
	}
	var envelope struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

func phase5LocalData[T any](t *testing.T, handler http.Handler, path string) T {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("local API GET %s: %d %s", path, response.Code, response.Body.String())
	}
	var envelope struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	return envelope.Data
}

func phase5ParityRestore(t *testing.T, digest string, stateRevision, epoch int64, pointID string) (generated.RestoreRequest, generated.RestoreBinding) {
	t.Helper()
	secondDigest := "sha256:" + strings.Repeat("b", 64)
	source := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: pointID, PointDigest: digest, ManifestDigest: digest, VerificationDigest: digest, SourceClass: "local", RepositoryGenerationID: "generation-a", KeyReferenceID: "key-a", DeclaredRPOSeconds: 3600, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: "2026-09-24T05:30:00Z", RecoveryEpoch: epoch, DependencyDigests: []string{digest}, RequiredDependencies: []generated.RestoreDependencyBinding{{DependencyID: "binary-a", Kind: "binary", Digest: digest}}, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "21"}
	fences, err := recovery.RequiredFenceSet([]recovery.FenceRequirement{{Boundary: "host-service", SubjectID: "former-host", FormerInstanceID: "instance-old", ReplacementInstanceID: "instance-new", TargetID: "control-a", AdapterID: "adapter-a", FormerIdentityID: "former-identity", ProfileID: "labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", ReleaseBuildID: "build-a", EvaluatorVersion: "1.0.0", RecoveryEpoch: epoch, RequiredEvidenceKinds: []string{"alternate-process-denied", "service-denied"}}}, digest, secondDigest)
	if err != nil {
		t.Fatal(err)
	}
	request := generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: stateRevision, RecoveryEpoch: epoch, TargetDigest: digest, IdempotencyKey: "restore-phase5", Source: source, Fences: fences.Items, AuditDecision: generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", LocalLastEventID: 4, IndependentLastEventID: 4, IndependentCheckpointDigest: digest, Strategy: "matched", DecisionDigest: digest}, PointID: pointID, DependencyIDs: []string{"dependency-a"}, TargetIDs: []string{"control-a"}, PriorInstanceID: "instance-old", NewInstanceID: "instance-new", PriorRecoveryEpoch: epoch, NextRecoveryEpoch: epoch + 1, FenceSetDigest: fences.FenceSetDigest, AuditDecisionDigest: digest, CandidateDigest: digest, FormerHostID: "former-host", ReplacementHostID: "replacement-host", RecoveryDraftID: "draft-a", CiphertextFingerprint: digest, SourceAdmissionDigest: digest, FenceQualificationDigest: secondDigest, RecoveryRunID: "run-a", RecoveryStepID: "step-a", RecoveryLeaseID: "lease-a", RecoveryChallengeID: "challenge-a", RecoveryReceiptID: "receipt-a", CanaryRunID: "canary-run-a", CanaryStepID: "canary-step-a", CanaryLeaseID: "canary-lease-a", CanaryChallengeID: "canary-challenge-a", CanaryReceiptID: "canary-receipt-a", CanaryBindingDigest: digest}
	binding := generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: source, PointID: pointID, DependencyIDs: request.DependencyIDs, TargetIDs: request.TargetIDs, TargetDigest: digest, PlanID: "restore-a", PlanDigest: digest, HumanAcknowledgementID: "pending-human-acknowledgement", FenceSetDigest: request.FenceSetDigest, AuditDecisionDigest: digest, CandidateDigest: digest, FormerHostID: request.FormerHostID, ReplacementHostID: request.ReplacementHostID, RecoveryDraftID: request.RecoveryDraftID, CiphertextFingerprint: digest, SourceAdmissionDigest: digest, FenceQualificationDigest: secondDigest, RecoveryRunID: request.RecoveryRunID, RecoveryStepID: request.RecoveryStepID, RecoveryLeaseID: request.RecoveryLeaseID, RecoveryChallengeID: request.RecoveryChallengeID, RecoveryReceiptID: request.RecoveryReceiptID, CanaryRunID: request.CanaryRunID, CanaryStepID: request.CanaryStepID, CanaryLeaseID: request.CanaryLeaseID, CanaryChallengeID: request.CanaryChallengeID, CanaryReceiptID: request.CanaryReceiptID, CanaryBindingDigest: digest, PriorInstanceID: request.PriorInstanceID, NewInstanceID: request.NewInstanceID, PriorRecoveryEpoch: epoch, NextRecoveryEpoch: epoch + 1, Status: "planned"}
	return request, binding
}
