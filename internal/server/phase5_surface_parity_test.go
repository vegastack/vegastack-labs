package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/cli"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/result"
	serverruntime "github.com/vegastack/vegastack-labs/internal/server"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type phase5ParityFacts struct {
	GateID, GateStatus, GateReason                 string
	BackupStatus, BackupReason, RecoveryPoint      string
	AuditStatus, AuditReason                       string
	RestorePoint, RestorePlan, RestoreStatus       string
	SchedulePolicy, ScheduleStatus, ScheduleReason string
	StateRevision, RecoveryEpoch                   int64
}

type phase5ParityFile struct{ content []byte }

func (file phase5ParityFile) Read(context.Context, string, int64) ([]byte, error) {
	return append([]byte(nil), file.content...), nil
}

type phase5ParityControl struct {
	*serverruntime.Operations
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

func TestPhase5SurfacesAgreeAndBrowserCannotReachProtectedEffects(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the acceptance fixture exercises the local Unix-socket transport")
	}
	const stateRevision, recoveryEpoch = int64(7), int64(2)
	digest := "sha256:" + strings.Repeat("a", 64)
	definition := generated.GeneratedGateDefinitions[7]
	evaluation := generated.GateEvaluation{Schema: generated.SchemaIDGateEvaluation, SchemaVersion: "1.1.0", EvaluationID: "evaluation-phase5", GateID: definition.GateID, SubjectID: "site-a", DefinitionVersion: definition.DefinitionVersion, EvaluatorVersion: definition.EvaluatorVersion, EvidenceIDs: []string{}, EvaluatedAt: "2026-09-24T06:00:00Z", RecoveryEpoch: recoveryEpoch, Outcome: "blocked", ReasonCode: "proof-unavailable", EvidenceSource: "none", ReadyForInput: true}
	gate := generated.GateView{Schema: generated.SchemaIDGateView, SchemaVersion: "1.1.0", Definition: definition, Evaluation: evaluation, ApplicabilityReasonCode: "applicable"}
	lastGood := "point-last-good"
	backup := generated.BrowserBackupStatusData{Schema: generated.SchemaIDBrowserBackupStatusData, SchemaVersion: "1.0.0", Status: "recovery-required", ReasonCode: "verification-overdue", SourceKind: "local", ProofClass: "live", LastGoodPointID: &lastGood, RecoveryRequired: true, StateRevision: stateRevision, RecoveryEpoch: recoveryEpoch, SafeNextAction: "verify the latest local recovery point"}
	verifiedAt := "2026-09-24T05:30:00Z"
	recoveryPoint := generated.BrowserRecoveryPoint{Schema: generated.SchemaIDBrowserRecoveryPoint, SchemaVersion: "1.0.0", PointID: lastGood, SourceKind: "local", ProofClass: "live", ContentDigest: digest, ManifestDigest: digest, CreatedAt: "2026-09-24T05:00:00Z", VerifiedAt: &verifiedAt, VerificationStatus: "verified", ReasonCode: "verified", RecoveryEpoch: recoveryEpoch}
	recoveryPoints := generated.BrowserRecoveryPointListData{Schema: generated.SchemaIDBrowserRecoveryPointListData, SchemaVersion: "1.0.0", Items: []generated.BrowserRecoveryPoint{recoveryPoint}, StateRevision: stateRevision, RecoveryEpoch: recoveryEpoch}
	auditStatus := generated.BrowserAuditVerificationData{Schema: generated.SchemaIDBrowserAuditVerificationData, SchemaVersion: "1.0.0", Status: "degraded", ReasonCode: "no-independent-anchor", SourceKind: "none", ProofClass: "none", IndependentMatch: false, LastAnchoredSequence: 0, PreAnchor: false, StateRevision: stateRevision, RecoveryEpoch: recoveryEpoch, SafeNextAction: "collect and compare an independent audit checkpoint"}
	restoreRequest, restoreBinding := phase5ParityRestore(t, digest, stateRevision, recoveryEpoch, lastGood)
	restores := generated.BrowserRestoreStatusListData{Schema: generated.SchemaIDBrowserRestoreStatusListData, SchemaVersion: "1.0.0", Items: []generated.BrowserRestoreStatus{{Schema: generated.SchemaIDBrowserRestoreStatus, SchemaVersion: "1.0.0", PointID: lastGood, PlanID: restoreBinding.PlanID, PlanDigest: restoreBinding.PlanDigest, TargetDigest: restoreBinding.TargetDigest, Status: restoreBinding.Status, ReasonCode: "restore-planned", RecoveryEpoch: restoreBinding.NextRecoveryEpoch, VerificationStatus: "pending", SafeNextAction: "continue with the exact approved restore plan"}}, StateRevision: stateRevision, RecoveryEpoch: recoveryEpoch}
	schedulePolicy := generated.BrowserScheduledJobPolicy{Schema: generated.SchemaIDBrowserScheduledJobPolicy, SchemaVersion: "1.0.0", PolicyID: "policy-a", Revision: 3, ActionKind: "backup-create", Enabled: true, Status: "active", ReasonCode: "active", TargetDigest: digest, StateRevision: stateRevision, RecoveryEpoch: recoveryEpoch}

	factory := result.NewFactory(result.BuildInfo{ToolVersion: "phase5-test", ReleaseBuildID: "phase5-test"}, func() (string, error) { return "request-phase5-parity", nil })
	responses := map[string][]byte{
		http.MethodGet + " /api/v1/gates/" + definition.GateID:                      phase5ParityEnvelope(t, factory, "api.v1.gates.get", false, recoveryEpoch, stateRevision, gate),
		http.MethodGet + " /api/v1/backups/status":                                  phase5ParityEnvelope(t, factory, "api.v1.backups.status", false, recoveryEpoch, stateRevision, backup),
		http.MethodGet + " /api/v1/recovery-points":                                 phase5ParityEnvelope(t, factory, "api.v1.recovery-points.list", false, recoveryEpoch, stateRevision, recoveryPoints),
		http.MethodGet + " /api/v1/audit-history/verification":                      phase5ParityEnvelope(t, factory, "api.v1.audit-history.verification", false, recoveryEpoch, stateRevision, auditStatus),
		http.MethodGet + " /api/v1/restore-plans":                                   phase5ParityEnvelope(t, factory, "api.v1.restores.list", false, recoveryEpoch, stateRevision, restores),
		http.MethodPost + " /api/v1/recovery-points/" + lastGood + "/restore-plans": phase5ParityEnvelope(t, factory, "api.v1.restores.plan", true, recoveryEpoch, stateRevision, restoreBinding),
		http.MethodGet + " /api/v1/scheduled-job-policies/policy-a":                 phase5ParityEnvelope(t, factory, "api.v1.scheduled-job-policies.get", false, recoveryEpoch, stateRevision, schedulePolicy),
	}
	_, profile, handler := phase5ParityServer(t, responses)
	configPath := "phase5-profile.json"

	client := localapi.NewClient(factory)
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

	operations := &phase5ParityControl{Operations: serverruntime.NewOperations(result.BuildInfo{ToolVersion: "phase5-test", ReleaseBuildID: "phase5-test"}, func() (string, error) { return "request-phase5-cli", nil }), client: client, profile: profile}
	cliGate := runPhase5ParityCLI[generated.GateView](t, operations, nil, configPath, "gate", "inspect", "--gate-id", definition.GateID)
	cliBackup := runPhase5ParityCLI[generated.BrowserBackupStatusData](t, operations, nil, configPath, "backup", "status")
	cliAudit := runPhase5ParityCLI[generated.BrowserAuditVerificationData](t, operations, nil, configPath, "audit", "verify")
	restoreRaw, _ := json.Marshal(restoreRequest)
	cliRestore := runPhase5ParityCLI[generated.RestoreBinding](t, operations, phase5ParityFile{content: restoreRaw}, configPath, "restore", "plan", "--file", "restore.json")
	cliSchedule := runPhase5ParityCLI[generated.BrowserScheduledJobPolicy](t, operations, nil, configPath, "schedule", "inspect", "--policy-id", "policy-a")
	cliFacts := phase5ParityFactsFrom(cliGate, cliBackup, cliAudit, cliRestore, cliSchedule)

	browserGate := phase5BrowserData[generated.GateView](t, handler, "/api/v1/gates/"+definition.GateID)
	browserBackup := phase5BrowserData[generated.BrowserBackupStatusData](t, handler, "/api/v1/backups/status")
	browserRecovery := phase5BrowserData[generated.BrowserRecoveryPointListData](t, handler, "/api/v1/recovery-points")
	browserAudit := phase5BrowserData[generated.BrowserAuditVerificationData](t, handler, "/api/v1/audit-history/verification")
	browserRestore := phase5BrowserData[generated.BrowserRestoreStatusListData](t, handler, "/api/v1/restore-plans")
	browserSchedule := phase5BrowserData[generated.BrowserScheduledJobPolicy](t, handler, "/api/v1/scheduled-job-policies/policy-a")
	if len(browserRecovery.Items) != 1 || len(browserRestore.Items) != 1 {
		t.Fatalf("browser fixture incomplete: recovery=%#v restore=%#v", browserRecovery, browserRestore)
	}
	browserBinding := restoreBinding
	browserBinding.PointID, browserBinding.PlanID, browserBinding.Status = browserRestore.Items[0].PointID, browserRestore.Items[0].PlanID, browserRestore.Items[0].Status
	browserFacts := phase5ParityFactsFrom(browserGate, browserBackup, browserAudit, browserBinding, browserSchedule)
	browserFacts.RecoveryPoint = browserRecovery.Items[0].PointID

	if !reflect.DeepEqual(apiFacts, cliFacts) || !reflect.DeepEqual(apiFacts, browserFacts) {
		t.Fatalf("surface mismatch:\napi=%#v\ncli=%#v\nbrowser=%#v", apiFacts, cliFacts, browserFacts)
	}
	for _, path := range []string{"/api/v1/backup-policies/policy-a/jobs", "/api/v1/restore-plans/restore-a/runs", "/api/v1/database/exports"} {
		if api.RemoteReadRequestAllowed(http.MethodPost, path) {
			t.Fatalf("browser reached protected effect %s", path)
		}
	}
	if encoded, _ := json.Marshal(browserFacts); strings.Contains(string(encoded), "private-phase5-canary") {
		t.Fatal("private canary entered safe facts")
	}
}

func phase5ParityFactsFrom(gate generated.GateView, backup generated.BrowserBackupStatusData, audit generated.BrowserAuditVerificationData, restore generated.RestoreBinding, schedule generated.BrowserScheduledJobPolicy) phase5ParityFacts {
	point := ""
	if backup.LastGoodPointID != nil {
		point = *backup.LastGoodPointID
	}
	return phase5ParityFacts{GateID: gate.Definition.GateID, GateStatus: gate.Evaluation.Outcome, GateReason: gate.Evaluation.ReasonCode, BackupStatus: backup.Status, BackupReason: backup.ReasonCode, RecoveryPoint: point, AuditStatus: audit.Status, AuditReason: audit.ReasonCode, RestorePoint: restore.PointID, RestorePlan: restore.PlanID, RestoreStatus: restore.Status, SchedulePolicy: schedule.PolicyID, ScheduleStatus: schedule.Status, ScheduleReason: schedule.ReasonCode, StateRevision: backup.StateRevision, RecoveryEpoch: backup.RecoveryEpoch}
}

func phase5ParityEnvelope[T any](t *testing.T, factory *result.Factory, command string, changed bool, epoch, revision int64, data T) []byte {
	t.Helper()
	envelope, err := factory.SuccessWithRequestID(command, "request-phase5-api", changed, epoch, revision, data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func phase5ParityServer(t *testing.T, responses map[string][]byte) (string, serverconfig.Profile, http.Handler) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "vsk-p5-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if response := responses[request.Method+" "+request.URL.Path]; response != nil {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(response)
			return
		}
		http.NotFound(writer, request)
	})
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close(); _ = os.RemoveAll(directory) })
	return directory, serverconfig.Profile{SocketPath: path}, handler
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
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
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
