package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type stubControlOperations struct {
	gateListResponse          localapi.TypedResponse[generated.GateListData]
	gateViewResponse          localapi.TypedResponse[generated.GateView]
	gateCheckResponse         localapi.TypedResponse[generated.GateEvaluation]
	gateEvidenceResponse      localapi.TypedResponse[generated.GateEvidenceSubmission]
	gateProfileResponse       localapi.TypedResponse[generated.GateProfileDraftSubmission]
	backupPolicyResponse      localapi.TypedResponse[generated.BackupPolicyDraftSubmission]
	retentionLockResponse     localapi.TypedResponse[generated.BackupRetentionLockDraftSubmission]
	retirementResponse        localapi.TypedResponse[generated.BackupRetirementDraftSubmission]
	offsiteRetirementResponse localapi.TypedResponse[generated.BackupOffsiteRetirementStageSubmission]
	offsiteDryRunResponse     localapi.TypedResponse[generated.BackupOffsiteRetirementDryRunData]
	backupStatusResponse      localapi.TypedResponse[generated.BackupStatusData]
	backupJobResponse         localapi.TypedResponse[generated.BackupJob]
	summaryResponse           localapi.TypedResponse[generated.ApiSummaryData]
	databaseResponse          localapi.TypedResponse[generated.DatabaseStatusData]
	auditListResponse         localapi.TypedResponse[generated.AuditCheckpointListData]
	auditVerifyResponse       localapi.TypedResponse[generated.AuditVerificationData]
	importResponse            localapi.TypedResponse[generated.InventoryImportData]
	diffResponse              localapi.TypedResponse[generated.InventoryDiffData]
	exportResponse            localapi.TypedResponse[generated.InventoryExportData]
	planResponse              localapi.TypedResponse[generated.Plan]
	runResponse               localapi.TypedResponse[generated.RunPresentation]
	err                       error
	calls                     int
	config                    string
	importRequest             generated.InventoryImportRequest
	diffRequest               generated.InventoryDiffRequest
	exportRequest             generated.InventoryExportRequest
}

func (stub *stubControlOperations) Gates(_ context.Context, _ string) (localapi.TypedResponse[generated.GateListData], error) {
	return stub.gateListResponse, stub.err
}
func (stub *stubControlOperations) GetGate(_ context.Context, _, _ string) (localapi.TypedResponse[generated.GateView], error) {
	return stub.gateViewResponse, stub.err
}
func (stub *stubControlOperations) CheckGate(_ context.Context, _, _, _ string) (localapi.TypedResponse[generated.GateEvaluation], error) {
	return stub.gateCheckResponse, stub.err
}
func (stub *stubControlOperations) SubmitGateEvidence(_ context.Context, _ string, _ generated.GateEvidenceRequest) (localapi.TypedResponse[generated.GateEvidenceSubmission], error) {
	return stub.gateEvidenceResponse, stub.err
}
func (stub *stubControlOperations) SubmitProfileDraft(_ context.Context, _ string, _ generated.GateProfileDraftRequest) (localapi.TypedResponse[generated.GateProfileDraftSubmission], error) {
	return stub.gateProfileResponse, stub.err
}
func (stub *stubControlOperations) SubmitBackupPolicyDraft(_ context.Context, _ string, _ generated.BackupPolicyDraftRequest) (localapi.TypedResponse[generated.BackupPolicyDraftSubmission], error) {
	return stub.backupPolicyResponse, stub.err
}
func (stub *stubControlOperations) SubmitBackupRetentionLockDraft(_ context.Context, _ string, _ generated.BackupRetentionLockDraftRequest) (localapi.TypedResponse[generated.BackupRetentionLockDraftSubmission], error) {
	return stub.retentionLockResponse, stub.err
}
func (stub *stubControlOperations) SubmitBackupRetirementDraft(_ context.Context, _ string, _ generated.BackupRetirementDraftRequest) (localapi.TypedResponse[generated.BackupRetirementDraftSubmission], error) {
	return stub.retirementResponse, stub.err
}
func (stub *stubControlOperations) StageBackupOffsiteRetirement(context.Context, string, generated.BackupOffsiteRetirementStageRequest) (localapi.TypedResponse[generated.BackupOffsiteRetirementStageSubmission], error) {
	return stub.offsiteRetirementResponse, stub.err
}
func (stub *stubControlOperations) DryRunBackupOffsiteRetirement(context.Context, string, generated.BackupOffsiteRetirementDryRunRequest) (localapi.TypedResponse[generated.BackupOffsiteRetirementDryRunData], error) {
	return stub.offsiteDryRunResponse, stub.err
}
func (stub *stubControlOperations) BackupStatus(_ context.Context, _ string) (localapi.TypedResponse[generated.BackupStatusData], error) {
	return stub.backupStatusResponse, stub.err
}
func (stub *stubControlOperations) RunBackup(_ context.Context, _ string, _ generated.BackupRunRequest) (localapi.TypedResponse[generated.BackupJob], error) {
	return stub.backupJobResponse, stub.err
}
func (stub *stubControlOperations) VerifyBackup(_ context.Context, _ string, _ generated.BackupVerifyRequest) (localapi.TypedResponse[generated.BackupJob], error) {
	return stub.backupJobResponse, stub.err
}

func (stub *stubControlOperations) Summary(_ context.Context, config string) (localapi.TypedResponse[generated.ApiSummaryData], error) {
	stub.calls++
	stub.config = config
	return stub.summaryResponse, stub.err
}

func (stub *stubControlOperations) DatabaseStatus(_ context.Context, config string) (localapi.TypedResponse[generated.DatabaseStatusData], error) {
	stub.calls++
	stub.config = config
	return stub.databaseResponse, stub.err
}

func (stub *stubControlOperations) AuditCheckpoints(_ context.Context, config string) (localapi.TypedResponse[generated.AuditCheckpointListData], error) {
	stub.calls++
	stub.config = config
	return stub.auditListResponse, stub.err
}

func (stub *stubControlOperations) VerifyAudit(_ context.Context, config string) (localapi.TypedResponse[generated.AuditVerificationData], error) {
	stub.calls++
	stub.config = config
	return stub.auditVerifyResponse, stub.err
}

func (stub *stubControlOperations) ImportInventory(_ context.Context, config string, request generated.InventoryImportRequest) (localapi.TypedResponse[generated.InventoryImportData], error) {
	stub.calls++
	stub.config, stub.importRequest = config, request
	return stub.importResponse, stub.err
}

func (stub *stubControlOperations) DiffInventory(_ context.Context, config string, request generated.InventoryDiffRequest) (localapi.TypedResponse[generated.InventoryDiffData], error) {
	stub.calls++
	stub.config, stub.diffRequest = config, request
	return stub.diffResponse, stub.err
}

func (stub *stubControlOperations) ExportInventory(_ context.Context, config string, request generated.InventoryExportRequest) (localapi.TypedResponse[generated.InventoryExportData], error) {
	stub.calls++
	stub.config, stub.exportRequest = config, request
	return stub.exportResponse, stub.err
}

func (stub *stubControlOperations) Plan(_ context.Context, config, _ string, _ int64) (localapi.TypedResponse[generated.Plan], error) {
	stub.calls++
	stub.config = config
	return stub.planResponse, stub.err
}
func (stub *stubControlOperations) Apply(_ context.Context, config, _ string) (localapi.TypedResponse[generated.RunPresentation], error) {
	stub.calls++
	stub.config = config
	return stub.runResponse, stub.err
}
func (stub *stubControlOperations) InspectRun(_ context.Context, config, _ string) (localapi.TypedResponse[generated.RunPresentation], error) {
	stub.calls++
	stub.config = config
	return stub.runResponse, stub.err
}
func (stub *stubControlOperations) CancelRun(_ context.Context, config, _ string) (localapi.TypedResponse[generated.RunPresentation], error) {
	stub.calls++
	stub.config = config
	return stub.runResponse, stub.err
}
func (stub *stubControlOperations) ResumeRun(_ context.Context, config, _ string) (localapi.TypedResponse[generated.RunPresentation], error) {
	stub.calls++
	stub.config = config
	return stub.runResponse, stub.err
}

type stubFileReader struct {
	content []byte
	err     error
	path    string
	limit   int64
	calls   int
}

func (stub *stubFileReader) Read(_ context.Context, path string, limit int64) ([]byte, error) {
	stub.calls++
	stub.path, stub.limit = path, limit
	return append([]byte(nil), stub.content...), stub.err
}

func successfulControlOperations(t *testing.T) *stubControlOperations {
	t.Helper()
	summary := generated.ApiSummaryData{DatabaseMode: "read-write", ReadAvailable: true, DraftCount: 2, ValidDraftCount: 1, BlockedDraftCount: 1, LastEventID: 9, StateRevision: 7, RecoveryEpoch: 2, SourceCounts: generated.ApiSourceCountsData{Total: 7, Healthy: 1, Stale: 1, Unknown: 1, Unavailable: 3, Failed: 1}, WorstSourceState: "failed"}
	database := generated.DatabaseStatusData{Mode: "read-write", SchemaVersion: 1, SQLiteVersion: "3.synthetic", IntegrityStatus: "ok"}
	auditList := generated.AuditCheckpointListData{Schema: generated.SchemaIDAuditCheckpointListData, SchemaVersion: "1.0.0", Checkpoints: []generated.AuditCheckpoint{}, RecoveryEpoch: 2}
	auditVerify := generated.AuditVerificationData{Schema: generated.SchemaIDAuditVerificationData, SchemaVersion: "1.1.0", Status: "degraded", InstanceID: "instance-test", RecoveryEpoch: 2, LocalDigest: "sha256:" + strings.Repeat("5", 64), IndependentMatch: false, LastAnchoredSequence: 0, ReasonCode: "no-independent-anchor", PreAnchor: false}
	imported := generated.InventoryImportData{DraftID: "draft-test", DraftRevision: 1, ValidationStatus: "valid", StateRevision: 8, RecoveryEpoch: 2, Created: true, Findings: []generated.InventoryFinding{}}
	diff := generated.InventoryDiffData{CandidateKind: "draft", CandidateDigest: "sha256:" + strings.Repeat("1", 64), BaselineKind: "draft", BaselineDraft: generated.InventoryDraftRef{DraftID: "draft-base", DraftRevision: 1}, StateRevision: 8, RecoveryEpoch: 2, Records: []generated.InventoryDiffRecord{}, Findings: []generated.InventoryFinding{}}
	exported := generated.InventoryExportData{ExportID: "sha256:" + strings.Repeat("2", 64), SubjectKind: "draft", Draft: generated.InventoryDraftRef{DraftID: "draft-test", DraftRevision: 1}, StateRevision: 9, RecoveryEpoch: 2, ContentDigest: "sha256:" + strings.Repeat("3", 64), Algorithm: "ed25519", KeyID: "synthetic-key", KeyFingerprint: "sha256:" + strings.Repeat("4", 64), VerificationStatus: "verified", PublicationStatus: "published", SignedBytesBase64: "e30K"}
	plan := phase4TestPlan()
	run := phase4TestRun(plan, generated.RunStatusSucceeded)
	definition := generated.GeneratedGateDefinitions[7]
	evaluation := generated.GateEvaluation{Schema: generated.SchemaIDGateEvaluation, SchemaVersion: "1.1.0", EvaluationID: "eval-test", GateID: definition.GateID, SubjectID: "site-a", DefinitionVersion: definition.DefinitionVersion, EvaluatorVersion: definition.EvaluatorVersion, EvidenceIDs: []string{}, EvaluatedAt: "2026-09-15T00:00:00Z", RecoveryEpoch: 2, Outcome: "blocked", ReasonCode: "proof-unavailable", EvidenceSource: "none", ReadyForInput: true}
	view := generated.GateView{Schema: generated.SchemaIDGateView, SchemaVersion: "1.1.0", Definition: definition, Evaluation: evaluation, ApplicabilityReasonCode: "applicable"}
	list := generated.GateListData{Schema: generated.SchemaIDGateListData, SchemaVersion: "1.1.0", Gates: []generated.GateView{view}, RecoveryEpoch: 2}
	evidence := generated.GateEvidenceSubmission{Schema: generated.SchemaIDGateEvidenceSubmission, SchemaVersion: "1.1.0", DraftID: "draft-test", ChangeID: "gate-evidence-test", EvidenceID: "evidence-test", Status: "draft", StateRevision: 8, RecoveryEpoch: 2}
	profile := generated.GateProfileDraftSubmission{Schema: generated.SchemaIDGateProfileDraftSubmission, SchemaVersion: "1.1.0", DraftID: "binding-test", ChangeID: "gate-profile-binding-test", BindingID: "binding-test", Status: "draft", StateRevision: 8, RecoveryEpoch: 2}
	backup := generated.BackupPolicyDraftSubmission{Schema: generated.SchemaIDBackupPolicyDraftSubmission, SchemaVersion: "1.1.0", DraftID: "backup-draft-test", PolicyID: "policy-a", PolicyDigest: "sha256:" + strings.Repeat("a", 64), Status: "draft", StateRevision: 8, RecoveryEpoch: 2}
	retentionLock := generated.BackupRetentionLockDraftSubmission{Schema: generated.SchemaIDBackupRetentionLockDraftSubmission, SchemaVersion: "1.1.0", DraftID: "lock-draft-test", ChangeID: "retention-lock-change-test", OperationID: "retention-lock-operation-test", CatalogDigest: "sha256:" + strings.Repeat("a", 64), Status: "draft", StateRevision: 9, RecoveryEpoch: 2}
	retirement := generated.BackupRetirementDraftSubmission{Schema: generated.SchemaIDBackupRetirementDraftSubmission, SchemaVersion: "1.1.0", DraftID: "retirement-draft-test", ChangeID: "retirement-change-test", OperationID: "retirement-operation-test", SelectionDigest: "sha256:" + strings.Repeat("b", 64), CredentialManifestDigest: "sha256:" + strings.Repeat("c", 64), TargetPointIDs: []string{"point-old"}, SurvivorPointIDs: []string{"point-good"}, Status: "draft", StateRevision: 10, RecoveryEpoch: 2}
	offsiteRetirement := generated.BackupOffsiteRetirementStageSubmission{Schema: generated.SchemaIDBackupOffsiteRetirementStageSubmission, SchemaVersion: "1.1.0", IntentID: "offsite-retirement-test", GenerationID: "generation-old", PointID: "point-old", RuleSetDigest: "sha256:" + strings.Repeat("a", 64), SurvivorRuleDigest: "sha256:" + strings.Repeat("b", 64), PreRuleCount: 10, SurvivorRuleCount: 5, SurvivorPointIDs: []string{"point-good"}, ExpectedReclaimBytes: 8, Status: "staged", StateRevision: 7, RecoveryEpoch: 2}
	dryRunDigest := "sha256:" + strings.Repeat("a", 64)
	offsiteDryRun := generated.BackupOffsiteRetirementDryRunData{Schema: generated.SchemaIDBackupOffsiteRetirementDryRunData, SchemaVersion: "1.1.0", IntentDigest: dryRunDigest, SelectionDigest: dryRunDigest, GenerationID: "generation-old", PointID: "point-old", BucketID: "bucket-a", RuleSetDigest: dryRunDigest, SurvivorRuleDigest: dryRunDigest, ManifestDigest: dryRunDigest, CatalogDigest: dryRunDigest, InventoryDigest: dryRunDigest, SurvivorPointIDs: []string{"point-good"}, SurvivorKeyReferenceIDs: []string{"key-good"}, Rules: []generated.BackupOffsiteRetirementRule{{RuleID: "old-config", Prefix: "critical/generation-old/config"}, {RuleID: "old-data", Prefix: "critical/generation-old/data/"}, {RuleID: "old-index", Prefix: "critical/generation-old/index/"}, {RuleID: "old-keys", Prefix: "critical/generation-old/keys/"}, {RuleID: "old-snapshots", Prefix: "critical/generation-old/snapshots/"}}, Objects: []generated.BackupOffsiteRetirementObject{{Key: "critical/generation-old/data/a", Digest: dryRunDigest, Bytes: 8}}, SurvivorBindings: []generated.BackupOffsiteRetirementSurvivorBinding{{PointID: "point-good", GenerationID: "generation-good", ReferenceID: "key-good", DependencyDigest: dryRunDigest}}, ObjectCount: 1, ExpectedReclaimBytes: 8, RetainedBytes: 21, MaxWorkObjects: 1, MaxMutationBytes: 8, PreRuleCount: 10, SurvivorRuleCount: 5, StateRevision: 7, RecoveryEpoch: 2}
	backupStatus := generated.BackupStatusData{Schema: generated.SchemaIDBackupStatusData, SchemaVersion: "1.3.0", Policies: []generated.BackupPolicy{}, Jobs: []generated.BackupJob{}, Verifications: []generated.BackupVerificationAttempt{}, LastGood: []generated.BackupLastGood{}, Retirements: []generated.BackupLocalRetirementStatus{}, Offsite: []generated.BackupOffsiteStatus{}, RecoveryEpoch: 2}
	backupJob := generated.BackupJob{Schema: generated.SchemaIDBackupJob, SchemaVersion: "1.1.0", JobID: "job-test", PolicyID: "policy-a", SourceKind: "fixture", ProofClass: "fixture", Status: "pending", RecoveryEpoch: 2}
	return &stubControlOperations{
		gateListResponse:          operationResponse(t, "api.v1.gates.list", false, 2, 7, list),
		gateViewResponse:          operationResponse(t, "api.v1.gates.get", false, 2, 7, view),
		gateCheckResponse:         operationResponse(t, "api.v1.gates.check", false, 2, 7, evaluation),
		gateEvidenceResponse:      operationResponse(t, "api.v1.gate-evidence.create", true, 2, 8, evidence),
		gateProfileResponse:       operationResponse(t, "api.v1.gate-profile-drafts.create", true, 2, 8, profile),
		backupPolicyResponse:      operationResponse(t, "api.v1.backup-policy-drafts.create", true, 2, 8, backup),
		retentionLockResponse:     operationResponse(t, "api.v1.backup-retention-lock-drafts.create", true, 2, 9, retentionLock),
		retirementResponse:        operationResponse(t, "api.v1.backup-retirement-drafts.create", true, 2, 10, retirement),
		offsiteRetirementResponse: operationResponse(t, "api.v1.backup-offsite-retirements.stage", true, 2, 7, offsiteRetirement),
		offsiteDryRunResponse:     operationResponse(t, "api.v1.backup-offsite-retirements.dry-run", false, 2, 7, offsiteDryRun),
		backupStatusResponse:      operationResponse(t, "api.v1.backups.status", false, 2, 7, backupStatus),
		backupJobResponse:         operationResponse(t, "api.v1.backups.run", true, 2, 8, backupJob),
		summaryResponse:           operationResponse(t, "api.v1.summary.get", false, 2, 7, summary),
		databaseResponse:          operationResponse(t, "api.v1.database-status.get", false, 2, 7, database),
		auditListResponse:         operationResponse(t, "api.v1.audit-checkpoints.list", false, 2, 7, auditList),
		auditVerifyResponse:       operationResponse(t, "api.v1.audit-history.verification", false, 2, 7, auditVerify),
		importResponse:            operationResponse(t, "api.v1.inventory-drafts.import", true, 2, 8, imported),
		diffResponse:              operationResponse(t, "api.v1.inventory-diffs.create", false, 2, 8, diff),
		exportResponse:            operationResponse(t, "api.v1.inventory-exports.create", true, 2, 9, exported),
		planResponse:              operationResponse(t, "api.v1.plans.create", true, plan.Binding.RecoveryEpoch, plan.Binding.StateRevision, plan),
		runResponse:               operationResponse(t, "api.v1.runs.get", run.Changed, run.RecoveryEpoch, run.StateRevision, phase4TestPresentation(run)),
	}
}

func operationResponse[T any](t *testing.T, command string, changed bool, epoch, revision int64, data T) localapi.TypedResponse[T] {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "synthetic-build"}, func() (string, error) { return "request-server-36", nil })
	envelope, err := factory.SuccessWithRequestID(command, "request-server-36", changed, epoch, revision, data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return localapi.TypedResponse[T]{Raw: append(raw, '\n'), Result: envelope, Data: data}
}

func TestInventoryImportJSONPreservesRemoteBytesAndExactFileContent(t *testing.T) {
	operations := successfulControlOperations(t)
	files := &stubFileReader{content: []byte("{\r\n  \"schema\": \"synthetic\"\r\n}\r\n")}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{
		"inventory", "import", "--config", "profile.json", "--file", "/tmp/inventory π.json", "--format", "typed-json", "--source-revision", "source-1", "--captured-at", "2026-09-08T06:00:00Z", "--idempotency-key", "opaque-1", "--output", "json",
	}, nil, WithControlOperations(operations, files))
	if code != 0 || stdout != string(operations.importResponse.Raw) || stderr != "" || operations.importRequest.Content != string(files.content) || files.calls != 1 {
		t.Fatalf("result = %d %q %q request=%#v", code, stdout, stderr, operations.importRequest)
	}
}

func TestDiffSelectorAndFileFailuresMakeNoRequest(t *testing.T) {
	for _, args := range [][]string{
		{"inventory", "diff", "--config", "profile.json"},
		{"inventory", "diff", "--config", "profile.json", "--draft-id", "d", "--draft-revision", "1", "--file", "/tmp/x"},
		{"inventory", "diff", "--config", "profile.json", "--file", "/tmp/x", "--format", "typed-json", "--source-revision", "s", "--captured-at", "not-a-time"},
	} {
		operations := successfulControlOperations(t)
		code, stdout, stderr := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(operations, &stubFileReader{content: []byte("{}")}))
		if code != 2 || operations.calls != 0 || strings.Contains(stdout+stderr, "/tmp/x") {
			t.Fatalf("unsafe selector result: %d %q %q calls=%d", code, stdout, stderr, operations.calls)
		}
	}
	operations := successfulControlOperations(t)
	files := &stubFileReader{err: errors.New("private-path-canary")}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), []string{"inventory", "diff", "--config", "profile.json", "--file", "/tmp/private-path-canary", "--format", "typed-json", "--source-revision", "s", "--captured-at", "2026-09-08T06:00:00Z", "--output", "json"}, nil, WithControlOperations(operations, files))
	if code != 8 || operations.calls != 0 || bytes.Contains([]byte(stdout+stderr), []byte("private-path-canary")) {
		t.Fatalf("unsafe file failure = %d %q %q", code, stdout, stderr)
	}
}

func TestInventoryDraftSelectorsAndExpectedRevisionAreTyped(t *testing.T) {
	operations := successfulControlOperations(t)
	files := &stubFileReader{content: []byte("{}")}
	code, _, stderr := runTestAppWithOptions(t, context.Background(), []string{"inventory", "diff", "--config", "profile.json", "--draft-id", "draft-next", "--draft-revision", "2", "--output", "json"}, nil, WithControlOperations(operations, files))
	if code != 0 || stderr != "" || operations.diffRequest.Draft == nil || operations.diffRequest.Draft.DraftRevision != 2 || files.calls != 0 {
		t.Fatalf("diff route = %d %#v files=%d", code, operations.diffRequest, files.calls)
	}
	operations = successfulControlOperations(t)
	code, _, stderr = runTestAppWithOptions(t, context.Background(), []string{"inventory", "import", "--config", "profile.json", "--file", "/tmp/input", "--format", "typed-json", "--source-revision", "source-1", "--captured-at", "2026-09-08T06:00:00Z", "--idempotency-key", "opaque", "--expected-state-revision", "0", "--output", "json"}, nil, WithControlOperations(operations, files))
	if code != 0 || stderr != "" || operations.importRequest.ExpectedStateRevision == nil || *operations.importRequest.ExpectedStateRevision != 0 {
		t.Fatalf("import revision = %d %#v", code, operations.importRequest)
	}
}

func TestControlHumanOutputsMatchGoldens(t *testing.T) {
	operations := successfulControlOperations(t)
	files := &stubFileReader{content: []byte("{}")}
	tests := []struct {
		golden string
		args   []string
	}{
		{"status-human.golden", []string{"status", "--config", "profile.json"}},
		{"database-status-human.golden", []string{"database", "status", "--config", "profile.json"}},
		{"inventory-import-human.golden", []string{"inventory", "import", "--config", "profile.json", "--file", "/tmp/input", "--format", "typed-json", "--source-revision", "source-1", "--captured-at", "2026-09-08T06:00:00Z", "--idempotency-key", "opaque"}},
		{"inventory-diff-human.golden", []string{"inventory", "diff", "--config", "profile.json", "--draft-id", "draft-test", "--draft-revision", "1"}},
		{"inventory-export-human.golden", []string{"inventory", "export", "--config", "profile.json", "--draft-id", "draft-test", "--draft-revision", "1"}},
	}
	for _, test := range tests {
		code, stdout, stderr := runTestAppWithOptions(t, context.Background(), test.args, nil, WithControlOperations(operations, files))
		want, err := os.ReadFile(filepath.Join("testdata", test.golden))
		if err != nil {
			t.Fatal(err)
		}
		if code != 0 || stderr != "" || stdout != string(want) {
			t.Fatalf("%s = code %d stdout %q stderr %q want %q", test.golden, code, stdout, stderr, want)
		}
	}
}

func TestOffsiteRetirementDryRunRendersExactInspectableArtifact(t *testing.T) {
	operations := successfulControlOperations(t)
	files := &stubFileReader{content: syntheticGateRequest(t, generated.CommandNameBackupOffsiteRetirementDryRun)}
	args := []string{"backup", "offsite-retirement", "dry-run", "--config", "profile.json", "--file", "/tmp/dry-run.json"}
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(operations, files))
	for _, exact := range []string{
		"old-config  critical/generation-old/config",
		"critical/generation-old/data/a  8 bytes",
		"point-good  generation generation-good  key key-good",
		"Objects (1, reclaim 8 bytes, max 1 objects/8 bytes)",
		"Survivors (21 retained bytes",
	} {
		if !strings.Contains(stdout, exact) {
			t.Fatalf("human dry-run missing %q: %s", exact, stdout)
		}
	}
	if code != 0 || stderr != "" {
		t.Fatalf("human dry-run = code %d stderr %q stdout %q", code, stderr, stdout)
	}

	jsonArgs := append(append([]string(nil), args...), "--output", "json")
	code, stdout, stderr = runTestAppWithOptions(t, context.Background(), jsonArgs, nil, WithControlOperations(operations, files))
	for _, exact := range []string{`"ruleId":"old-config"`, `"prefix":"critical/generation-old/config"`, `"key":"critical/generation-old/data/a"`, `"referenceId":"key-good"`, `"dependencyDigest":"sha256:`} {
		if !strings.Contains(stdout, exact) {
			t.Fatalf("JSON dry-run missing %q: %s", exact, stdout)
		}
	}
	if code != 0 || stderr != "" {
		t.Fatalf("JSON dry-run = code %d stderr %q stdout %q", code, stderr, stdout)
	}
}
