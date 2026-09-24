//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
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
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const lifecycleAcceptanceCanary = "synthetic-private-lifecycle-canary-135"

func lifecycleAcceptanceDigest(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(part))
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

type lifecycleAcceptanceAuthorizer struct{}

func (lifecycleAcceptanceAuthorizer) Authorize(_ context.Context, principal identity.Principal, request authorization.Request) (authorization.Decision, error) {
	branch := authorization.BranchHuman
	return authorization.Decision{PrincipalID: principal.ID, Action: request.Action, Target: request.Target, Allowed: true, Branch: &branch,
		ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, Risk: authorization.RiskControlPlane,
		StateRevision: func() int64 {
			if request.Plan != nil {
				return request.Plan.Binding.StateRevision
			}
			return 0
		}(),
		RecoveryEpoch: func() int64 {
			if request.Plan != nil {
				return request.Plan.Binding.RecoveryEpoch
			}
			return 0
		}(),
		PlanDigest: func() string {
			if request.Plan != nil {
				return request.Plan.PlanDigest
			}
			return ""
		}()}, nil
}

type lifecycleAcceptancePlanReader struct{ plans *planengine.Service }

func (reader lifecycleAcceptancePlanReader) Get(ctx context.Context, id string) (generated.Plan, error) {
	stored, err := reader.plans.Get(ctx, id)
	return stored.Plan, err
}
func (reader lifecycleAcceptancePlanReader) ValidateCurrent(ctx context.Context, plan generated.Plan) error {
	return reader.plans.ValidateCurrent(ctx, plan)
}

type lifecycleAcceptanceGate struct{ calls int }

func (gate *lifecycleAcceptanceGate) VerifySecretStep(_ context.Context, plan generated.Plan, operation generated.PlanOperation) error {
	if plan.AuthorizationBranch != string(authorization.BranchHuman) || plan.ExecutorMode != "central" || operation.AdapterID != "core.credential" {
		return errors.New("synthetic gate received a widened operation")
	}
	gate.calls++
	return nil
}

type lifecycleAcceptanceVerifier struct {
	actions []credentialref.LifecycleAction
}

func (verifier *lifecycleAcceptanceVerifier) Verify(_ context.Context, step runengine.ExactStepBinding, binding credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	if step.Step.OperationID != binding.OperationID || step.Step.ArtifactDigest != binding.CiphertextFingerprint || !credentialref.ValidNativeBindings(binding) {
		return nil, errors.New("native observation binding mismatch")
	}
	verifier.actions = append(verifier.actions, binding.Action)
	results := make([]credentialref.ConsumerVerification, 0, len(binding.ConsumerIDs)+len(binding.RequiredDeniedConsumerIDs))
	for _, consumer := range binding.NativeConsumers {
		value, err := credentialref.NewConsumerVerification(binding, consumer.ConsumerID, consumer.ProfileID, consumer.RoleID,
			lifecycleAcceptanceDigest("native-positive", string(binding.Action), consumer.ConsumerID), "loaded", "verified", true)
		if err != nil {
			return nil, err
		}
		results = append(results, value)
	}
	for _, reader := range binding.NativeDeniedReaders {
		value, err := credentialref.NewConsumerVerification(binding, reader.ConsumerID, reader.ProfileID, reader.RoleID,
			lifecycleAcceptanceDigest("native-denied", string(binding.Action), reader.ConsumerID), "reader-denied", "denied", false)
		if err != nil {
			return nil, err
		}
		results = append(results, value)
	}
	return results, nil
}

type lifecycleAcceptanceInstalledSource struct {
	t              *testing.T
	draft          store.CredentialImportDraft
	native         nativecredential.VerifyRecoveryRequest
	material       []byte
	custody, fence string
	enrollment     *acceptanceRecoveryEnrollment
	delegate       *acceptanceRecoverySource
	authority      installedRecoveryAuthority
}

func (source *lifecycleAcceptanceInstalledSource) CurrentInstalledRecovery(_ context.Context, request RecoveryCustodyRequest) (installedRecoveryAuthority, error) {
	binding := recovery.WitnessBinding{FormerHostID: "former-host", FormerInstanceID: "former-instance", ReplacementHostID: "replacement-host", ReplacementInstanceID: "replacement-instance", DraftID: request.Draft.DraftID, CiphertextFingerprint: request.Draft.CiphertextFingerprint, PlanDigest: request.PlanDigest, RunID: request.RunID, StepID: request.StepID, LeaseID: request.LeaseID, ChallengeID: "challenge-135", ReceiptID: "receipt-135", SourceAdmissionDigest: source.custody, FenceQualificationDigest: source.fence, PriorEpoch: request.PriorRecoveryEpoch, NewEpoch: request.RecoveryEpoch, StateRevision: request.StateRevision}
	source.delegate = newAcceptanceRecoverySource(source.t, binding, source.draft, source.native, source.material, source.enrollment)
	value, err := source.delegate.installedRecoverySource.authority.CurrentInstalledRecovery(context.Background(), request)
	if err == nil {
		source.authority = value
	}
	return value, err
}

func (source *lifecycleAcceptanceInstalledSource) LoadVerified(ctx context.Context, binding recovery.WitnessBinding, required []recovery.BoundaryRequirement, now time.Time) (installedRecoveryCandidate, error) {
	if source.delegate == nil {
		return installedRecoveryCandidate{}, recovery.ErrWitnessUnavailable
	}
	return source.delegate.installedRecoverySource.loader.LoadVerified(ctx, binding, required, now)
}

type lifecycleAcceptanceEnv struct {
	t            *testing.T
	path         string
	authority    *store.Store
	references   *store.CredentialRepository
	revisions    *store.PlanRepository
	declarations *change.Service
	lifecycle    api.CredentialLifecycleService
	principal    identity.Principal
	human        identity.Principal
	clock        func() time.Time
	now          *time.Time
	machineID    string
	gate         *lifecycleAcceptanceGate
	verifier     runengine.CredentialLifecycleVerifier
	recovery     runengine.CredentialRecoveryVerifier
	plans        []generated.Plan
	runs         []generated.Run
	imports      []generated.CredentialImportSubmission
	requests     []generated.CredentialLifecycleRequest
	coordinates  int
}

type lifecycleAcceptanceNativeRequest struct {
	Step    runengine.ExactStepBinding     `json:"step"`
	Binding credentialref.LifecycleBinding `json:"binding"`
	Root    string                         `json:"root"`
}

type lifecycleAcceptanceNativeResponse struct {
	Results []credentialref.ConsumerVerification `json:"results,omitempty"`
	Error   string                               `json:"error,omitempty"`
}

type lifecycleAcceptanceNativeProcessVerifier struct{ coordinate, root string }

func (verifier lifecycleAcceptanceNativeProcessVerifier) Verify(_ context.Context, step runengine.ExactStepBinding, binding credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	requestPath, responsePath := filepath.Join(verifier.coordinate, "verify-request.json"), filepath.Join(verifier.coordinate, "verify-response.json")
	request, err := json.Marshal(lifecycleAcceptanceNativeRequest{Step: step, Binding: binding, Root: verifier.root})
	if err != nil || os.WriteFile(requestPath, request, 0o644) != nil || os.Chmod(requestPath, 0o644) != nil {
		return nil, errors.New("native verifier request unavailable")
	}
	_ = os.Remove(responsePath)
	executable, err := os.Executable()
	if err != nil {
		return nil, errors.New("native verifier executable unavailable")
	}
	command := exec.Command("/usr/sbin/runuser", "-u", "vsk-labs", "--", executable, "-test.run=^TestLifecycleAcceptanceNativeVerifierHelper$")
	command.Env = append(os.Environ(), "VSK135_NATIVE_HELPER=1", "VSK135_NATIVE_REQUEST="+requestPath, "VSK135_NATIVE_RESPONSE="+responsePath)
	var diagnostics bytes.Buffer
	command.Stdout, command.Stderr = &diagnostics, &diagnostics
	if command.Run() != nil {
		_ = os.WriteFile(filepath.Join(verifier.coordinate, "debug"), append([]byte("helper-process\n"), diagnostics.Bytes()...), 0o600)
		return nil, errors.New("native verifier process failed")
	}
	raw, err := os.ReadFile(responsePath)
	var response lifecycleAcceptanceNativeResponse
	if err != nil || json.Unmarshal(raw, &response) != nil || response.Error != "" {
		_ = os.WriteFile(filepath.Join(verifier.coordinate, "debug"), []byte(response.Error+"\n"), 0o600)
		return nil, errors.New("native verifier rejected lifecycle")
	}
	return response.Results, nil
}

func TestLifecycleAcceptanceNativeVerifierHelper(t *testing.T) {
	if os.Getenv("VSK135_NATIVE_HELPER") != "1" {
		t.Skip("internal disposable lifecycle verifier helper")
	}
	raw, err := os.ReadFile(os.Getenv("VSK135_NATIVE_REQUEST"))
	var request lifecycleAcceptanceNativeRequest
	decodeErr := json.Unmarshal(raw, &request)
	if err != nil || decodeErr != nil || filepath.Clean(request.Root) != request.Root {
		t.Fatalf("invalid native verifier helper request: read=%v decode=%v root=%q", err, decodeErr, request.Root)
	}
	native, err := nativecredential.NewInstalledNativeLifecycleVerifier(context.Background(), request.Root, 21141)
	response := lifecycleAcceptanceNativeResponse{}
	if err != nil {
		response.Error = "constructor"
	} else {
		response.Results, err = native.VerifyNative(context.Background(), nativecredential.NativeVerificationStep{OperationID: request.Step.Step.OperationID, OperationType: request.Step.Step.OperationType, TargetID: request.Step.Step.TargetID, ArtifactDigest: request.Step.Step.ArtifactDigest, PlanDigest: request.Step.Plan.PlanDigest, RunID: request.Step.Run.RunID, StepID: request.Step.Step.StepID}, request.Binding)
		if err != nil {
			response.Error = "verification"
		}
	}
	body, marshalErr := json.Marshal(response)
	if marshalErr != nil || os.WriteFile(os.Getenv("VSK135_NATIVE_RESPONSE"), body, 0o600) != nil {
		t.Fatal("native verifier helper response unavailable")
	}
}

func newLifecycleAcceptanceEnv(t *testing.T) *lifecycleAcceptanceEnv {
	t.Helper()
	ctx := context.Background()
	directory, err := os.MkdirTemp("/var/tmp", "vsk135-lifecycle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	if err := os.Mkdir(filepath.Join(directory, "credential-drafts"), 0o700); err != nil {
		t.Fatal(err)
	}
	// The engine converts its logical lease expiry into a real context deadline.
	// Anchor the disposable process test at invocation time so the fixture does
	// not start with an already-expired lease after its original authoring date.
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "lifecycle-acceptance", BuildVersion: "lifecycle-acceptance", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	references := store.NewCredentialRepository(authority)
	revisions := store.NewPlanRepository(authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), clock)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := api.NewCredentialLifecycleService(references, revisions, declarations, lifecycleAcceptanceAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil || len(strings.TrimSpace(string(machine))) != 32 {
		t.Fatalf("machine identity unavailable: %v", err)
	}
	return &lifecycleAcceptanceEnv{t: t, path: path, authority: authority, references: references, revisions: revisions, declarations: declarations, lifecycle: lifecycle,
		principal: identity.Principal{ID: "operator-135", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman},
		human:     identity.Principal{ID: "human-135", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman},
		clock:     clock, now: &now, machineID: strings.TrimSpace(string(machine)), gate: &lifecycleAcceptanceGate{}, verifier: &lifecycleAcceptanceVerifier{},
		recovery: runengine.UnavailableCredentialRecoveryVerifier{}}
}

func (env *lifecycleAcceptanceEnv) importDraft(version, suffix string, private []byte) generated.CredentialImportSubmission {
	env.t.Helper()
	directory := filepath.Dir(env.path)
	root := filepath.Join(directory, "credential-drafts")
	if err := os.Chown(directory, 0, 0); err != nil {
		env.t.Fatal(err)
	}
	if err := os.Chown(root, 0, 0); err != nil {
		env.t.Fatal(err)
	}
	current, err := env.revisions.CurrentRevision(context.Background())
	if err != nil {
		env.t.Fatal(err)
	}
	input := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ReferenceID: "reference-135", ConsumerID: "consumer-a", PurposeID: "purpose-135", TargetID: "target-135", ResolverID: "native-systemd", MaterialVersion: version, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "import-" + suffix}
	input.TargetDigest = credentialref.ImportTargetDigest(input)
	value, err := newProductionCredentialImporter(env.references, env.revisions, env.path, 0).Import(context.Background(), input, append([]byte(nil), private...), env.principal)
	if err != nil {
		env.t.Fatal(err)
	}
	env.imports = append(env.imports, value)
	return value
}

func (env *lifecycleAcceptanceEnv) configureNative(version string) {
	env.t.Helper()
	name := credentialref.LoadedNameForVersion("consumer-a", "reference-135", version)
	root := filepath.Join(filepath.Dir(env.path), "credential-drafts")
	env.coordinates++
	coordinate := os.Getenv("VSK135_COORDINATOR")
	if coordinate == "" || filepath.Clean(coordinate) != coordinate {
		env.t.Fatal("native root coordinator unavailable")
	}
	request := filepath.Join(coordinate, "request-"+strconv.Itoa(env.coordinates))
	if err := os.WriteFile(request, []byte(name+"\n"+root+"\n"), 0o600); err != nil {
		env.t.Fatal(err)
	}
	ready := filepath.Join(coordinate, "ready-"+strconv.Itoa(env.coordinates))
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			env.t.Fatal("native root coordinator timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
	nativeRoot := os.Getenv("VSK135_NATIVE_ROOT")
	if nativeRoot == "" || filepath.Clean(nativeRoot) != nativeRoot {
		env.t.Fatal("native verifier root unavailable")
	}
	env.verifier = lifecycleAcceptanceNativeProcessVerifier{coordinate: coordinate, root: nativeRoot}
}

func (env *lifecycleAcceptanceEnv) nativeReaders() (*[]generated.CredentialNativeConsumer, *[]generated.CredentialNativeDeniedReader) {
	positives := []generated.CredentialNativeConsumer{
		{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-a", TargetID: "target-135", HostMachineID: env.machineID, UnitName: "vsk141-alpha.service", ServiceUID: 21142, ServiceGID: 21142, ProfileID: "profile-native", RoleID: "role-alpha"},
		{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-b", TargetID: "target-135", HostMachineID: env.machineID, UnitName: "vsk141-beta.service", ServiceUID: 21143, ServiceGID: 21143, ProfileID: "profile-native", RoleID: "role-beta"},
	}
	denied := []generated.CredentialNativeDeniedReader{
		{Schema: generated.SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "denied-a", TargetID: "target-135", HostMachineID: env.machineID, ReaderUID: 21144, ReaderGID: 21144, ProfileID: "profile-native", RoleID: "role-denied-a"},
		{Schema: generated.SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "denied-b", TargetID: "target-135", HostMachineID: env.machineID, ReaderUID: 21145, ReaderGID: 21145, ProfileID: "profile-native", RoleID: "role-denied-b"},
	}
	return &positives, &denied
}

func (env *lifecycleAcceptanceEnv) request(action, version, key string) generated.CredentialLifecycleRequest {
	current, err := env.revisions.CurrentRevision(context.Background())
	if err != nil {
		env.t.Fatal(err)
	}
	value := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", Action: action, ReferenceID: "reference-135", MaterialVersion: version,
		ResolverID: "native-systemd", TargetID: "target-135", ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: key,
		ConsumerIDs: []string{}, RequiredDeniedConsumerIDs: []string{}}
	return value
}

func (env *lifecycleAcceptanceEnv) apply(input generated.CredentialLifecycleRequest) generated.Run {
	env.t.Helper()
	input.TargetDigest = credentialref.LifecycleTargetDigest(input)
	if input.TargetDigest == "" {
		env.t.Fatalf("invalid lifecycle request: %+v", input)
	}
	env.requests = append(env.requests, input)
	submission, err := env.lifecycle.CreateDraft(context.Background(), input, env.principal)
	if err != nil {
		env.t.Fatalf("create %s draft: %v", input.Action, err)
	}
	declaration, err := env.declarations.Get(context.Background(), submission.ChangeID, 1)
	if err != nil {
		env.t.Fatal(err)
	}
	current, err := env.revisions.CurrentRevision(context.Background())
	if err != nil {
		env.t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(env.revisions)
	if err != nil {
		env.t.Fatal(err)
	}
	fingerprint, err := observations.CurrentFingerprint(context.Background(), declaration.DeclarationID, declaration.Operations)
	if err != nil {
		env.t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{Repository: env.revisions, Observations: observations, Clock: env.clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		env.t.Fatal(err)
	}
	created, err := plans.Create(context.Background(), planengine.AuthorScope{PrincipalID: env.principal.ID, PrincipalMethod: env.principal.Method, AgentSessionID: "session-135"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID, DeclarationRevision: declaration.Revision, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: "plan-" + input.IdempotencyKey, Extensions: declaration.Extensions})
	if err != nil {
		env.t.Fatalf("plan %s: %v", input.Action, err)
	}
	plan := created.Plan
	acknowledger, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(env.authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: env.clock})
	if err != nil {
		env.t.Fatal(err)
	}
	card, err := acknowledger.Request(context.Background(), acknowledgement.Scope{Human: env.human, AuthorityID: "authority-135", Nonce: "nonce-" + input.IdempotencyKey}, plan.PlanID)
	if err != nil {
		env.t.Fatal(err)
	}
	approved, err := acknowledger.Decide(context.Background(), acknowledgement.Candidate{Human: env.human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove,
		PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, Nonce: card.Nonce,
		StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(env.t, plan.ExpiresAt), DecidedAt: env.clock()})
	if err != nil {
		env.t.Fatal(err)
	}
	core, err := runengine.NewCoreCredentialEffect(env.references, store.NewAcknowledgementRepository(env.authority), env.gate, env.verifier, env.recovery, env.clock)
	if err != nil {
		env.t.Fatal(err)
	}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(env.authority), Plans: plans, Admission: runengine.NewAdmissionGate(acknowledger, env.clock), Adapters: adapter.NewRegistry(), CredentialCore: core, Clock: env.clock})
	if err != nil {
		env.t.Fatal(err)
	}
	branch := string(authorization.BranchHuman)
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-" + input.IdempotencyKey, PrincipalID: env.human.ID,
		Action: string(authorization.ActionExecute), TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1,
		RecoveryEpoch: plan.Binding.RecoveryEpoch, PlanDigest: plan.PlanDigest, DecidedAt: env.clock().Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	humanID := env.human.ID
	result, err := engine.Submit(context.Background(), runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: "run-" + input.IdempotencyKey, Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved,
		Attribution: audit.Attribution{AuthenticatedPrincipalID: env.principal.ID, AuthenticatedPrincipalMethod: env.principal.Method, ResponsibleHumanPrincipalID: &humanID, Agent: &audit.AgentMetadata{Name: "codex", SessionID: "session-135"}}})
	if err != nil || result.Status != "succeeded" {
		env.t.Fatalf("apply %s: run=%+v err=%v", input.Action, result, err)
	}
	env.plans, env.runs = append(env.plans, plan), append(env.runs, result)
	return result
}

func mustAcceptanceTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func (env *lifecycleAcceptanceEnv) enterRecoveryEpoch() {
	if err := env.authority.PrepareRecoveryAuditEpoch(context.Background(), 1, audit.Fingerprint(lifecycleAcceptanceDigest("checkpoint")), audit.Fingerprint(lifecycleAcceptanceDigest("decision"))); err != nil {
		env.t.Fatal(err)
	}
	if err := env.authority.Close(); err != nil {
		env.t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", env.path)
	if err != nil {
		env.t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE system_meta SET recovery_epoch=1 WHERE id=1`); err != nil {
		_ = db.Close()
		env.t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		env.t.Fatal(err)
	}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: env.path, Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "lifecycle-acceptance", BuildVersion: "lifecycle-acceptance", Clock: env.clock})
	if err != nil {
		env.t.Fatal(err)
	}
	env.t.Cleanup(func() { _ = authority.Close() })
	env.authority = authority
	env.references, env.revisions = store.NewCredentialRepository(authority), store.NewPlanRepository(authority)
	env.declarations, err = change.NewService(store.NewDeclarationRepository(authority), env.clock)
	if err != nil {
		env.t.Fatal(err)
	}
	env.lifecycle, err = api.NewCredentialLifecycleService(env.references, env.revisions, env.declarations, lifecycleAcceptanceAuthorizer{})
	if err != nil {
		env.t.Fatal(err)
	}
}

func (env *lifecycleAcceptanceEnv) enterReplacementAuthority() {
	env.t.Helper()
	replacement, err := os.MkdirTemp("/var/tmp", "vsk135-replacement-")
	if err != nil {
		env.t.Fatal(err)
	}
	env.t.Cleanup(func() { _ = os.RemoveAll(replacement) })
	if err := os.Chmod(replacement, 0o700); err != nil {
		env.t.Fatal(err)
	}
	snapshot := filepath.Join(replacement, "control.db")
	db, err := sql.Open("sqlite3", env.path)
	if err != nil {
		env.t.Fatal(err)
	}
	if _, err := db.Exec(`VACUUM INTO ?`, snapshot); err != nil {
		_ = db.Close()
		env.t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		env.t.Fatal(err)
	}
	if err := env.authority.Close(); err != nil {
		env.t.Fatal(err)
	}
	authority, err := store.Open(context.Background(), store.Config{DatabasePath: snapshot, Mode: store.OpenExisting, ExpectedUID: 0, ToolVersion: "lifecycle-acceptance", BuildVersion: "lifecycle-acceptance", Clock: env.clock})
	if err != nil {
		env.t.Fatal(err)
	}
	env.t.Cleanup(func() { _ = authority.Close() })
	env.path, env.authority = snapshot, authority
	env.references, env.revisions = store.NewCredentialRepository(authority), store.NewPlanRepository(authority)
	env.declarations, err = change.NewService(store.NewDeclarationRepository(authority), env.clock)
	if err != nil {
		env.t.Fatal(err)
	}
	env.lifecycle, err = api.NewCredentialLifecycleService(env.references, env.revisions, env.declarations, lifecycleAcceptanceAuthorizer{})
	if err != nil {
		env.t.Fatal(err)
	}
}

func (env *lifecycleAcceptanceEnv) enterReplacementHost() {
	env.t.Helper()
	directory := filepath.Dir(env.path)
	root := filepath.Join(directory, "credential-drafts")
	formerRoot := filepath.Join(directory, "former-credential-drafts")
	if err := os.Rename(root, formerRoot); err != nil && !os.IsNotExist(err) {
		env.t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		env.t.Fatal(err)
	}
	const hostKey = "/var/lib/systemd/credential.secret"
	formerKey := filepath.Join(directory, "former-systemd-credential.secret")
	if err := os.Rename(hostKey, formerKey); err != nil {
		env.t.Fatal(err)
	}
	setup := exec.Command("/usr/bin/systemd-creds", "setup")
	setup.Stdout, setup.Stderr = io.Discard, io.Discard
	if err := setup.Run(); err != nil {
		env.t.Fatal("replacement host key setup failed")
	}
	env.t.Cleanup(func() {
		_ = os.Remove(hostKey)
		if err := os.Rename(formerKey, hostKey); err != nil {
			env.t.Error(err)
		}
	})
}

func (env *lifecycleAcceptanceEnv) installRecoveryVerifier(draftID string, material []byte) *lifecycleAcceptanceInstalledSource {
	draft, err := env.references.GetImportDraftByID(context.Background(), draftID)
	if err != nil {
		env.t.Fatal(err)
	}
	stable := recovery.WitnessBinding{FormerHostID: "former-host", FormerInstanceID: "former-instance", ReplacementHostID: "replacement-host", ReplacementInstanceID: "replacement-instance", DraftID: draft.DraftID, CiphertextFingerprint: draft.CiphertextFingerprint, PriorEpoch: draft.RecoveryEpoch - 1, NewEpoch: draft.RecoveryEpoch}
	enrollment := newAcceptanceRecoveryEnrollment(env.t, stable)
	dynamic := &lifecycleAcceptanceInstalledSource{t: env.t, draft: draft, native: nativecredential.VerifyRecoveryRequest{Name: draft.CiphertextName, CiphertextDirectory: filepath.Join(filepath.Dir(env.path), "credential-drafts"), ExpectedUID: 0, ExpectedFingerprint: draft.CiphertextFingerprint}, material: material, custody: enrollment.sourceAdmissionDigest, fence: enrollment.fenceQualificationDigest, enrollment: enrollment}
	source := &installedRecoverySource{authority: dynamic, loader: dynamic, ciphertextRoot: filepath.Join(filepath.Dir(env.path), "credential-drafts"), ownerUID: uint32(os.Geteuid()), clock: time.Now, compare: nativecredential.VerifyRecoveredDraft}
	verifier, err := NewRecoveryCustodyVerifier(env.references, env.revisions, source)
	if err != nil {
		env.t.Fatal(err)
	}
	env.recovery = verifier
	return dynamic
}

func TestFullCredentialLifecycleAcceptance(t *testing.T) {
	if os.Getenv("VSK135_LIFECYCLE_ACCEPTANCE") != "1" {
		t.Skip("requires disposable root systemd lifecycle fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("disposable lifecycle capstone coordinator must run as root")
	}
	env := newLifecycleAcceptanceEnv(t)
	material := []byte(lifecycleAcceptanceCanary)
	t.Cleanup(func() {
		for index := range material {
			material[index] = 0
		}
	})
	if _, err := productionAdapterRegistry().ResolveCredentialResolver("onepassword-a", "consumer-provider", "profile-provider"); err == nil {
		t.Fatal("optional provider unexpectedly registered")
	}
	if err := (runengine.UnavailableGateVerifier{}).VerifySecretStep(context.Background(), generated.Plan{}, generated.PlanOperation{}); err == nil {
		t.Fatal("production live gate unexpectedly available")
	}

	v1 := env.importDraft("version-1", "v1", material)
	provider := env.request("credential.stage", "version-1", "provider-stage-v1")
	provider.DraftID, provider.ConsumerIDs, provider.ResolverID = &v1.DraftID, []string{"consumer-provider"}, "onepassword-a"
	provider.TargetDigest = credentialref.LifecycleTargetDigest(provider)
	beforeProvider, err := env.revisions.CurrentRevision(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.lifecycle.CreateDraft(context.Background(), provider, env.principal); err == nil {
		t.Fatal("optional provider lifecycle reached the native authority path")
	}
	afterProvider, err := env.revisions.CurrentRevision(context.Background())
	if err != nil || beforeProvider != afterProvider {
		t.Fatalf("optional provider denial appended authority state: before=%+v after=%+v err=%v", beforeProvider, afterProvider, err)
	}

	stage := env.request("credential.stage", "version-1", "stage-v1")
	stage.DraftID, stage.ConsumerIDs = &v1.DraftID, []string{"consumer-a", "consumer-b"}
	env.apply(stage)
	staged, err := env.references.GetCredentialVersion(context.Background(), "reference-135", "version-1")
	if err != nil || staged.Status != "staged" || staged.ActivatedAt != nil {
		t.Fatalf("stage was not inert: %+v %v", staged, err)
	}

	activate := env.request("credential.activate", "version-1", "activate-v1")
	activate.ConsumerIDs, activate.RequiredDeniedConsumerIDs = []string{"consumer-a", "consumer-b"}, []string{"denied-a", "denied-b"}
	activate.NativeConsumers, activate.NativeDeniedReaders = env.nativeReaders()
	env.configureNative("version-1")
	env.apply(activate)

	v2 := env.importDraft("version-2", "v2", material)
	stageV2 := env.request("credential.stage", "version-2", "stage-v2")
	stageV2.DraftID, stageV2.ConsumerIDs = &v2.DraftID, []string{"consumer-a", "consumer-b"}
	env.apply(stageV2)
	prior := "version-1"
	rotate := env.request("credential.rotate", "version-2", "rotate-v2")
	rotate.DraftID, rotate.PriorMaterialVersion, rotate.OverlapSeconds = &v2.DraftID, &prior, 900
	rotate.ConsumerIDs, rotate.RequiredDeniedConsumerIDs = []string{"consumer-a", "consumer-b"}, []string{"denied-a", "denied-b"}
	rotate.NativeConsumers, rotate.NativeDeniedReaders = env.nativeReaders()
	env.configureNative("version-2")
	env.apply(rotate)
	oldDuringOverlap, err := env.references.GetCredentialVersion(context.Background(), "reference-135", "version-1")
	if err != nil || oldDuringOverlap.Status != "active" {
		t.Fatalf("rotation removed old overlap version: %+v %v", oldDuringOverlap, err)
	}
	*env.now = env.now.Add(899 * time.Second)
	oldBeforeDeadline, err := env.references.GetCredentialVersion(context.Background(), "reference-135", "version-1")
	if err != nil || oldBeforeDeadline.Status != "active" {
		t.Fatalf("old version did not survive the declared overlap: %+v %v", oldBeforeDeadline, err)
	}
	*env.now = env.now.Add(time.Second)

	revoke := env.request("credential.revoke", "version-1", "revoke-v1")
	env.apply(revoke)
	v1Final, err := env.references.GetCredentialVersion(context.Background(), "reference-135", "version-1")
	if err != nil || v1Final.Status != "revoked" {
		t.Fatalf("old version not revoked: %+v %v", v1Final, err)
	}
	v2Final, err := env.references.GetCredentialVersion(context.Background(), "reference-135", "version-2")
	if err != nil || v2Final.Status != "active" {
		t.Fatalf("active successor shadowed: %+v %v", v2Final, err)
	}

	env.enterReplacementAuthority()
	env.enterRecoveryEpoch()
	env.enterReplacementHost()
	recoveryDraft := env.importDraft("version-2", "recovery-v2", material)
	priorEpoch := int64(0)
	source := env.installRecoveryVerifier(recoveryDraft.DraftID, material)
	custody, fence := source.custody, source.fence
	recover := env.request("credential.recover", "version-2", "recover-v2")
	recover.DraftID, recover.ConsumerIDs = &recoveryDraft.DraftID, []string{"consumer-a"}
	recover.PriorRecoveryEpoch, recover.CustodyProofDigest, recover.FormerControllerFenceDigest = &priorEpoch, &custody, &fence
	env.apply(recover)
	current, err := env.revisions.CurrentRevision(context.Background())
	if err != nil || current.RecoveryEpoch != 1 || source.delegate == nil {
		t.Fatalf("recovery changed epoch or skipped installed source: %+v err=%v", current, err)
	}
	beforeReplayVersions, err := env.references.ListCredentialVersions(context.Background(), "reference-135", 1)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := source.LoadVerified(context.Background(), source.authority.Binding, source.authority.Required, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := replay.consume(context.Background(), func(private io.ReadCloser) error { return private.Close() }); err == nil {
		t.Fatal("one-use recovery custody replay accepted")
	}
	afterReplayVersions, err := env.references.ListCredentialVersions(context.Background(), "reference-135", 1)
	if err != nil || len(afterReplayVersions) != len(beforeReplayVersions) {
		t.Fatalf("denied recovery replay appended a credential version: before=%d after=%d err=%v", len(beforeReplayVersions), len(afterReplayVersions), err)
	}
	oldEpoch, err := env.references.ListCredentialVersions(context.Background(), "reference-135", 0)
	latestStatus := map[string]string{}
	for _, version := range oldEpoch {
		latestStatus[version.MaterialVersion] = version.Status
	}
	if err != nil || len(oldEpoch) != 5 || latestStatus["version-1"] != "revoked" || latestStatus["version-2"] != "active" {
		t.Fatalf("recovery changed prior epoch statuses: %+v err=%v", oldEpoch, err)
	}
	newEpoch, err := env.references.ListCredentialVersions(context.Background(), "reference-135", 1)
	if err != nil || len(newEpoch) != 1 || newEpoch[0].MaterialVersion != "version-2" || newEpoch[0].Status != "staged" || newEpoch[0].ActivatedAt != nil {
		t.Fatalf("recovery cut over instead of staging: %+v err=%v", newEpoch, err)
	}

	if env.gate.calls != 3 {
		t.Fatalf("wrong gate calls: %d", env.gate.calls)
	}
	db, err := sql.Open("sqlite3", env.path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var positive, denied, restart, recoveryRecords int
	if err := db.QueryRow(`SELECT count(*) FROM credential_consumer_verifications WHERE result='verified'`).Scan(&positive); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM credential_consumer_verifications WHERE result='denied'`).Scan(&denied); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM credential_consumer_verifications WHERE result='verified' AND restart_observed=1`).Scan(&restart); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM credential_recovery_records`).Scan(&recoveryRecords); err != nil {
		t.Fatal(err)
	}
	if positive != 4 || denied != 4 || restart != 4 || recoveryRecords != 1 {
		t.Fatalf("incomplete lifecycle evidence: positive=%d denied=%d restart=%d recovery=%d", positive, denied, restart, recoveryRecords)
	}

	public, err := json.Marshal(struct {
		Imports  []generated.CredentialImportSubmission
		Requests []generated.CredentialLifecycleRequest
		Plans    []generated.Plan
		Runs     []generated.Run
		Args     []string
	}{env.imports, env.requests, env.plans, env.runs, os.Args})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(public, []byte(lifecycleAcceptanceCanary)) {
		t.Fatal("secret escaped public envelopes")
	}
	rows, err := db.Query(`SELECT canonical_payload FROM audit_events UNION ALL SELECT payload_bytes FROM outbox`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(payload, []byte(lifecycleAcceptanceCanary)) {
			t.Fatal("secret escaped audit or outbox surface")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		raw, readErr := os.ReadFile(env.path + suffix)
		if readErr != nil && !os.IsNotExist(readErr) {
			t.Fatal(readErr)
		}
		if bytes.Contains(raw, []byte(lifecycleAcceptanceCanary)) {
			t.Fatalf("secret escaped SQLite surface %s", suffix)
		}
	}
}
