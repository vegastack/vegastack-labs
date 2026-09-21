//go:build linux

package run

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// The fixture composes real declaration, binding, plan, acknowledgement, lease,
// run and credential repositories. No resolver or live consumer is registered.
func prepareSQLiteCredentialLifecycle(t *testing.T, fixture *sqliteRestartFixture, action credentialref.LifecycleAction) *store.CredentialRepository {
	t.Helper()
	ctx := context.Background()
	repository := store.NewCredentialRepository(fixture.authority)
	plansRepository := store.NewPlanRepository(fixture.authority)
	current, err := plansRepository.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := digest("credential-lifecycle-ciphertext")
	attribution := audit.Attribution{AuthenticatedPrincipalID: "principal-sqlite-restart", AuthenticatedPrincipalMethod: identity.LocalOSPeerMethod}
	var draftID *string
	if action == credentialref.ActionStage {
		input := generated.CredentialImportRequest{Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "lifecycle-import", ReferenceID: "reference-lifecycle", ConsumerID: "consumer-lifecycle", PurposeID: "purpose-lifecycle", TargetID: "target-lifecycle", ResolverID: "native-systemd", MaterialVersion: "version-lifecycle"}
		input.TargetDigest = credentialref.ImportTargetDigest(input)
		imported, err := repository.PutImportDraft(ctx, store.CredentialImportDraftRequest{Input: input, DraftID: "draft-lifecycle", CiphertextName: "ciphertext-lifecycle", CiphertextFingerprint: fingerprint, Expected: current, Attribution: attribution, KeyDigest: digest("lifecycle-import-key"), RequestDigest: digest("lifecycle-import-request")})
		if err != nil {
			t.Fatal(err)
		}
		draftID = &imported.DraftID
		current, err = plansRepository.CurrentRevision(ctx)
		if err != nil {
			t.Fatal(err)
		}
	}
	binding := credentialref.LifecycleBinding{OperationID: "operation-lifecycle", Action: action, DraftID: draftID, ReferenceID: "reference-lifecycle", ConsumerIDs: []string{"consumer-lifecycle"}, MaterialVersion: "version-lifecycle", ResolverID: "native-systemd", TargetID: "target-lifecycle", CiphertextFingerprint: fingerprint, StateRevision: current.StateRevision + 3, RecoveryEpoch: current.RecoveryEpoch}
	if draftID != nil {
		origin, err := repository.GetImportDraftByID(ctx, *draftID)
		if err != nil {
			t.Fatal(err)
		}
		binding.ImportDraftStateRevision = &origin.StateRevision
		binding.ImportDraftConsumerID = &origin.ConsumerID
		binding.ImportDraftPurposeID = &origin.PurposeID
	}
	if action == credentialref.ActionActivate {
		binding.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
		binding.NativeConsumers = []credentialref.NativeConsumerBinding{{ConsumerID: "consumer-lifecycle", TargetID: "target-lifecycle", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "lifecycle.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-lifecycle", RoleID: "role-lifecycle", LoadedName: credentialref.LoadedNameForVersion("consumer-lifecycle", binding.ReferenceID, binding.MaterialVersion)}}
		binding.NativeDeniedReaders = []credentialref.NativeDeniedReaderBinding{{ConsumerID: "consumer-denied", TargetID: "target-lifecycle", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-denied", RoleID: "role-denied"}}
	}
	extensions := []generated.ContractExtension{{Name: "x-credential-lifecycle", ValueDigest: credentialref.LifecycleManifestDigestOf(binding)}}
	declarations, err := change.NewService(store.NewDeclarationRepository(fixture.authority), fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	author := change.AuthorScope{PrincipalID: attribution.AuthenticatedPrincipalID, PrincipalMethod: attribution.AuthenticatedPrincipalMethod, AgentSessionID: "session-lifecycle"}
	revised, err := declarations.Revise(ctx, author, generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: "declaration-lifecycle-" + string(action), DeclarationType: "credential.lifecycle", ExpectedRevision: 1, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: binding.OperationID, OperationType: string(action), AdapterID: "core.credential", TargetID: binding.TargetID, InputDigest: fingerprint, ArtifactDigest: fingerprint, Idempotent: false}}, ReasonDigest: digest("lifecycle-reason"), Extensions: extensions})
	if err != nil {
		t.Fatal(err)
	}
	current, err = plansRepository.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.PutLifecycleDraft(ctx, store.CredentialLifecycleDraftRequest{DeclarationID: revised.Document.DeclarationID, DeclarationRevision: revised.Document.Revision, Binding: binding, Expected: current, Attribution: attribution, KeyDigest: digest("lifecycle-binding-key-" + string(action)), RequestDigest: digest("lifecycle-binding-request-" + string(action))})
	if err != nil {
		t.Fatal(err)
	}
	current, err = plansRepository.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(plansRepository)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := observations.CurrentFingerprint(ctx, revised.Document.DeclarationID, revised.Document.Operations)
	if err != nil {
		t.Fatal(err)
	}
	plans := fixture.newPlanService(plansRepository, observations)
	planned, err := plans.Create(ctx, planengine.AuthorScope{PrincipalID: author.PrincipalID, PrincipalMethod: author.PrincipalMethod, AgentSessionID: author.AgentSessionID}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: revised.Document.DeclarationID, DeclarationRevision: revised.Document.Revision, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: observation, IdempotencyKey: "plan-lifecycle-" + string(action), Extensions: extensions})
	if err != nil {
		t.Fatal(err)
	}
	fixture.plan = planned.Plan
	fixture.recompose()
	fixture.engine.credentialCore = sqliteCredentialCore(t, fixture, repository)
	// Round-trip the actual persisted binding before dispatch. This fails when
	// the reader confuses the member digest with the stored manifest digest.
	loaded, err := repository.GetLifecycleBinding(ctx, fixture.plan, binding.OperationID)
	if err != nil {
		t.Fatalf("stored lifecycle binding roundtrip: %v", err)
	}
	if loaded.Digest() != binding.Digest() {
		t.Fatal("stored binding changed")
	}
	fixture.request = fixture.submitRequest()
	fixture.request.Reference.IdempotencyKey = "submit-lifecycle-" + string(action)
	fixture.request.Attribution.ResponsibleHumanPrincipalID = &fixture.request.Acknowledgement.HumanID
	fixture.request.Attribution.Agent = &audit.AgentMetadata{Name: "codex", SessionID: "session-lifecycle"}
	if _, err := repository.GetReference(ctx, binding.ReferenceID); action == credentialref.ActionStage && store.Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("draft activated reference: %v", err)
	}
	return repository
}

func TestSQLiteCredentialLifecycleEngineAdmissionAndAppend(t *testing.T) {
	for _, mode := range []string{"allowed", "missing-ack", "stale-plan", "interrupted-after-append"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newSQLiteRestartFixture(t, "human")
			repository := prepareSQLiteCredentialLifecycle(t, fixture, credentialref.ActionStage)
			switch mode {
			case "missing-ack":
				fixture.request.Acknowledgement = nil
			case "stale-plan":
				fixture.request.Reference.PlanDigest = digest("stale-plan")
			case "interrupted-after-append":
				fixture.engine.testAfterBoundary = func(boundary Boundary) error {
					if boundary == BoundaryEffectReturned {
						return errors.New("synthetic interruption")
					}
					return nil
				}
			}
			result, err := fixture.engine.Submit(context.Background(), fixture.request)
			versions, readErr := repository.ListCredentialVersions(context.Background(), "reference-lifecycle", 0)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if mode == "missing-ack" || mode == "stale-plan" {
				if err == nil || len(versions) != 0 {
					t.Fatalf("denied request appended: result=%+v err=%v versions=%d", result, err, len(versions))
				}
				return
			}
			if len(versions) != 1 || versions[0].Status != "staged" {
				t.Fatalf("stage did not append exactly once: %+v err=%v", versions, err)
			}
			assertSQLiteCredentialAudit(t, fixture)
			if mode == "allowed" {
				if err != nil || result.Status != "succeeded" {
					t.Fatalf("real engine stage failed: result=%+v err=%v", result, err)
				}
				prepareSQLiteCredentialLifecycle(t, fixture, credentialref.ActionActivate)
				blocked, err := fixture.engine.Submit(context.Background(), fixture.request)
				after, readErr := repository.ListCredentialVersions(context.Background(), "reference-lifecycle", 0)
				if Code(err) != generated.ErrorCodePrerequisiteBlocked || blocked.Status != "failed" || readErr != nil || len(after) != 1 || after[0].Status != "staged" {
					t.Fatalf("production verifier absence admitted activation: result=%+v err=%v versions=%+v read=%v", blocked, err, after, readErr)
				}
			} else {
				if err == nil {
					t.Fatal("interruption reported success")
				}
				// Close and reopen SQLite, then recompose the actual core so a
				// regression can neither hide behind a missing core nor repeat the append.
				fixture.restart(t)
				repository = store.NewCredentialRepository(fixture.authority)
				fixture.engine.credentialCore = sqliteCredentialCore(t, fixture, repository)
				if err := fixture.engine.Reconcile(context.Background()); err != nil {
					t.Fatal(err)
				}
				recovered, err := fixture.engine.Get(context.Background(), result.RunID)
				if err != nil || recovered.Status != "partial" {
					t.Fatalf("ambiguous append not recovery-required: %+v %v", recovered, err)
				}
				_, _ = fixture.engine.Submit(context.Background(), fixture.request)
				after, err := repository.ListCredentialVersions(context.Background(), "reference-lifecycle", 0)
				if err != nil || len(after) != 1 {
					t.Fatalf("ambiguous append repeated: %+v %v", after, err)
				}
			}
		})
	}
}

// This gate fixture represents only the external gate-verification boundary.
// Admission, consumed approval, durable intent and lease remain production state.
type sqliteLifecycleGate struct {
	fixture *sqliteRestartFixture
}

func (gate sqliteLifecycleGate) VerifySecretStep(ctx context.Context, plan generated.Plan, operation generated.PlanOperation) error {
	runs, err := store.NewRunRepository(gate.fixture.authority).ActiveRuns(ctx)
	if err != nil {
		return err
	}
	location := (&url.URL{Scheme: "file", Path: gate.fixture.config.DatabasePath}).String() + "?mode=ro"
	observer, err := sql.Open("sqlite3", location)
	if err != nil {
		return err
	}
	defer observer.Close()
	for _, run := range runs {
		if run.PlanID != plan.PlanID || run.Status != "running" || run.ExecutorMode != "central" || run.StateRevision != plan.Binding.StateRevision || run.RecoveryEpoch != plan.Binding.RecoveryEpoch {
			continue
		}
		for _, step := range run.Steps {
			if step.OperationID != operation.OperationID || step.Status != "running" || step.EffectState != "intent-recorded" {
				continue
			}
			var payload []byte
			err := observer.QueryRowContext(ctx, `SELECT leases.canonical_bytes FROM target_execution_leases AS leases JOIN plan_run_steps AS steps ON steps.active_lease_id=leases.lease_id WHERE steps.run_id=? AND steps.step_id=? AND steps.status='running' AND steps.effect_state='intent-recorded' AND leases.status='active'`, run.RunID, step.StepID).Scan(&payload)
			if err != nil {
				return err
			}
			var lease generated.ExecutorLease
			if err := json.Unmarshal(payload, &lease); err != nil {
				return err
			}
			if lease.Status != "active" || generated.ValidateExecutorLeaseBinding(plan, run, lease) != nil {
				return errors.New("synthetic gate requires an exact persisted active lease")
			}
			return nil
		}
	}
	return errors.New("synthetic gate requires a persisted running intent")
}

func TestSQLiteCredentialLifecycleActivationBlocksWithoutConsumerVerifier(t *testing.T) {
	fixture := newSQLiteRestartFixture(t, "human")
	repository := prepareSQLiteCredentialLifecycle(t, fixture, credentialref.ActionStage)
	if result, err := fixture.engine.Submit(context.Background(), fixture.request); err != nil || result.Status != "succeeded" {
		t.Fatalf("stage failed: %+v %v", result, err)
	}
	prepareSQLiteCredentialLifecycle(t, fixture, credentialref.ActionActivate)
	core, err := NewCoreCredentialEffect(repository, store.NewAcknowledgementRepository(fixture.authority), sqliteLifecycleGate{fixture: fixture}, UnavailableCredentialLifecycleVerifier{}, UnavailableCredentialRecoveryVerifier{}, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	fixture.engine.credentialCore = core
	blocked, err := fixture.engine.Submit(context.Background(), fixture.request)
	var stable *Error
	if !errors.As(err, &stable) || stable.Code() != generated.ErrorCodePrerequisiteBlocked || stable.Target() != "credential-consumer-verifier-unavailable" || blocked.Status != "failed" {
		t.Fatalf("missing consumer verifier denial changed: result=%+v err=%v", blocked, err)
	}
	versions, err := repository.ListCredentialVersions(context.Background(), "reference-lifecycle", 0)
	if err != nil || len(versions) != 1 || versions[0].Status != "staged" {
		t.Fatalf("consumer absence appended or activated: %+v %v", versions, err)
	}
	reference, err := repository.GetReference(context.Background(), "reference-lifecycle")
	if err != nil || reference.Status != "staged" || reference.ActivatedAt != nil || len(reference.VerifiedConsumerIDs) != 0 {
		t.Fatalf("consumer absence changed durable status/evidence: %+v %v", reference, err)
	}
	assertSQLiteCredentialAudit(t, fixture)
}

func TestSQLiteCredentialVerifierPanicRecordsPartialWithoutSecretLeak(t *testing.T) {
	fixture := newSQLiteRestartFixture(t, "human")
	repository := prepareSQLiteCredentialLifecycle(t, fixture, credentialref.ActionStage)
	if result, err := fixture.engine.Submit(context.Background(), fixture.request); err != nil || result.Status != "succeeded" {
		t.Fatalf("stage failed: %+v %v", result, err)
	}
	prepareSQLiteCredentialLifecycle(t, fixture, credentialref.ActionActivate)
	canary := "private-verifier-value-" + strings.Repeat("s", 32)
	core, err := NewCoreCredentialEffect(repository, store.NewAcknowledgementRepository(fixture.authority), sqliteLifecycleGate{fixture: fixture}, lifecycleVerifierFunc(func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
		panic(canary)
	}), UnavailableCredentialRecoveryVerifier{}, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	fixture.engine.credentialCore = core
	result, err := fixture.engine.Submit(context.Background(), fixture.request)
	if Code(err) != generated.ErrorCodeRecoveryRequired || result.Status != "partial" || strings.Contains(err.Error(), canary) {
		t.Fatalf("verifier panic must become redacted effect-unknown partial: result=%+v err=%v", result, err)
	}
	versions, readErr := repository.ListCredentialVersions(context.Background(), "reference-lifecycle", 0)
	if readErr != nil || len(versions) != 1 || versions[0].Status != "staged" {
		t.Fatalf("uncertain verification appended an active version: %+v %v", versions, readErr)
	}
}

func sqliteCredentialCore(t *testing.T, fixture *sqliteRestartFixture, repository *store.CredentialRepository) *CoreCredentialEffect {
	t.Helper()
	core, err := NewCoreCredentialEffect(repository, store.NewAcknowledgementRepository(fixture.authority), UnavailableGateVerifier{}, UnavailableCredentialLifecycleVerifier{}, UnavailableCredentialRecoveryVerifier{}, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	return core
}

func assertSQLiteCredentialAudit(t *testing.T, fixture *sqliteRestartFixture) {
	t.Helper()
	// A read-only test observer checks durable public audit metadata. Writable
	// SQLite remains exclusively owned by the production Store under test.
	location := (&url.URL{Scheme: "file", Path: fixture.config.DatabasePath}).String() + "?mode=ro"
	observer, err := sql.Open("sqlite3", location)
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	var count int
	if err := observer.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='credential.version-applied' AND correlation_id='reference-lifecycle'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("missing or repeated credential audit result: %d %v", count, err)
	}
	var payload []byte
	if err := observer.QueryRow(`SELECT canonical_payload FROM audit_events WHERE event_type='credential.version-applied' AND correlation_id='reference-lifecycle'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var event audit.Event
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatal(err)
	}
	if event.HumanID == nil || *event.HumanID != fixture.request.Acknowledgement.HumanID || event.AgentName == nil || *event.AgentName != "codex" || event.AgentSessionID == nil || *event.AgentSessionID != "session-lifecycle" {
		t.Fatalf("credential audit lost human/agent attribution: %+v", event)
	}
}
