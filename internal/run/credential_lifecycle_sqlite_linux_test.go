//go:build linux

package run

import (
	"context"
	"errors"
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
	if action == credentialref.ActionActivate {
		binding.RequiredDeniedConsumerIDs = []string{"consumer-denied"}
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
	core, err := NewCoreCredentialEffect(repository, store.NewAcknowledgementRepository(fixture.authority), UnavailableGateVerifier{}, UnavailableCredentialLifecycleVerifier{}, UnavailableCredentialRecoveryVerifier{}, fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	fixture.engine.credentialCore = core
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
				// Fresh engine composition reconciles persisted uncertainty without a
				// caller-supplied lease/intent or repeating the append.
				fixture.recompose()
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
