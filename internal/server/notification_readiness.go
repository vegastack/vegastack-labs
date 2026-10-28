package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubalerts"
	"github.com/vegastack/vegastack-labs/internal/adapter/slackalerts"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"sync"
	"time"
)

type notificationReadiness struct {
	monitor      *operationsMonitoring
	repo         *store.NotificationReadinessRepository
	declarations *change.Service
	slack        *slackalerts.Client
	github       func(githubalerts.Borrow) (*githubalerts.Client, error)
	mu           sync.Mutex
	results      map[string]adapter.ExactExecutionBinding
}

func (n *notificationReadiness) allowed(ctx context.Context) error {
	if n == nil || n.repo == nil {
		return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	health, healthErr := n.monitor.s.Health(ctx)
	if healthErr != nil || health.Mode != store.DatabaseReady || !health.MutationEnabled || health.RecoveryPending {
		return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	scope, e := store.NewGateRepository(n.monitor.s).GetAppliedProfileScope(ctx)
	if e != nil || !slices.Contains(scope.Capabilities, operations.ReadinessCapability(n.repo.Digest)) || !slices.Contains(scope.Capabilities, "credential.operations.readiness") {
		return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	return n.repo.CheckPolicy(ctx)
}
func (n *notificationReadiness) prepare(ctx context.Context, q generated.NotificationReadinessRequest) (generated.DeclarationRevision, error) {
	empty := generated.DeclarationRevision{}
	if e := n.allowed(ctx); e != nil {
		return empty, e
	}
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return empty, serviceFailure(generated.ErrorCodeAuthenticationRequired)
	}
	author := change.AuthorScope{PrincipalID: p.ID, PrincipalMethod: p.Method, AgentSessionID: q.RequestID}
	if identity.EffectivePrincipalKind(p) == identity.PrincipalAgent {
		author.AgentName = p.ID
	}
	actor, e := audit.NewAttribution(p, nil, nil)
	if e != nil {
		return empty, e
	}
	if identity.EffectivePrincipalKind(p) == identity.PrincipalAgent {
		actor.Agent = &audit.AgentMetadata{Name: p.ID, SessionID: q.RequestID}
	}
	current, e := store.NewPlanRepository(n.monitor.s).CurrentRevision(ctx)
	if e != nil || current != (store.RevisionToken{StateRevision: q.ExpectedStateRevision, RecoveryEpoch: q.RecoveryEpoch}) {
		return empty, serviceFailure(generated.ErrorCodePlanStale)
	}
	if q.Action == "evidence-draft" {
		if q.RunID == "" {
			return empty, serviceFailure(generated.ErrorCodeInputInvalid)
		}
		r, e := n.repo.Receipts(ctx, q.RunID, q.RecoveryEpoch)
		if e != nil {
			return empty, e
		}
		if _, e = n.repo.Bindings(ctx, current.StateRevision, current.RecoveryEpoch); e != nil {
			return empty, e
		}
		observed, e := operations.ValidateNotificationReceipts(r, n.repo.Digest, q.RecoveryEpoch, n.monitor.clock().UTC())
		if e != nil {
			return empty, e
		}
		draft, e := store.NewGateRepository(n.monitor.s).PutGateDraft(ctx, store.GateDraftRequest{EvidenceID: q.RequestID, GateID: "G-011", SubjectID: "scope", DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", SourceKind: "local", ProofClass: "live", ArtifactDigest: n.repo.Digest, Bundle: operations.NotificationBundle(r, observed), Expected: current, KeyDigest: operations.NotificationDigest([]string{q.RequestID, "key"}), RequestDigest: operations.NotificationDigest(q), Attribution: actor})
		if e != nil {
			return empty, e
		}
		d, e := gate.BuildEvidenceChange(draft, store.RevisionToken{StateRevision: draft.StateRevision, RecoveryEpoch: q.RecoveryEpoch})
		if e != nil {
			return empty, e
		}
		v, e := n.declarations.Revise(ctx, author, d)
		return v.Document, e
	}
	if q.Action != "canary-draft" || q.RunID != "" {
		return empty, serviceFailure(generated.ErrorCodeInputInvalid)
	}
	bindings, e := n.repo.Bindings(ctx, current.StateRevision+3, current.RecoveryEpoch)
	if e != nil {
		return empty, e
	}
	manifest := credentialref.ManifestDigest(bindings)
	id := "notification-test-" + operations.NotificationDigest(q)[7:39]
	d := generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: id, DeclarationType: "notification-readiness", ExpectedRevision: 1, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ReasonDigest: n.repo.Digest, Extensions: []generated.ContractExtension{{Name: "x-notification-readiness", ValueDigest: n.repo.Digest}, {Name: "x-credential-bindings", ValueDigest: manifest}}, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "notification-readiness", OperationType: operations.ReadinessOperation, AdapterID: operations.ReadinessAdapter, TargetID: n.repo.Policy.TargetID, InputDigest: credentialref.OperationManifestDigest(bindings, "notification-readiness"), ArtifactDigest: n.repo.Digest, Idempotent: false}}}
	v, e := n.declarations.Revise(ctx, author, d)
	if e != nil {
		return empty, e
	}
	_, e = store.NewCredentialRepository(n.monitor.s).StageStepBindings(ctx, store.CredentialBindingStageRequest{DeclarationID: id, DeclarationRevision: v.Document.Revision, Bindings: bindings, Expected: store.RevisionToken{StateRevision: v.Document.StateRevision, RecoveryEpoch: current.RecoveryEpoch}, Attribution: actor, KeyDigest: operations.NotificationDigest([]string{id, "bindings"}), RequestDigest: manifest})
	return v.Document, e
}
func (n *notificationReadiness) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
}
func (n *notificationReadiness) ExecuteBoundWithCredentials(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	empty := adapter.Effect{}
	if n == nil || len(values) != 2 || len(op.SecretReferences) != 2 {
		return empty, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	check := func() error {
		if e := n.allowed(ctx); e != nil {
			return e
		}
		_, _, e := n.repo.Current(ctx, op, b)
		return e
	}
	if e := check(); e != nil {
		return empty, e
	}
	var githubValue, slackValue *credentialref.Value
	for i, ref := range op.SecretReferences {
		if ref.Consumer != operations.ReadinessAdapter || values[i] == nil {
			return empty, serviceFailure(generated.ErrorCodeAuthorizationDenied)
		}
		switch ref.ID {
		case n.repo.Policy.PrimaryReferenceID:
			githubValue = values[i]
		case n.repo.Policy.SecondaryReferenceID:
			slackValue = values[i]
		default:
			return empty, serviceFailure(generated.ErrorCodeAuthorizationDenied)
		}
	}
	if githubValue == nil || slackValue == nil {
		return empty, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	if e := n.repo.Record(ctx, op, b, []operations.NotificationReceipt{}, true); e != nil {
		return empty, e
	}
	client, e := n.github(func(ctx context.Context, purpose, target string) (*credentialref.Value, error) {
		if purpose != "operations.github-issues.write" || target != operations.Digest(n.repo.Primary.Repository) {
			return nil, serviceFailure(generated.ErrorCodeAuthorizationDenied)
		}
		if e := check(); e != nil {
			return nil, e
		}
		return credentialref.NewValue(githubValue.Bytes())
	})
	if e != nil {
		return empty, e
	}
	correlation := "operations-" + operations.NotificationDigest([]string{b.RunID, b.StepID, n.repo.Digest})[7:39]
	receipts := []operations.NotificationReceipt{}
	for _, phase := range []string{"failure", "recovery"} {
		kind := audit.EventType("operations.alert.opened")
		if phase == "recovery" {
			kind = "operations.alert.closed"
		}
		event := audit.Event{Schema: audit.EventSchema, SchemaVersion: audit.EventSchemaVersion, EventID: 1, OccurredAt: n.monitor.clock().UTC().Format(time.RFC3339Nano), RecoveryEpoch: b.RecoveryEpoch, StateRevision: b.StateRevision, Type: kind, CorrelationID: correlation, PrincipalID: "server-notification-readiness", PrincipalMethod: "server-engine", Target: audit.Target{Kind: "operations-target", ID: n.repo.Digest}}
		r, e := client.DeliverReceipt(ctx, event)
		if e != nil {
			return empty, e
		}
		receipts = append(receipts, operations.NotificationReceipt{Route: "github", Phase: phase, ProviderID: r.IssueNumber, State: r.State, AcceptedAt: r.AcceptedAt.Format(time.RFC3339Nano), ResponseDigest: r.ResponseDigest})
		if e = n.repo.Record(ctx, op, b, receipts, false); e != nil {
			return empty, e
		}
		s, e := n.slack.SendCanary(ctx, slackValue, correlation, phase, n.repo.Digest, check)
		if e != nil {
			return empty, e
		}
		receipts = append(receipts, operations.NotificationReceipt{Route: "slack", Phase: phase, State: "provider-accepted", AcceptedAt: s.AcceptedAt.Format(time.RFC3339Nano), ResponseDigest: s.ResponseDigest})
		if e = n.repo.Record(ctx, op, b, receipts, false); e != nil {
			return empty, e
		}
	}
	_, human, e := n.repo.Current(ctx, op, b)
	if e != nil {
		return empty, e
	}
	refDigest, e := n.repo.ReferenceDigest(ctx, b.RecoveryEpoch)
	if e != nil {
		return empty, e
	}
	record := operations.NotificationReceipts{ReferenceDigest: refDigest, RunID: b.RunID, PlanID: b.PlanID, PlanDigest: b.PlanDigest, StepID: b.StepID, LeaseID: b.LeaseID, PolicyDigest: n.repo.Digest, HumanID: human, RecoveryEpoch: b.RecoveryEpoch, Receipts: receipts}
	digest := operations.NotificationDigest(record)
	n.mu.Lock()
	n.results[digest] = b
	n.mu.Unlock()
	return adapter.Effect{Status: "succeeded", ResultDigest: digest, Changed: true, EffectObserved: true}, nil
}
func (n *notificationReadiness) Verify(ctx context.Context, op adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	n.mu.Lock()
	b, ok := n.results[effect.ResultDigest]
	delete(n.results, effect.ResultDigest)
	n.mu.Unlock()
	if !ok || effect.Status != "succeeded" {
		return adapter.Verification{}, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	if e := n.repo.VerifyExecuting(ctx, op, b, effect.ResultDigest); e != nil {
		return adapter.Verification{}, e
	}
	return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
}

type notificationReadinessGate struct {
	source   *notificationReadiness
	fallback run.GateVerifier
}

func (g notificationReadinessGate) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	if op.AdapterID == operations.ReadinessAdapter || op.OperationType == operations.ReadinessOperation {
		if g.source == nil || !store.IsNotificationReadiness(p) {
			return serviceFailure(generated.ErrorCodeAuthorizationDenied)
		}
		if e := g.source.allowed(ctx); e != nil {
			return e
		}
		_, e := g.source.repo.ActivePlan(ctx, p)
		return e
	}
	return g.fallback.VerifySecretStep(ctx, p, op)
}
func (m *operationsMonitoring) notificationEvaluation(ctx context.Context, scope store.GateAppliedProfile, h store.Health, at time.Time) (generated.GateEvaluation, error) {
	n := m.readiness
	if n == nil || h.Revision.RecoveryEpoch != scope.RecoveryEpoch || n.repo.CheckPolicy(ctx) != nil {
		return generated.GateEvaluation{}, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	if _, e := n.repo.Bindings(ctx, h.Revision.StateRevision, h.Revision.RecoveryEpoch); e != nil {
		return generated.GateEvaluation{}, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	v := gate.NotificationReadinessVerifier{PolicyDigest: n.repo.Digest, Epoch: scope.RecoveryEpoch, Now: at, Receipts: func(ctx context.Context, id string) (operations.NotificationReceipts, error) {
		return n.repo.ForEvidence(ctx, id, scope.RecoveryEpoch)
	}, Bundle: func(ctx context.Context, id string) (generated.GateEvidenceBundle, error) {
		d, e := store.NewGateRepository(m.s).GetGateDraft(ctx, id)
		return d.Bundle, e
	}}
	e, err := gate.EvaluateNotificationReadiness(ctx, store.NewGateRepository(m.s), gate.ResolvedScope{ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, Capabilities: scope.Capabilities, StateRevision: scope.StateRevision, RecoveryEpoch: scope.RecoveryEpoch}, gate.Subject{ID: "scope", Kind: "site", ReleaseBuildID: m.build.ReleaseBuildID, ToolVersion: m.build.ToolVersion}, at, v)
	return e, err
}
func (m *operationsMonitoring) notificationGatePassed(ctx context.Context, scope store.GateAppliedProfile, h store.Health, at time.Time) bool {
	e, err := m.notificationEvaluation(ctx, scope, h, at)
	return err == nil && e.Outcome == "passed"
}

func (o *Operations) NotificationReadiness(ctx context.Context, path string, q generated.NotificationReadinessRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, e
	}
	return c.NotificationReadiness(ctx, p, q)
}
