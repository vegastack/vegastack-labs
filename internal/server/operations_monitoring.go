package server

import (
	"context"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/beszel"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubalerts"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	monitor "github.com/vegastack/vegastack-labs/internal/operations"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"sync"
	"time"
)

const operationsDestination audit.DestinationID = "operations-github-alerts"

type operationsMonitoring struct {
	s         *store.Store
	p         serverconfig.Profile
	registry  *adapter.Registry
	build     result.BuildInfo
	clock     func() time.Time
	github    *githubalerts.Client
	beszel    map[string]*beszel.Client
	heartbeat *siteHeartbeatControl
	mu        sync.Mutex
}

func (m *operationsMonitoring) borrow(ctx context.Context, consumer, purpose, target, reference, material, capability string) (*credentialref.Value, error) {
	fail := func() (*credentialref.Value, error) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "operations-credential", false)
	}
	scope, e := store.NewGateRepository(m.s).GetAppliedProfileScope(ctx)
	if e != nil || !slices.Contains(scope.Capabilities, capability) {
		return fail()
	}
	r, e := store.NewCredentialRepository(m.s).GetReference(ctx, reference)
	if e != nil || r.Status != "active" || r.ConsumerID != consumer || r.PurposeID != purpose || r.TargetID != target || r.MaterialVersion != material || r.RecoveryEpoch != scope.RecoveryEpoch || r.ActivatedAt == nil || !slices.Contains(r.VerifiedConsumerIDs, consumer) {
		return fail()
	}
	h, e := m.s.Health(ctx)
	if e != nil || h.Revision.RecoveryEpoch != r.RecoveryEpoch {
		return fail()
	}
	resolver, e := m.registry.ResolveCredentialResolver("native-systemd", consumer, scope.ProfileID)
	if e != nil {
		return fail()
	}
	return resolver.Resolve(ctx, credentialref.StepBinding{OperationID: "operations-observation", AdapterID: consumer, TargetID: target, ReferenceID: reference, ConsumerID: consumer, PurposeID: purpose, MaterialVersion: material, ResolverID: "native-systemd", StateRevision: h.Revision.StateRevision, RecoveryEpoch: r.RecoveryEpoch})
}
func (m *operationsMonitoring) deliveryAllowed(ctx context.Context) bool {
	if m.github == nil {
		return false
	}
	scope, e := store.NewGateRepository(m.s).GetAppliedProfileScope(ctx)
	if e != nil || !slices.Contains(scope.Capabilities, "operations.notifications") {
		return false
	}
	h, e := m.s.Health(ctx)
	if e != nil || h.Revision.RecoveryEpoch != scope.RecoveryEpoch {
		return false
	}
	v, e := gate.Evaluate(ctx, store.NewGateRepository(m.s), gate.ResolvedScope{ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, Capabilities: scope.Capabilities, StateRevision: scope.StateRevision, RecoveryEpoch: scope.RecoveryEpoch}, gate.Subject{ID: "scope", Kind: "site", ReleaseBuildID: m.build.ReleaseBuildID, ToolVersion: m.build.ToolVersion, StateRevision: h.Revision.StateRevision}, "G-011", m.clock().UTC(), gate.NewProofRegistry())
	return e == nil && v.Outcome == "passed"
}
func (m *operationsMonitoring) status(ctx context.Context) (generated.OperationsStatusData, error) {
	h, e := m.s.Health(ctx)
	if e != nil {
		return generated.OperationsStatusData{}, e
	}
	alerts, e := m.s.OperationsAlerts(ctx, h.Revision)
	if e != nil {
		return generated.OperationsStatusData{}, e
	}
	d := generated.OperationsStatusData{Schema: generated.SchemaIDOperationsStatusData, SchemaVersion: "1.0.0", StateRevision: h.Revision.StateRevision, RecoveryEpoch: h.Revision.RecoveryEpoch, Notifications: "disabled", Alerts: []generated.OperationsAlert{}, Deliveries: []generated.OutboxRecordData{}}
	if m.github != nil {
		d.Notifications = "configured"
	}
	for _, a := range alerts {
		v := generated.OperationsAlert{Schema: generated.SchemaIDOperationsAlert, SchemaVersion: "1.0.0", Key: a.Key, TargetDigest: a.TargetDigest, Class: a.Class, Severity: a.Severity, ObservationState: string(a.State), Status: a.Status, ObservedAt: a.ObservedAt.Format(time.RFC3339Nano), Occurrences: a.Occurrences, Generation: a.Generation}
		for _, f := range []struct {
			p *time.Time
			s *string
		}{{a.FirstFailure, &v.FirstFailure}, {a.LastFailure, &v.LastFailure}, {a.LastGood, &v.LastGood}} {
			if f.p != nil {
				*f.s = f.p.Format(time.RFC3339Nano)
			}
		}
		d.Alerts = append(d.Alerts, v)
	}
	records, e := m.s.OperationsOutbox(ctx, h.Revision)
	if e != nil {
		return generated.OperationsStatusData{}, e
	}
	for _, r := range records {
		v := generated.OutboxRecordData{OutboxID: int64(r.OutboxID), EventID: int64(r.EventID), DestinationID: string(r.Destination), PayloadSchema: r.PayloadSchema, PayloadVersion: r.PayloadVersion, PayloadSHA256: string(r.PayloadSHA256), DedupeSHA256: string(r.DedupeSHA256), Status: string(r.Status), AttemptCount: int64(r.AttemptCount), MaxAttempts: int64(r.MaxAttempts), CreatedAt: r.CreatedAt.Format(time.RFC3339Nano), UpdatedAt: r.UpdatedAt.Format(time.RFC3339Nano)}
		if r.NextAttemptAt != nil {
			s := r.NextAttemptAt.Format(time.RFC3339Nano)
			v.NextAttemptAt = &s
		}
		if r.DeliveredAt != nil {
			s := r.DeliveredAt.Format(time.RFC3339Nano)
			v.DeliveredAt = &s
		}
		if r.LastErrorCode != nil {
			s := string(*r.LastErrorCode)
			v.LastErrorCode = &s
		}
		d.Deliveries = append(d.Deliveries, v)
	}
	return d, nil
}
func (m *operationsMonitoring) observe(ctx context.Context) (generated.OperationsStatusData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return generated.OperationsStatusData{}, failure.New(generated.ErrorCodeAuthenticationRequired, "operations", false)
	}
	auth := store.NewReadAuthorizer(m.s)
	scope, e := auth.AuthorizeRead(ctx, p, authorization.ReadTarget{Capability: "platform.source.read", ResourceKind: "platform-source"})
	if e != nil {
		return generated.OperationsStatusData{}, e
	}
	// Check every configured external target before borrowing or contacting it.
	for _, b := range m.p.OperationsBeszel {
		if _, e = auth.AuthorizeRead(ctx, p, authorization.ReadTarget{Capability: "operations.target.read", ResourceKind: "operations-target", ResourceID: b.TargetID}); e != nil {
			return generated.OperationsStatusData{}, e
		}
	}
	h, e := m.s.Health(ctx)
	if e != nil {
		return generated.OperationsStatusData{}, e
	}
	now := m.clock().UTC()
	page, e := store.NewSourceRepository(m.s).ListSources(ctx, scope, readmodel.SourceListQuery{Limit: 200, Sort: "id-asc", EvaluationAt: now}, h.Revision)
	if e != nil || page.HasMore {
		return generated.OperationsStatusData{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "operations-sources", false)
	}
	actor, e := audit.NewAttribution(p, nil, nil)
	if e != nil {
		return generated.OperationsStatusData{}, e
	}
	if identity.EffectivePrincipalKind(p) == identity.PrincipalAgent {
		actor.Agent = &audit.AgentMetadata{Name: p.ID, SessionID: "operations-observe"}
	}
	destination := audit.DestinationID("")
	if m.github != nil {
		destination = operationsDestination
	}
	record := func(o monitor.Observation) error {
		_, err := m.s.RecordOperationsObservation(ctx, h.Revision, o, actor, destination)
		return err
	}
	for _, source := range page.Items {
		o := monitor.Observation{TargetDigest: monitor.Digest("source:" + string(source.ID)), Class: "source-health", Severity: "critical", State: source.State, ObservedAt: now, Verified: source.State == readmodel.SourceHealthy && source.CollectedAt != nil && !source.CollectedAt.After(now)}
		if source.CollectedAt != nil {
			o.SampleAt = *source.CollectedAt
		}
		if e = record(o); e != nil {
			return generated.OperationsStatusData{}, e
		}
	}
	for _, binding := range m.p.OperationsBeszel {
		o, err := m.beszel[binding.TargetID].Observe(ctx, binding.RecordID, monitor.Digest(binding.TargetID), now, time.Duration(binding.StaleAfterSeconds)*time.Second)
		if err != nil {
			o = monitor.Observation{TargetDigest: monitor.Digest(binding.TargetID), Class: "source-health", Severity: "critical", State: readmodel.SourceUnknown, ObservedAt: now}
		}
		if e = record(o); e != nil {
			return generated.OperationsStatusData{}, e
		}
	}
	return m.status(ctx)
}

// dispatch is an in-process consumer of the existing outbox. Its exact fixed
// notification capability is enabled only by applied configuration and G-011;
// API reads never invoke it. It cannot alter source health or perform repairs.
func (m *operationsMonitoring) dispatch(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.deliveryAllowed(ctx) {
		return
	}
	h, e := m.s.Health(ctx)
	if e != nil {
		return
	}
	now := m.clock().UTC()
	due, e := m.s.DueOperationsDeliveries(ctx, operationsDestination, h.Revision.RecoveryEpoch, now)
	if e != nil {
		return
	}
	for _, d := range due {
		if !m.deliveryAllowed(ctx) {
			return
		}
		if e = m.s.PrepareOperationsDelivery(ctx, d, now); e != nil {
			return
		}
		err := m.github.Deliver(ctx, d.Event)
		attempt := audit.OutboxAttempt{OutboxID: d.Record.OutboxID, ExpectedAttempt: d.Record.AttemptCount, AttemptedAt: m.clock().UTC(), Delivered: err == nil}
		if err != nil {
			attempt.Retryable = true
			attempt.ErrorCode = audit.DestinationUnavailable
		}
		if _, e = m.s.RecordOutboxAttempt(ctx, attempt); e != nil {
			return
		}
	}
}
func registerOperationsMonitoring(ctx context.Context, app *api.Application, s *store.Store, registry *adapter.Registry, p serverconfig.Profile, build result.BuildInfo, databasePath string) error {
	m := &operationsMonitoring{s: s, p: p, registry: registry, build: build, clock: time.Now, beszel: map[string]*beszel.Client{}}
	if e := composeOperationsNative(ctx, p, databasePath, s, registry); e != nil {
		return e
	}
	for _, entry := range p.OperationsBeszel {
		b := entry
		c, e := beszel.New(b.Endpoint, nil, func(ctx context.Context, purpose, target string) (*credentialref.Value, error) {
			if purpose != "operations.beszel.read" || target != monitor.Digest(b.TargetID) {
				return nil, fmt.Errorf("operations scope denied")
			}
			return m.borrow(ctx, "operations.beszel", purpose, b.TargetID, b.ReferenceID, b.MaterialVersion, "credential.operations.read")
		})
		if e != nil {
			return e
		}
		m.beszel[b.TargetID] = c
	}
	if p.OperationsGithub != nil {
		g := *p.OperationsGithub
		c, e := githubalerts.New(g.Endpoint, g.Repository, g.RepositoryID, nil, func(ctx context.Context, purpose, target string) (*credentialref.Value, error) {
			if purpose != "operations.github-issues.write" || target != monitor.Digest(g.Repository) || !m.deliveryAllowed(ctx) {
				return nil, fmt.Errorf("operations scope denied")
			}
			return m.borrow(ctx, "operations.github-alerts", purpose, g.TargetID, g.ReferenceID, g.MaterialVersion, "credential.operations.notify")
		})
		if e != nil {
			return e
		}
		m.github = c
	}
	heartbeat, heartbeatErr := composeSiteHeartbeat(ctx, p, s, registry, databasePath, build)
	if heartbeatErr != nil {
		return heartbeatErr
	}
	m.heartbeat = heartbeat
	if e := api.RegisterOperationsMonitoring(app, api.OperationsMonitoring{Status: m.status, Observe: m.observe}); e != nil {
		return e
	}
	if m.github != nil || m.heartbeat != nil {
		go func() {
			notificationBusy := make(chan struct{}, 1)
			timer := time.NewTicker(30 * time.Second)
			defer timer.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					m.lifecycleTick(ctx, notificationBusy)
				}
			}
		}()
	}
	return nil
}
func (o *Operations) OperationsStatus(ctx context.Context, path string, observe bool) (localapi.TypedResponse[generated.OperationsStatusData], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.OperationsStatusData]{}, e
	}
	return c.OperationsStatus(ctx, p, observe)
}

// One existing ticker drives both fixed notification consumers. Only one
// notification dispatch may be in flight; its outages cannot hold up heartbeat.
func (m *operationsMonitoring) lifecycleTick(ctx context.Context, notificationBusy chan struct{}) {
	if ctx.Err() != nil {
		return
	}
	if m.heartbeat != nil {
		m.heartbeat.publish(ctx)
	}
	if m.github == nil {
		return
	}
	select {
	case notificationBusy <- struct{}{}:
		go func() { defer func() { <-notificationBusy }(); m.dispatch(ctx) }()
	default:
	}
}
