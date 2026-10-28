package server

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	r2adapter "github.com/vegastack/vegastack-labs/internal/adapters/r2"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/siteheartbeat"
	"github.com/vegastack/vegastack-labs/internal/store"
)

const heartbeatCredentialCapability = "credential.operations.heartbeat"
const heartbeatPurpose = "operations.heartbeat.write"

type heartbeatAuthority interface {
	Health(context.Context) (store.Health, error)
}
type heartbeatProfileSource interface {
	GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error)
}
type heartbeatReferenceSource interface {
	GetReference(context.Context, string) (generated.CredentialReference, error)
}
type siteHeartbeatControl struct {
	binding     generated.OperationsHeartbeatBinding
	authority   heartbeatAuthority
	profiles    heartbeatProfileSource
	references  heartbeatReferenceSource
	registry    *adapter.Registry
	build       result.BuildInfo
	clock       func() time.Time
	verifyGate  func(context.Context, store.GateAppliedProfile, store.Health, time.Time) bool
	publisher   *siteheartbeat.Publisher
	mu          sync.Mutex
	lastAttempt time.Time
}

func heartbeatUnavailable() error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, "site-heartbeat", false)
}
func (c *siteHeartbeatControl) bindings(ctx context.Context) (store.GateAppliedProfile, store.Health, generated.CredentialReference, error) {
	var emptyScope store.GateAppliedProfile
	var emptyHealth store.Health
	var emptyRef generated.CredentialReference
	fail := func() (store.GateAppliedProfile, store.Health, generated.CredentialReference, error) {
		return emptyScope, emptyHealth, emptyRef, heartbeatUnavailable()
	}
	if c == nil || c.authority == nil || c.profiles == nil || c.references == nil || c.registry == nil || c.clock == nil || c.verifyGate == nil {
		return fail()
	}
	scope, err := c.profiles.GetAppliedProfileScope(ctx)
	if err != nil || scope.PolicyID != c.binding.PolicyID || scope.PolicyVersion != c.binding.PolicyVersion || !slices.Contains(scope.Capabilities, heartbeatCredentialCapability) || !slices.Contains(scope.Capabilities, serverconfig.HeartbeatCapability(c.binding)) {
		return fail()
	}
	health, err := c.authority.Health(ctx)
	if err != nil || health.Mode != store.DatabaseReady || health.IntegrityStatus != store.IntegrityVerified || health.RecoveryPending || health.Revision.StateRevision <= 0 || scope.StateRevision > health.Revision.StateRevision || scope.RecoveryEpoch != health.Revision.RecoveryEpoch {
		return fail()
	}
	reference, err := c.references.GetReference(ctx, c.binding.ReferenceID)
	if err != nil || reference.ReferenceID != c.binding.ReferenceID || reference.Status != "active" || reference.ConsumerID != r2adapter.HeartbeatConsumer || reference.PurposeID != heartbeatPurpose || reference.TargetID != c.binding.TargetID || reference.MaterialVersion != c.binding.MaterialVersion || reference.ResolverID != "native-systemd" || reference.RecoveryEpoch != health.Revision.RecoveryEpoch || reference.StateRevision > health.Revision.StateRevision || reference.ActivatedAt == nil || !slices.Contains(reference.VerifiedConsumerIDs, r2adapter.HeartbeatConsumer) {
		return fail()
	}
	activated, err := time.Parse(time.RFC3339, *reference.ActivatedAt)
	if err != nil || activated.After(c.clock().UTC()) {
		return fail()
	}
	if !c.verifyGate(ctx, scope, health, c.clock().UTC()) {
		return fail()
	}
	return scope, health, reference, nil
}
func (c *siteHeartbeatControl) HeartbeatSnapshot(ctx context.Context) (siteheartbeat.Snapshot, error) {
	_, health, _, err := c.bindings(ctx)
	if err != nil {
		return siteheartbeat.Snapshot{}, err
	}
	return siteheartbeat.Snapshot{SiteDigest: c.binding.SiteDigest, ObservedAt: c.clock().UTC(), StateRevision: health.Revision.StateRevision, RecoveryEpoch: health.Revision.RecoveryEpoch}, nil
}
func (c *siteHeartbeatControl) Inspect(ctx context.Context, requested credentialref.Reference) (credentialref.Metadata, error) {
	_, _, reference, err := c.bindings(ctx)
	if err != nil || requested.ID != c.binding.ReferenceID || requested.Consumer != r2adapter.HeartbeatConsumer {
		return credentialref.Metadata{}, heartbeatUnavailable()
	}
	return credentialref.Metadata{Reference: requested, MaterialVersion: reference.MaterialVersion, State: credentialref.Current}, nil
}
func (c *siteHeartbeatControl) Resolve(ctx context.Context, requested credentialref.Reference) (*credentialref.Value, error) {
	scope, health, reference, err := c.bindings(ctx)
	if err != nil || requested.ID != c.binding.ReferenceID || requested.Consumer != r2adapter.HeartbeatConsumer {
		return nil, heartbeatUnavailable()
	}
	capability, err := c.registry.ResolveCredentialCapability("native-systemd", r2adapter.HeartbeatConsumer, scope.ProfileID)
	if err != nil || capability != heartbeatCredentialCapability {
		return nil, heartbeatUnavailable()
	}
	resolver, err := c.registry.ResolveCredentialResolver("native-systemd", r2adapter.HeartbeatConsumer, scope.ProfileID)
	if err != nil {
		return nil, heartbeatUnavailable()
	}
	value, err := resolver.Resolve(ctx, credentialref.StepBinding{OperationID: "site-heartbeat", AdapterID: r2adapter.HeartbeatConsumer, TargetID: c.binding.TargetID, ReferenceID: reference.ReferenceID, ConsumerID: r2adapter.HeartbeatConsumer, PurposeID: heartbeatPurpose, MaterialVersion: reference.MaterialVersion, ResolverID: "native-systemd", StateRevision: health.Revision.StateRevision, RecoveryEpoch: health.Revision.RecoveryEpoch})
	if err != nil {
		if value != nil {
			value.Close()
		}
		return nil, heartbeatUnavailable()
	}
	return value, nil
}

// publish is called only by the existing in-process lifecycle. It is not an
// API operation. Five-minute attempts cannot be driven by browser refreshes.
func (c *siteHeartbeatControl) publish(ctx context.Context) {
	if c == nil || c.publisher == nil || c.clock == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock().UTC()
	if !c.lastAttempt.IsZero() && now.Before(c.lastAttempt.Add(5*time.Minute)) {
		return
	}
	c.lastAttempt = now
	_ = c.publisher.Publish(ctx)
}
func composeSiteHeartbeat(ctx context.Context, p serverconfig.Profile, s *store.Store, registry *adapter.Registry, path string, build result.BuildInfo) (*siteHeartbeatControl, error) {
	if p.OperationsHeartbeat == nil {
		return nil, nil
	}
	frozen, err := serverconfig.FreezeSiteHeartbeat(p.OperationsHeartbeat, p.OffsiteBackup)
	if err != nil {
		return nil, err
	}
	c := &siteHeartbeatControl{binding: *frozen, authority: s, profiles: store.NewGateRepository(s), references: store.NewCredentialRepository(s), registry: registry, build: build, clock: time.Now}
	c.verifyGate = func(ctx context.Context, scope store.GateAppliedProfile, health store.Health, now time.Time) bool {
		evaluated, err := gate.Evaluate(ctx, store.NewGateRepository(s), gate.ResolvedScope{ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, Capabilities: scope.Capabilities, StateRevision: scope.StateRevision, RecoveryEpoch: scope.RecoveryEpoch}, gate.Subject{ID: "scope", Kind: "site", ReleaseBuildID: build.ReleaseBuildID, ToolVersion: build.ToolVersion, StateRevision: health.Revision.StateRevision}, "G-011", now, gate.NewProofRegistry())
		return err == nil && evaluated.Outcome == "passed"
	}
	if err = composeSiteHeartbeatNative(ctx, p, path, s, registry); err != nil {
		return nil, err
	}
	backupBucket := ""
	if p.OffsiteBackup != nil {
		backupBucket = p.OffsiteBackup.Bucket
	}
	writer := r2adapter.HeartbeatWriter{Client: r2adapter.S3Client{Endpoint: frozen.Endpoint, Bucket: frozen.Bucket, Clock: c.clock}, ObjectKey: frozen.ObjectKey, BackupBucket: backupBucket, SiteDigest: frozen.SiteDigest, Reference: credentialref.Reference{ID: frozen.ReferenceID, Consumer: r2adapter.HeartbeatConsumer}, Resolver: c}
	c.publisher = &siteheartbeat.Publisher{Source: c, Writer: writer, Clock: c.clock}
	return c, nil
}
