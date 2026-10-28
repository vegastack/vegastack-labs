package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/githubalerts"
	r2adapter "github.com/vegastack/vegastack-labs/internal/adapters/r2"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/siteheartbeat"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type heartbeatStateFixture struct {
	health      store.Health
	scope       store.GateAppliedProfile
	reference   generated.CredentialReference
	healthReads int
}

func (f *heartbeatStateFixture) Health(context.Context) (store.Health, error) {
	f.healthReads++
	return f.health, nil
}
func (f *heartbeatStateFixture) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return f.scope, nil
}
func (f *heartbeatStateFixture) GetReference(context.Context, string) (generated.CredentialReference, error) {
	return f.reference, nil
}

type heartbeatNativeFixture struct {
	calls   int
	binding credentialref.StepBinding
}

func (r *heartbeatNativeFixture) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	r.calls++
	r.binding = b
	return credentialref.NewValue([]byte(`{"accessKeyId":"fixture-access","secretAccessKey":"fixture-private-value","sessionToken":"fixture-put-only-session"}`))
}

type heartbeatWire func(*http.Request) (*http.Response, error)

func (w heartbeatWire) RoundTrip(r *http.Request) (*http.Response, error) { return w(r) }
func heartbeatControlFixture(t *testing.T) (*siteHeartbeatControl, *heartbeatStateFixture, *heartbeatNativeFixture, *time.Time, *int) {
	t.Helper()
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	activated := now.Add(-time.Minute).Format(time.RFC3339)
	binding := generated.OperationsHeartbeatBinding{Schema: "vegastack-labs.dev/operations-heartbeat-binding", SchemaVersion: "1.0.0", Endpoint: "https://account.r2.cloudflarestorage.com", Bucket: "status-bucket", ObjectKey: "heartbeat.json", SiteDigest: "sha256:" + strings.Repeat("a", 64), TargetID: "status-target", ReferenceID: "heartbeat-ref", MaterialVersion: "v1", PolicyID: "site-policy", PolicyVersion: "1.0.0"}
	f := &heartbeatStateFixture{health: store.Health{Mode: store.DatabaseReady, IntegrityStatus: store.IntegrityVerified, Revision: store.RevisionToken{StateRevision: 7, RecoveryEpoch: 2}}, scope: store.GateAppliedProfile{ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: binding.PolicyID, PolicyVersion: binding.PolicyVersion, StateRevision: 5, RecoveryEpoch: 2, Capabilities: []string{heartbeatCredentialCapability, serverconfig.HeartbeatCapability(binding)}}, reference: generated.CredentialReference{ReferenceID: binding.ReferenceID, ConsumerID: r2adapter.HeartbeatConsumer, PurposeID: heartbeatPurpose, TargetID: binding.TargetID, MaterialVersion: binding.MaterialVersion, ResolverID: "native-systemd", Status: "active", StateRevision: 6, RecoveryEpoch: 2, ActivatedAt: &activated, VerifiedConsumerIDs: []string{r2adapter.HeartbeatConsumer}}}
	r := &heartbeatNativeFixture{}
	registry := adapter.NewRegistry()
	if err := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: r2adapter.HeartbeatConsumer, ProfileID: f.scope.ProfileID, CapabilityID: heartbeatCredentialCapability, Enabled: true}, r); err != nil {
		t.Fatal(err)
	}
	c := &siteHeartbeatControl{binding: binding, authority: f, profiles: f, references: f, registry: registry, clock: func() time.Time { return now }, verifyGate: func(context.Context, store.GateAppliedProfile, store.Health, time.Time) bool { return true }}
	calls := 0
	writer := r2adapter.HeartbeatWriter{Client: r2adapter.S3Client{Endpoint: binding.Endpoint, Bucket: binding.Bucket, Clock: c.clock, Client: &http.Client{Transport: heartbeatWire(func(request *http.Request) (*http.Response, error) {
		calls++
		body, _ := io.ReadAll(request.Body)
		if request.Method != "PUT" || request.URL.Path != "/status-bucket/heartbeat.json" || !strings.Contains(string(body), `"stateRevision":7`) || !strings.Contains(string(body), `"recoveryEpoch":2`) {
			t.Fatal("wrong sanitized write")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}}, ObjectKey: binding.ObjectKey, SiteDigest: binding.SiteDigest, Reference: credentialref.Reference{ID: binding.ReferenceID, Consumer: r2adapter.HeartbeatConsumer}, Resolver: c}
	c.publisher = &siteheartbeat.Publisher{Source: c, Writer: writer, Clock: c.clock}
	return c, f, r, &now, &calls
}
func TestSiteHeartbeatCompositionPublishesFreshExactAuthorizedSnapshot(t *testing.T) {
	c, f, r, now, calls := heartbeatControlFixture(t)
	c.publish(context.Background())
	if *calls != 1 || r.calls != 1 || f.healthReads < 3 || r.binding.TargetID != c.binding.TargetID || r.binding.PurposeID != heartbeatPurpose {
		t.Fatal("missing exact authorized write")
	}
	snapshot, err := c.HeartbeatSnapshot(context.Background())
	if err != nil || !snapshot.ObservedAt.Equal(*now) || snapshot.StateRevision != 7 {
		t.Fatal("source did not use current authority/UTC")
	}
	c.publish(context.Background())
	if *calls != 1 {
		t.Fatal("caller bypassed fixed five-minute cadence")
	}
}
func TestSiteHeartbeatCompositionDeniesBeforeBorrowOrNetwork(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*siteHeartbeatControl, *heartbeatStateFixture)
	}{
		{"no applied exact capability", func(c *siteHeartbeatControl, f *heartbeatStateFixture) {
			f.scope.Capabilities = []string{heartbeatCredentialCapability}
		}},
		{"policy", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { f.scope.PolicyID = "other-policy" }},
		{"bucket changed", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { c.binding.Bucket = "other-bucket" }},
		{"epoch", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { f.scope.RecoveryEpoch++ }},
		{"safe mode", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { f.health.Mode = store.DatabaseSafeMode }},
		{"purpose", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { f.reference.PurposeID = "backup-write" }},
		{"material", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { f.reference.MaterialVersion = "old" }},
		{"target", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { f.reference.TargetID = "backup-target" }},
		{"revoked", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { f.reference.Status = "revoked" }},
		{"missing custody verification", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { f.reference.VerifiedConsumerIDs = nil }},
		{"missing gate evidence", func(c *siteHeartbeatControl, f *heartbeatStateFixture) {
			c.verifyGate = func(context.Context, store.GateAppliedProfile, store.Health, time.Time) bool { return false }
		}},
		{"missing native resolver", func(c *siteHeartbeatControl, f *heartbeatStateFixture) { c.registry = adapter.NewRegistry() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f, r, _, calls := heartbeatControlFixture(t)
			tc.change(c, f)
			c.publish(context.Background())
			if *calls != 0 || r.calls != 0 {
				t.Fatal("denial borrowed or contacted destination")
			}
		})
	}
}
func TestSiteHeartbeatLifecycleIsIndependentOfBusyNotificationDispatch(t *testing.T) {
	c, _, _, now, calls := heartbeatControlFixture(t)
	m := &operationsMonitoring{heartbeat: c, github: &githubalerts.Client{}}
	busy := make(chan struct{}, 1)
	busy <- struct{}{}
	m.lifecycleTick(context.Background(), busy)
	*now = now.Add(5 * time.Minute)
	m.lifecycleTick(context.Background(), busy)
	if *calls != 2 || len(busy) != 1 {
		t.Fatal("notification outage blocked heartbeat")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	*now = now.Add(5 * time.Minute)
	m.lifecycleTick(ctx, busy)
	if *calls != 2 {
		t.Fatal("shutdown launched heartbeat")
	}
}
func TestSiteHeartbeatProductionCompositionIsAbsentOrFailsClosed(t *testing.T) {
	absent, err := composeSiteHeartbeat(context.Background(), serverconfig.Profile{}, nil, adapter.NewRegistry(), "unused", result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"})
	if err != nil || absent != nil {
		t.Fatal("default enabled heartbeat")
	}
	c, _, _, _, _ := heartbeatControlFixture(t)
	configured, err := composeSiteHeartbeat(context.Background(), serverconfig.Profile{OperationsHeartbeat: &c.binding}, nil, adapter.NewRegistry(), "unused", result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := configured.HeartbeatSnapshot(context.Background()); err == nil {
		t.Fatal("missing applied production authority admitted heartbeat")
	}
}
