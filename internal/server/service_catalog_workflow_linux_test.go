//go:build linux

package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// This exercises production composition over real SQLite and synthetic TLS
// providers. SQL seeds are fixtures, not proof of approval or native admission.
type serviceCatalogWorkflow struct {
	t                                       *testing.T
	ctx                                     context.Context
	actor                                   identity.Principal
	db                                      *sql.DB
	source                                  *serviceCatalogComposition
	definition                              generated.ServiceDefinition
	policy                                  servicecatalog.Policy
	resolver                                *serviceCatalogWorkflowResolver
	hostingCalls, artifactCalls             atomic.Int32
	hostingUnavailable, artifactUnavailable bool
	hostingStatus                           string
	onHosting                               func() error
}
type serviceCatalogWorkflowResolver struct {
	values  []*credentialref.Value
	aliases [][]byte
}

func (r *serviceCatalogWorkflowResolver) Resolve(_ context.Context, b credentialref.StepBinding) (*credentialref.Value, error) {
	if !credentialref.ValidBinding(b) || b.TargetID != "service-a" || (b.ConsumerID != "hosting.coolify" && b.ConsumerID != "registry.harbor") {
		return nil, fmt.Errorf("unexpected synthetic credential binding")
	}
	value, err := credentialref.NewValue([]byte("fixture-service-secret"))
	if err == nil {
		r.values = append(r.values, value)
		r.aliases = append(r.aliases, value.Bytes())
	}
	return value, err
}
func (f *serviceCatalogWorkflow) closed() {
	f.t.Helper()
	for i, value := range f.resolver.values {
		if len(value.Bytes()) != 0 {
			f.t.Fatal("borrow remained open")
		}
		for _, b := range f.resolver.aliases[i] {
			if b != 0 {
				f.t.Fatal("borrow alias retained material")
			}
		}
	}
}
func (f *serviceCatalogWorkflow) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.db.Exec(query, args...); err != nil {
		f.t.Fatalf("fixture SQL: %v\n%s", err, query)
	}
}
func (f *serviceCatalogWorkflow) draft() generated.ServiceImportDraftRequest {
	return generated.ServiceImportDraftRequest{Schema: generated.SchemaIDServiceImportDraftRequest, SchemaVersion: "1.0.0", ServiceID: "service-a", BindingID: "binding-a", ExpectedStateRevision: 5, IdempotencyKey: "import-a", ReasonDigest: servicecatalog.Digest("synthetic reason")}
}
func newServiceCatalogWorkflow(t *testing.T) *serviceCatalogWorkflow {
	t.Helper()
	f := &serviceCatalogWorkflow{t: t, hostingStatus: "running:healthy", resolver: &serviceCatalogWorkflowResolver{}}
	f.actor = identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman, DeviceID: "device-a"}
	f.ctx = identity.WithVerifiedPrincipal(context.Background(), f.actor)
	hosting := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hostingCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer fixture-service-secret" {
			t.Error("unexpected hosting method/credential")
			w.WriteHeader(403)
			return
		}
		if f.hostingUnavailable {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"private":"fixture-service-secret"}`))
			return
		}
		switch r.URL.Path {
		case "/api/v1/team":
			_, _ = w.Write([]byte(`{"id":1}`))
		case "/api/v1/projects/project-a":
			_, _ = w.Write([]byte(`{"id":2,"uuid":"project-a"}`))
		case "/api/v1/projects/project-a/production":
			_, _ = w.Write([]byte(`{"id":3,"project_id":2,"name":"production"}`))
		case "/api/v1/applications/app-a":
			if hook := f.onHosting; hook != nil {
				f.onHosting = nil
				if err := hook(); err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"uuid": "app-a", "environment_id": 3, "destination_id": 4, "destination_type": `App\Models\StandaloneDocker`, "docker_registry_image_name": "registry.example/project/app", "docker_registry_image_tag": "v1", "status": f.hostingStatus, "private": "fixture-service-secret"})
		default:
			t.Errorf("unexpected hosting route %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(hosting.Close)
	artifactDigest := servicecatalog.Digest("artifact")
	registryPeer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.artifactCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		user, password, ok := r.BasicAuth()
		if r.Method != "GET" || !ok || user != "robot$service" || password != "fixture-service-secret" {
			t.Error("unexpected registry method/credential")
			w.WriteHeader(403)
			return
		}
		if f.artifactUnavailable {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"private":"fixture-service-secret"}`))
			return
		}
		if r.URL.Path != "/api/v2.0/projects/project/repositories/app/artifacts/"+artifactDigest || r.URL.Query().Get("with_scan_overview") != "true" {
			t.Error("unexpected registry route")
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"digest": artifactDigest, "project_id": 2, "repository_id": 3, "project_name": "project", "repository_name": "project/app", "manifest_media_type": "application/vnd.oci.image.index.v1+json", "scan_overview": map[string]any{"application/vnd.security.vulnerability.report; version=1.1": map[string]any{"scan_status": "Success", "complete_percent": 100, "summary": map[string]any{"total": 0}}}, "private": "fixture-service-secret"})
	}))
	t.Cleanup(registryPeer.Close)
	binding := generated.ServiceProviderBinding{Schema: generated.SchemaIDServiceProviderBinding, SchemaVersion: "1.0.0", BindingID: "binding-a", ServiceID: "service-a", EnvironmentID: "environment-a", OwnerID: "operator-a", HostID: "synthetic-service-host", HostIdentityDigest: servicecatalog.Digest("synthetic-host-identity"), Coolify: &generated.CoolifyServiceBinding{Schema: generated.SchemaIDCoolifyServiceBinding, SchemaVersion: "1.0.0", Origin: hosting.URL + "/api/v1", TeamID: 1, ProjectID: 2, EnvironmentID: 3, DestinationID: 4, ProjectUUID: "project-a", Environment: "production", ApplicationUUID: "app-a", DestinationType: `App\Models\StandaloneDocker`, ObservationReferenceID: "hosting-ref"}, Harbor: &generated.HarborServiceBinding{Schema: generated.SchemaIDHarborServiceBinding, SchemaVersion: "1.0.0", Origin: registryPeer.URL, Project: "project", Repository: "app", ArtifactDigest: artifactDigest, RobotUsername: "robot$service", ObservationReferenceID: "registry-ref"}}
	policies, err := servicePolicies([]generated.ServiceProviderBinding{binding})
	if err != nil {
		t.Fatal(err)
	}
	f.policy = policies[0]
	f.definition = policies[0].Definition
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	authority, err := store.Open(f.ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", ServiceImportPolicies: policies})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if authority != nil {
			_ = authority.Close()
		}
	})
	f.db, err = sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	f.db.SetMaxOpenConns(1)
	f.exec(`PRAGMA foreign_keys=ON`)
	t.Cleanup(func() { _ = f.db.Close() })
	hash := servicecatalog.Digest("fixture")
	f.exec(`UPDATE system_meta SET state_revision=5 WHERE id=1`)
	f.exec(`INSERT INTO effective_authorization_principals VALUES('operator-a','human','active',1,'now','now')`)
	f.exec(`INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`)
	f.exec(`INSERT INTO operator_devices VALUES('device-a','operator-a','approved',1,'now','now')`)
	f.exec(`INSERT INTO effective_authorization_grants VALUES('service-author','operator-a','maintainer','author','service.import.prepare','service','service-a',NULL,1,'active','now','now'),('service-read','operator-a','reader','read','service.read','service','service-a',NULL,1,'active','now','now')`)
	f.exec(`INSERT INTO declaration_revisions VALUES('fixture-declaration',1,'host.discovery-target',1,0,?,?,'draft',?,'now','operator-a','session-a')`, hash, hash, []byte(`{}`))
	f.exec(`INSERT INTO immutable_plans VALUES('fixture-plan',?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, hash, hash, hash, hash, []byte(`{}`), "synthetic fixture", hash)
	f.exec(`INSERT INTO acknowledgement_requests VALUES('fixture-ack','fixture-plan',?,?,?,'operator-a','fixture-authority',?,1,0,'later','approved',?,?,'now','now','now')`, hash, hash, hash, hash, []byte(`{}`), []byte(`{}`))
	f.exec(`INSERT INTO plan_runs VALUES('fixture-run','fixture-plan',?,'decision',NULL,'1.0.0','central','executor',?,'succeeded',0,'not-requested','verified',?,0,1,0,?,?,?,'now','now')`, hash, hash, hash, hash, hash, []byte(`{}`))
	f.exec(`INSERT INTO host_discovery_drafts VALUES('fixture-target','candidate-a',1,0,'activate',?,?,'operator-a',1,0)`, hash, []byte(`{}`))
	f.exec(`INSERT INTO host_discovery_targets VALUES('candidate-a',1,'fixture-target','active','fixture-plan',0)`)
	f.exec(`INSERT INTO host_discovery_attempts VALUES('fixture-observation','operator-a',?,?,'candidate-a',1,?,1,1,0,'later',?)`, hash, hash, hash, []byte(`{}`))
	f.exec(`INSERT INTO host_observations VALUES('fixture-observation','candidate-a',1,?,?,1,0)`, []byte(`{}`), hash)
	f.exec(`INSERT INTO host_adoption_drafts VALUES('fixture-adoption',?,?,'operator-a',1,0)`, hash, []byte(`{}`))
	f.exec(`INSERT INTO managed_hosts VALUES('synthetic-service-host','candidate-a',?,'product-serial','physical','fixture-observation','synthetic-profile','fixture-adoption','fixture-plan','operator-a','fixture-ack',1,0)`, binding.HostIdentityDigest)
	f.exec(`INSERT INTO gate_applied_profiles VALUES('service-profile','synthetic-profile','1.0.0','fixture-policy','1.0.0',?,1,0,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, []byte(`["credential.hosting.read","credential.registry.read"]`), hash)
	f.credentialVersion("hosting-ref", "hosting.coolify", "hosting-observe", "one", "active", 1)
	f.credentialVersion("registry-ref", "registry.harbor", "registry-observe", "one", "active", 1)
	// Fixture SQL bypasses the store's writer cache. Reopen the real store so
	// its health revision matches the seeded database before composition.
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	authority, err = store.Open(f.ctx, store.Config{DatabasePath: path, Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", ServiceImportPolicies: policies})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if authority != nil {
			_ = authority.Close()
		}
	})
	adapters := adapter.NewRegistry()
	for _, entry := range []struct{ consumer, capability string }{{"hosting.coolify", "credential.hosting.read"}, {"registry.harbor", "credential.registry.read"}} {
		if err := adapters.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-service", ConsumerID: entry.consumer, ProfileID: "synthetic-profile", CapabilityID: entry.capability, Enabled: true}, f.resolver); err != nil {
			t.Fatal(err)
		}
	}
	source, err := newServiceCatalogComposition(f.ctx, serverconfig.Profile{SocketOwnerUID: uint32(os.Geteuid()), ServiceBindings: []generated.ServiceProviderBinding{binding}}, authority, adapters, path)
	if err != nil {
		t.Fatal(err)
	}
	source.coolifyTransport = hosting.Client().Transport
	source.harborTransport = registryPeer.Client().Transport
	f.source = source
	var violation string
	rows, err := f.db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("fixture foreign key violation", violation)
	}
	return f
}
func (f *serviceCatalogWorkflow) credentialVersion(reference, consumer, purpose, material, status string, revision int64) {
	f.t.Helper()
	activated := time.Now().UTC().Format(time.RFC3339)
	f.exec(`INSERT INTO credential_reference_versions VALUES(?,?,?,?,?,'fixture-service',?,?,?, ?,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, fmt.Sprintf("%s-%s-%s", reference, material, status), reference, consumer, purpose, "service-a", material, servicecatalog.Digest(material), status, revision, activated, []byte(fmt.Sprintf("[%q]", consumer)), servicecatalog.Digest("fixture"))
}
func (f *serviceCatalogWorkflow) register() {
	f.t.Helper()
	record := generated.ServiceRecord{Schema: generated.SchemaIDServiceRecord, SchemaVersion: "1.0.0", Definition: f.definition, Revision: 1, RegistrationStatus: "registered", HostAdmission: "not-verified", RegisteredAt: time.Now().UTC().Format(time.RFC3339), StateRevision: 5}
	raw, err := json.Marshal(record)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO service_catalog VALUES(?,?,?,?,?,'fixture-plan','fixture-run')`, record.Definition.ServiceID, f.policy.ResourceKeyDigest, raw, servicecatalog.Digest(record), servicecatalog.Digest("synthetic import"))
}
func TestServiceCatalogCompositionPrepareVerifyAndCredentialClosure(t *testing.T) {
	f := newServiceCatalogWorkflow(t)
	imported, err := f.source.Prepare(f.ctx, f.draft())
	if err != nil {
		t.Fatal(err)
	}
	if imported.ObservationDigest == "" || f.hostingCalls.Load() != 4 || f.artifactCalls.Load() != 1 {
		t.Fatal("exact providers not observed", err)
	}
	if err := f.source.VerifyImport(context.Background(), imported, f.actor); err != nil {
		t.Fatal(err)
	}
	f.closed()
	raw, _ := json.Marshal(imported)
	for _, private := range []string{"fixture-service-secret", "hosting-ref", "registry-ref", "https://"} {
		if strings.Contains(string(raw), private) {
			t.Fatal("private source leaked to import")
		}
	}
	var count int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM service_catalog`).Scan(&count); err != nil || count != 0 {
		t.Fatal("preparation registered service", count, err)
	}
	f.hostingStatus = "stopped"
	if err := f.source.VerifyImport(context.Background(), imported, f.actor); err == nil {
		t.Fatal("provider drift did not stale import")
	}
	f.closed()
}
func TestServiceCatalogCompositionDeniesBeforeProviderIO(t *testing.T) {
	for _, mode := range []string{"grant", "device", "owner", "target"} {
		t.Run(mode, func(t *testing.T) {
			f := newServiceCatalogWorkflow(t)
			draft := f.draft()
			switch mode {
			case "grant":
				f.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='service-author'`)
			case "device":
				f.exec(`UPDATE operator_devices SET status='revoked' WHERE device_id='device-a'`)
			case "owner":
				f.exec(`UPDATE effective_authorization_principals SET status='revoked' WHERE principal_id='operator-a'`)
			case "target":
				draft.ServiceID = "private-service"
			}
			if _, err := f.source.Prepare(f.ctx, draft); err == nil {
				t.Fatal("denied preparation accepted")
			}
			if f.hostingCalls.Load() != 0 || f.artifactCalls.Load() != 0 || len(f.resolver.values) != 0 {
				t.Fatal("denied target borrowed/contacted provider")
			}
		})
	}
}
func TestServiceCatalogCompositionRejectsChangedAuthorityDuringRead(t *testing.T) {
	for _, mode := range []string{"device", "grant", "epoch", "credential"} {
		t.Run(mode, func(t *testing.T) {
			f := newServiceCatalogWorkflow(t)
			f.onHosting = func() error {
				switch mode {
				case "device":
					_, err := f.db.Exec(`UPDATE operator_devices SET status='revoked' WHERE device_id='device-a'`)
					return err
				case "grant":
					_, err := f.db.Exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='service-author'`)
					return err
				case "epoch":
					_, err := f.db.Exec(`UPDATE system_meta SET recovery_epoch=1 WHERE id=1`)
					return err
				case "credential":
					_, err := f.db.Exec(`INSERT INTO credential_reference_versions SELECT 'hosting-ref-revoked',reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,'revoked',5,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at FROM credential_reference_versions WHERE reference_id='hosting-ref'`)
					return err
				}
				return nil
			}
			if _, err := f.source.Prepare(f.ctx, f.draft()); err == nil || serviceDisplayable(err) {
				t.Fatalf("changed authority became status: %v", err)
			}
			if f.artifactCalls.Load() != 0 {
				t.Fatal("continued provider reads after authority change")
			}
			f.closed()
		})
	}
}
func TestServiceCatalogCompositionObservationScopeAndIndependentOutages(t *testing.T) {
	f := newServiceCatalogWorkflow(t)
	f.register()
	for _, mode := range []string{"current", "hosting-outage", "registry-outage"} {
		t.Run(mode, func(t *testing.T) {
			f.hostingUnavailable = mode == "hosting-outage"
			f.artifactUnavailable = mode == "registry-outage"
			observed, err := f.source.Observe(f.ctx, "service-a")
			if err != nil {
				t.Fatal(err)
			}
			hosting, artifact := "observed", "observed"
			if f.hostingUnavailable {
				hosting = "unavailable"
			}
			if f.artifactUnavailable {
				artifact = "unavailable"
			}
			if observed.HostingState != hosting || observed.ArtifactState != artifact || observed.SignatureState != "unverified" || observed.ProvenanceState != "unverified" || observed.RunningDigestState != "unknown" || observed.HealthState != "unknown" || observed.HostAdmission != "not-verified" {
				t.Fatalf("unexpected observation %+v", observed)
			}
			if mode == "current" && (observed.ArtifactKind != "index" || observed.ScanState != "passed") {
				t.Fatal(observed)
			}
			raw, _ := json.Marshal(observed)
			for _, private := range []string{"fixture-service-secret", "hosting-ref", "registry-ref", "https://", "robot$"} {
				if strings.Contains(string(raw), private) {
					t.Fatal("private provider state leaked")
				}
			}
			f.closed()
		})
	}
	f.exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE grant_id='service-read'`)
	beforeHosting, beforeArtifact := f.hostingCalls.Load(), f.artifactCalls.Load()
	if _, err := f.source.Observe(f.ctx, "service-a"); err == nil {
		t.Fatal("revoked read accepted")
	} else if store.Code(err) != generated.ErrorCodeAuthorizationDenied {
		stable, ok := failure.As(err)
		if !ok || stable.Code != generated.ErrorCodeAuthorizationDenied {
			t.Fatal(err)
		}
	}
	if f.hostingCalls.Load() != beforeHosting || f.artifactCalls.Load() != beforeArtifact {
		t.Fatal("revoked read contacted provider")
	}
}

func TestServiceCatalogCompositionCredentialRotationStalesImport(t *testing.T) {
	f := newServiceCatalogWorkflow(t)
	imported, err := f.source.Prepare(f.ctx, f.draft())
	if err != nil {
		t.Fatal(err)
	}
	// Append synthetic metadata to represent an authorized rotation's end state.
	// This fixture does not claim to exercise the credential rotation workflow.
	f.credentialVersion("hosting-ref", "hosting.coolify", "hosting-observe", "one", "revoked", 5)
	f.credentialVersion("hosting-ref", "hosting.coolify", "hosting-observe", "two", "active", 5)
	err = f.source.VerifyImport(context.Background(), imported, f.actor)
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodePlanStale {
		t.Fatalf("rotation did not stale plan: %v", err)
	}
	f.closed()
}
func TestServiceCatalogCompositionConfiguredProviderOutageBlocksImport(t *testing.T) {
	for _, provider := range []string{"hosting", "registry"} {
		t.Run(provider, func(t *testing.T) {
			f := newServiceCatalogWorkflow(t)
			f.hostingUnavailable = provider == "hosting"
			f.artifactUnavailable = provider == "registry"
			if _, err := f.source.Prepare(f.ctx, f.draft()); err == nil {
				t.Fatal("configured provider outage allowed import")
			}
			var records int
			if err := f.db.QueryRow(`SELECT COUNT(*) FROM service_catalog`).Scan(&records); err != nil || records != 0 {
				t.Fatal("outage registered service", records, err)
			}
			f.closed()
		})
	}
}
