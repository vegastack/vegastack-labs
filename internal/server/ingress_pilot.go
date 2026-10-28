package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/gate"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ingressPilotComposition struct {
	profile        serverconfig.Profile
	store          *store.Store
	source         *ingressAuthority
	identityClient *http.Client
	probe          func(context.Context, serverconfig.Profile) (string, error)
	machine        func() (string, error)
}

func digestBytes(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func pilotMachineDigest() (string, error) {
	b, e := os.ReadFile("/etc/machine-id")
	if e != nil {
		return "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) != 32 {
		return "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	return digestBytes(b), nil
}

// The probe uses only the exact local listener/private endpoint from the
// protected profile. It validates its configured certificate and performs a
// real signed-out API denial; no caller supplies a URL or redirect target.
func probePilotOrigin(ctx context.Context, p serverconfig.Profile) (string, error) {
	q := p.IngressControllerReadPilot.Change
	certificate, e := loadProtectedTLSKeyPair(p.RemoteRead.TLSCertificatePath, p.RemoteRead.TLSPrivateKeyPath)
	if e != nil || len(certificate.Certificate) == 0 {
		return "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	root, e := x509.ParseCertificate(certificate.Certificate[len(certificate.Certificate)-1])
	if e != nil {
		return "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: q.OriginServerName, RootCAs: pool}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, e := http.NewRequestWithContext(ctx, http.MethodGet, q.OriginService+"/api/v1/status", nil)
	if e != nil {
		return "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	r.Host = q.Hostname
	response, e := client.Do(r)
	if e != nil {
		return "", ingress.Error(generated.ErrorCodeDependencyUnavailable)
	}
	defer response.Body.Close()
	if (response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden) || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || len(response.TLS.PeerCertificates) == 0 || digestBytes(response.TLS.PeerCertificates[0].Raw) != q.OriginIdentityDigest {
		return "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	return q.OriginIdentityDigest, nil
}

func (p *ingressPilotComposition) enabled(scope gate.ResolvedScope) bool {
	return p != nil && p.profile.IngressControllerReadPilot != nil && scope.ProfileID == "vegastack-labs" && slices.Contains(scope.Capabilities, ingress.PilotCapability)
}

func (p *ingressPilotComposition) borrow(ctx context.Context, id, purpose string, epoch int64) (*credentialref.Value, string, error) {
	r, e := p.source.credentials.GetActiveVersion(ctx, id, epoch)
	if e != nil || r.ConsumerID != ingress.AdapterID || r.PurposeID != purpose || r.TargetID != p.profile.IngressControllerReadPilot.Change.ProfileID || r.ActivatedAt == nil || !slices.Contains(r.VerifiedConsumerIDs, ingress.AdapterID) {
		return nil, "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	scope, e := p.source.gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return nil, "", e
	}
	cap, e := p.source.registry.ResolveCredentialCapability(r.ResolverID, ingress.AdapterID, scope.ProfileID)
	if e != nil || !slices.Contains(scope.Capabilities, cap) {
		return nil, "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	resolver, e := p.source.registry.ResolveCredentialResolver(r.ResolverID, ingress.AdapterID, scope.ProfileID)
	if e != nil {
		return nil, "", e
	}
	current, e := store.NewPlanRepository(p.store).CurrentRevision(ctx)
	if e != nil || current.RecoveryEpoch != epoch {
		return nil, "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	v, e := resolver.Resolve(ctx, credentialref.StepBinding{OperationID: "ingress-pilot-observe", AdapterID: ingress.AdapterID, ConsumerID: ingress.AdapterID, TargetID: r.TargetID, ReferenceID: r.ReferenceID, PurposeID: r.PurposeID, MaterialVersion: r.MaterialVersion, ResolverID: r.ResolverID, StateRevision: current.StateRevision, RecoveryEpoch: epoch})
	if e != nil || v == nil {
		if v != nil {
			v.Close()
		}
		return nil, "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	return v, ingress.Digest([]string{r.ReferenceID, r.MaterialVersion, r.ResolverID, r.PurposeID}), nil
}

// facts is also called again at execution. It derives facts; it never accepts
// caller checks, receipts, JWTs or a passed flag. Unknown observations deny.
func (p *ingressPilotComposition) facts(ctx context.Context, q generated.IngressDraftRequest) ([]generated.GateEvidenceFact, error) {
	deny := func() ([]generated.GateEvidenceFact, error) {
		return nil, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	if p == nil || p.profile.IngressControllerReadPilot == nil {
		return deny()
	}
	policy := *p.profile.IngressControllerReadPilot
	if ingress.ValidatePilotChange(policy, q.Change, q.RecoveryEpoch) != nil {
		return deny()
	}
	scope, e := p.source.gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return deny()
	}
	resolved := gate.ResolvedScope{ProfileID: scope.ProfileID, Capabilities: scope.Capabilities}
	if !p.enabled(resolved) || scope.RecoveryEpoch != q.RecoveryEpoch || !slices.Contains(scope.Capabilities, "cloudflare.ingress") || !slices.Contains(scope.Capabilities, "credential.ingress.read") {
		return deny()
	}
	if _, e = p.source.repository.PreviewPilotEvidence(ctx, q); e != nil {
		return nil, e
	}
	health, e := p.store.Health(ctx)
	if e != nil || health.Mode != store.DatabaseReady || health.RecoveryPending {
		return deny()
	}
	authority, e := p.store.CurrentAuthority(ctx)
	if e != nil || authority.InstanceID != policy.ControllerInstanceID || authority.RecoveryEpoch != policy.RecoveryEpoch {
		return deny()
	}
	machine, e := p.machine()
	if e != nil || machine != policy.ControllerMachineIDDigest {
		return deny()
	}
	principal, e := p.store.ResolveRemoteIdentity(ctx, policy.IdentityBindingDigest)
	if e != nil || principal.ID != q.Change.OwnerID {
		return deny()
	}
	id, e := identity.LoadCloudflareAccessProfile(ctx, p.profile.RemoteRead.IdentityConfigPath)
	if e != nil || ingress.Digest(id) != policy.IdentityProfileDigest || policy.IdentityBinding.Issuer != id.Issuer || len(policy.IdentityBinding.Audiences) != 1 || policy.IdentityBinding.Audiences[0] != id.Audience {
		return deny()
	}
	adapter, e := identity.NewCloudflareAccessAdapter(id, p.identityClient, time.Now)
	if e != nil || adapter.Refresh(ctx) != nil {
		return deny()
	}
	tlsDigest, e := p.probe(ctx, p.profile)
	if e != nil {
		return nil, e
	}
	observer, ok := p.source.backend.(interface {
		ObservePilotAudience(context.Context, generated.IngressChange, *credentialref.Value) (string, error)
	})
	if !ok {
		return deny()
	}
	versions := []string{}
	for _, ref := range []struct{ id, purpose string }{{q.Change.ObservationReferenceID, ingress.PurposeRead}, {q.Change.MutationReferenceID, ingress.PurposeWrite}} {
		v, version, e := p.borrow(ctx, ref.id, ref.purpose, q.RecoveryEpoch)
		if e != nil {
			return nil, e
		}
		audience, e := observer.ObservePilotAudience(ctx, q.Change, v)
		if e != nil || audience != id.Audience {
			v.Close()
			return deny()
		}
		read := q.Change
		read.Action, read.ResourceKind, read.ResourceID = "import", "tunnel-configuration", read.TunnelID
		read.ExpectedOwnershipRevision = 0
		s, e := p.source.backend.ObserveIngress(ctx, read, v)
		if e != nil {
			v.Close()
			return nil, e
		}
		if len(s.Connections) == 0 {
			v.Close()
			return deny()
		}
		for _, connection := range s.Connections {
			if connection.ConnectorID != q.Change.Connectors[0].ConnectorID {
				v.Close()
				return deny()
			}
		}
		read.ResourceKind, read.ResourceID = "access-policy", read.AccessPolicyID
		access, e := p.source.backend.ObserveIngress(ctx, read, v)
		v.Close()
		allowed, want := slices.Clone(access.AllowedGroupIDs), slices.Clone(q.Change.AllowedGroupIDs)
		slices.Sort(allowed)
		slices.Sort(want)
		if e != nil || !slices.Equal(allowed, want) {
			return deny()
		}
		versions = append(versions, version)
	}
	// This is an engine ownership denial canary, not a claim that Cloudflare's
	// management token is resource-scoped or that a provider write was tested.
	foreign := q.Change
	foreign.Hostname = "outside-pilot.invalid"
	if ingress.ValidatePilotChange(policy, foreign, q.RecoveryEpoch) == nil {
		return deny()
	}
	if _, e = p.source.repository.PreviewPilotEvidence(ctx, q); e != nil {
		return nil, e
	}
	facts := []generated.GateEvidenceFact{}
	for _, f := range []struct{ id, digest string }{{"pilot.policy", ingress.PilotPolicyDigest(policy)}, {"pilot.credentials", ingress.Digest(versions)}, {"pilot.tls", tlsDigest}, {"pilot.identity", ingress.Digest([]string{policy.IdentityBindingDigest, policy.IdentityProfileDigest})}, {"pilot.controller", ingress.Digest([]any{authority.InstanceID, machine, authority.RecoveryEpoch})}, {"pilot.provider-scope", ingress.ScopeDigest(q.Change)}} {
		facts = append(facts, generated.GateEvidenceFact{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: f.id, ValueDigest: f.digest})
	}
	return facts, nil
}

func pilotSubject(gateID string) (string, string) {
	if gateID == "G-016" {
		return ingress.AdapterID, "adapter"
	}
	return "scope", "site"
}

func (p *ingressPilotComposition) collect(ctx context.Context, q generated.IngressPilotEvidenceRequest, a audit.Attribution) (store.GateDraft, error) {
	facts, e := p.facts(ctx, q.Request)
	if e != nil {
		return store.GateDraft{}, e
	}
	if q.GateID != "platform-safety" && q.GateID != ingress.PilotGateID && q.GateID != "G-016" {
		return store.GateDraft{}, ingress.Error(generated.ErrorCodeInputInvalid)
	}
	subject, _ := pilotSubject(q.GateID)
	return p.source.gates.PutGateDraft(ctx, store.GateDraftRequest{EvidenceID: q.EvidenceID, GateID: q.GateID, SubjectID: subject, DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", SourceKind: "local", ProofClass: "live", ArtifactDigest: ingress.PilotPolicyDigest(*p.profile.IngressControllerReadPilot), Bundle: ingress.PilotBundle(facts, time.Now()), Expected: store.RevisionToken{StateRevision: q.Request.ExpectedStateRevision, RecoveryEpoch: q.Request.RecoveryEpoch}, KeyDigest: ingress.Digest(q.Request.IdempotencyKey), RequestDigest: ingress.Digest(q), Attribution: a})
}

func (p *ingressPilotComposition) evaluate(ctx context.Context, scope gate.ResolvedScope, gateID string, at time.Time) (generated.GateEvaluation, error) {
	current, e := store.NewPlanRepository(p.store).CurrentRevision(ctx)
	if e != nil || current.RecoveryEpoch != scope.RecoveryEpoch {
		return generated.GateEvaluation{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	scope.StateRevision = current.StateRevision
	q := generated.IngressDraftRequest{Change: p.profile.IngressControllerReadPilot.Change, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch}
	facts, e := p.facts(ctx, q)
	if e != nil {
		return generated.GateEvaluation{}, e
	}
	registry := gate.NewProofRegistry()
	v := gate.IngressPilotVerifier{PolicyDigest: ingress.PilotPolicyDigest(*p.profile.IngressControllerReadPilot), Facts: facts, Bundle: func(ctx context.Context, id string) (generated.GateEvidenceBundle, error) {
		d, e := p.source.gates.GetGateDraft(ctx, id)
		return d.Bundle, e
	}}
	for _, id := range []string{"platform-safety", ingress.PilotGateID, "G-016"} {
		registry.Register(id, "local", v)
	}
	subject, kind := pilotSubject(gateID)
	return gate.EvaluateIngressPilot(ctx, p.source.gates, scope, gate.Subject{ID: subject, Kind: kind, ReleaseBuildID: p.source.build.ReleaseBuildID, ToolVersion: p.source.build.ToolVersion, StateRevision: scope.StateRevision}, gateID, at, registry)
}

func (c *ingressAuthority) CollectPilotEvidence(ctx context.Context, q generated.IngressPilotEvidenceRequest) (store.GateDraft, error) {
	if c.pilot == nil {
		return store.GateDraft{}, ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	a, e := hostdiscovery.Attribution(ctx, "pilot-"+ingress.Digest(q)[7:39])
	if e != nil {
		return store.GateDraft{}, e
	}
	return c.pilot.collect(ctx, q, a)
}
func (c *ingressAuthority) EvaluatePilot(ctx context.Context, scope gate.ResolvedScope, subjectID, gateID string, at time.Time) (generated.GateEvaluation, bool, error) {
	if c.pilot == nil || !c.pilot.enabled(scope) || (gateID != "platform-safety" && gateID != ingress.PilotGateID && gateID != "G-016") {
		return generated.GateEvaluation{}, false, nil
	}
	subject, kind := pilotSubject(gateID)
	if subjectID != subject {
		return generated.GateEvaluation{}, false, nil
	}
	evaluation, e := c.pilot.evaluate(ctx, scope, gateID, at)
	if e != nil {
		evaluation, _ = gate.Evaluate(ctx, c.gates, scope, gate.Subject{ID: subject, Kind: kind, ReleaseBuildID: c.build.ReleaseBuildID, ToolVersion: c.build.ToolVersion}, gateID, at, gate.NewProofRegistry())
		evaluation.Outcome, evaluation.ReasonCode = "blocked", "pilot-observation-unavailable"
	}
	return evaluation, true, nil
}

// A controller-read pilot retains normal authentication/session handling and
// resource authorization, but exposes no ordinary browser/executor mutation.
func controllerReadPilotHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if (path == "/api" || strings.HasPrefix(path, "/api/")) && r.Method != http.MethodGet {
			session := r.Method == http.MethodPost && (path == "/api/v1/session" || path == "/api/v1/session/renew" || path == "/api/v1/session/logout")
			if !session {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "NOT_FOUND", http.StatusNotFound)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
