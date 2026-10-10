//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func accessAcceptanceInput(t *testing.T, f hostActionEnrollmentFixture) generated.DebianAccessInput {
	t.Helper()
	public, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ssh.NewPublicKey(public)
	if e != nil {
		t.Fatal(e)
	}
	k := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	d := f.DestinationIdentity
	a := generated.AccessAccount{Schema: generated.SchemaIDAccessAccount, SchemaVersion: "1.0.0", Name: "automation", UID: 1001, GID: 1001, Home: "/home/automation", Role: "automation", PublicKeys: []string{k}, PublicKeyDigests: []string{hostaction.BytesDigest([]byte(k))}}
	lock := generated.DebianProfileLock{Schema: generated.SchemaIDDebianProfileLock, SchemaVersion: "1.0.0", ImageDigest: d, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", PackageSourceDigest: d, Packages: []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "openssh-server", Version: "synthetic-test"}}, ExecutableVersion: "1.0.0", AnsibleVersion: "synthetic-test", AnsibleExecutableDigest: d, CollectionDigest: d, RoleDigest: d, Backend: "iptables-nft"}
	in := generated.DebianAccessInput{Schema: generated.SchemaIDDebianAccessInput, SchemaVersion: "1.0.0", HostID: "synthetic-host", HostIdentityDigest: d, ProfileID: "test-profile", ProfileLock: lock, ProfileLockDigest: hostaction.Digest(lock), ActionVersion: "1.0.0", AutomationUID: 1001, Accounts: []generated.AccessAccount{a}, SSHUsers: []string{"automation"}, SSHSourcePrefixes: []string{"127.0.0.1/32"}, RecoverySourcePrefixes: []string{"127.0.0.1/32"}, PrivilegedServiceKeys: []generated.AccessServiceKey{}, Interfaces: []generated.AccessInterface{{Schema: generated.SchemaIDAccessInterface, SchemaVersion: "1.0.0", Name: "eth0", Index: 2, Addresses: []string{f.Target.Address}}}, HostFlows: []generated.AccessFlow{}, ContainerFlows: []generated.AccessFlow{}}
	in.RollbackSpecification = generated.AccessRollbackSpecification{Schema: generated.SchemaIDAccessRollbackSpecification, SchemaVersion: "1.0.0", HostID: in.HostID, HostIdentityDigest: d, ProfileLockDigest: in.ProfileLockDigest, DeadlineSeconds: 600, RecoverySourcePrefixes: in.RecoverySourcePrefixes, OwnedState: []generated.AccessOwnedState{{Schema: generated.SchemaIDAccessOwnedState, SchemaVersion: "1.0.0", ResourceID: "ssh-config", BeforeDigest: d, AfterDigest: d}}}
	in.RollbackDigest = hostaction.Digest(in.RollbackSpecification)
	in.RenderedAccess = generated.RenderedAccess{Schema: generated.SchemaIDRenderedAccess, SchemaVersion: "1.0.0", ProfileLockDigest: in.ProfileLockDigest, RendererDigest: d, Accounts: in.Accounts, SSHUsers: in.SSHUsers, SSHSourcePrefixes: in.SSHSourcePrefixes, RecoverySourcePrefixes: in.RecoverySourcePrefixes, PrivilegedServiceKeys: in.PrivilegedServiceKeys, Interfaces: in.Interfaces, HostFlows: in.HostFlows, ContainerFlows: in.ContainerFlows, RollbackUnitsDigest: d}
	in.RenderedAccessDigest = hostaction.Digest(in.RenderedAccess)
	return in
}

// Real API/declaration/plan/Slack/engine/SSH/helper/receipt/store; target OS and
// network qualification observations below are explicitly synthetic. This is
// isolated software composition proof, not native Debian acceptance.
func TestHostAccessSequenceAcceptance(t *testing.T) {
	for _, mode := range []string{"success", "forged-result", "persistence-failure", "post-record-failure", "failed-probe"} {
		t.Run(mode, func(t *testing.T) {
			state := &accessAcceptanceOS{mode: mode}
			hostActionAcceptance(t, "success", hostActionAcceptanceHooks{EnrollmentOnly: true, Peer: func(t *testing.T, k ssh.Signer, s ActionSigner, _ *atomic.Int32, dir string) int {
				state.path = filepath.Join(dir, "access-state")
				return accessAcceptancePeer(t, k, s, dir, state)
			}, Enrollment: func(t *testing.T, f hostActionEnrollmentFixture) adapter.CredentialResolver {
				runAccessAcceptance(t, f, state)
				return hostActionAcceptanceCredential{key: f.Key}
			}})
		})
	}
}

type accessAcceptanceRenderer struct{}

func (accessAcceptanceRenderer) RenderRole(_ context.Context, in generated.DebianAccessInput) (generated.RenderedAccess, error) {
	return in.RenderedAccess, nil
}
func accessAcceptanceRequest(t *testing.T, f hostActionEnrollmentFixture) generated.HostAccessDraftRequest {
	in := accessAcceptanceInput(t, f)
	raw, _ := json.Marshal(in)
	current, e := store.NewPlanRepository(f.Authority).CurrentRevision(f.Context)
	if e != nil {
		t.Fatal(e)
	}
	r := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "debian.access.apply", ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), HostID: "synthetic-host", TargetRevision: 1, TargetDigest: f.TargetDigest, AutomationPrincipalID: "automation-a", CallerUID: 1001, CredentialReferenceID: "action-key", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: f.TargetDigest, HostIdentityDigest: f.DestinationIdentity}, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, IdempotencyKey: "access-a"}
	collect := r
	collect.ActionID = "debian.access.collect"
	collect.IdempotencyKey = "collect-a"
	d := hostaction.Digest("synthetic-source")
	source := generated.AccessProbeSource{Schema: generated.SchemaIDAccessProbeSource, SchemaVersion: "1.0.0", HostID: r.HostID, IdentityDigest: f.DestinationIdentity, Kind: "host-network", ContextID: "synthetic-context", ContextDigest: d, Interface: "lo", InterfaceIndex: 1, Address: "127.0.0.1", Family: "ipv4", RouteDigest: d}
	tuple := generated.AccessProbeTuple{Schema: generated.SchemaIDAccessProbeTuple, SchemaVersion: "1.0.0", HostID: r.HostID, IdentityDigest: f.DestinationIdentity, Address: f.Target.Address, Port: 22, Protocol: "tcp"}
	probe := generated.AccessProbeInput{Schema: generated.SchemaIDAccessProbeInput, SchemaVersion: "1.0.0", SubjectHostID: r.HostID, SubjectIdentityDigest: f.DestinationIdentity, SubjectHostKey: f.Target.HostKey, ProfileLockDigest: in.ProfileLockDigest, ApplyInputDigest: r.ActionInputDigest, RollbackDigest: in.RollbackDigest, AdministratorUser: "automation", Source: source, Cases: []generated.AccessProbeCase{}, TimeoutMillis: 10, Attempts: 1}
	for i, kind := range []string{"ssh-admin", "ssh-wrong-user", "ssh-password", "ssh-root", "host-flow", "host-flow"} {
		expected := "denied"
		if i == 0 || i == 4 {
			expected = "allowed"
		}
		destination := tuple
		if i == 5 {
			destination.Port = 1
		}
		probe.Cases = append(probe.Cases, generated.AccessProbeCase{Schema: generated.SchemaIDAccessProbeCase, SchemaVersion: "1.0.0", ProbeID: fmt.Sprintf("case-%d", i), Kind: kind, Expected: expected, Destination: destination, Witness: tuple})
	}
	local := r
	local.ActionID = "debian.access.probe.local"
	local.IdempotencyKey = "local-a"
	raw, _ = json.Marshal(probe)
	local.ActionInput = string(raw)
	local.ActionInputDigest = hostaction.BytesDigest(raw)
	probe.Source.Kind = "network-namespace"
	probe.Source.Address = "127.0.0.2"
	probe.Cases = []generated.AccessProbeCase{{Schema: generated.SchemaIDAccessProbeCase, SchemaVersion: "1.0.0", ProbeID: "case-source", Kind: "ssh-source", Expected: "denied", Destination: tuple, Witness: tuple}}
	remote := r
	remote.ActionID = "debian.access.probe-source"
	remote.IdempotencyKey = "remote-a"
	raw, _ = json.Marshal(probe)
	remote.ActionInput = string(raw)
	remote.ActionInputDigest = hostaction.BytesDigest(raw)
	return generated.HostAccessDraftRequest{Schema: generated.SchemaIDHostAccessDraftRequest, SchemaVersion: "1.0.0", Subject: r, Input: in, Probes: []generated.HostAccessProbeRequest{{Schema: generated.SchemaIDHostAccessProbeRequest, SchemaVersion: "1.0.0", Kind: "collect", Request: collect}, {Schema: generated.SchemaIDHostAccessProbeRequest, SchemaVersion: "1.0.0", Kind: "local-probe", Request: local}, {Schema: generated.SchemaIDHostAccessProbeRequest, SchemaVersion: "1.0.0", Kind: "source-probe", Request: remote}}}
}
func runAccessAcceptance(t *testing.T, f hostActionEnrollmentFixture, state *accessAcceptanceOS) {
	t.Helper()
	f.UseWallClock()
	ctx := f.Context
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := f.DB.ExecContext(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	d := hostaction.Digest("synthetic-active-key")
	exec(`INSERT INTO credential_reference_versions VALUES('access-active','action-key','host-action','host-action-ssh','synthetic-host','native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','operator-a','now')`, d, time.Now().UTC().Format(time.RFC3339), []byte(`["host-action"]`), d)
	exec(`INSERT INTO effective_authorization_principals VALUES('automation-a','agent','active',1,'now','now')`)
	exec(`INSERT INTO effective_authorization_grants VALUES('automation-action','automation-a','infrastructure-admin','execute','host.action.execute','execution-target','synthetic-host','human',1,'active','now','now')`)
	grant := func(id, action, cap, kind, target string, branch any) {
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, action, cap, kind, target, branch)
	}
	grant("access-prepare", "author", "host.action.prepare", "host", "synthetic-host", nil)
	request := accessAcceptanceRequest(t, f)
	compiled, e := debianaccess.BuildDraft(request)
	if e != nil {
		t.Fatal(e)
	}
	declarationID := "host-access-" + hostaction.Digest(compiled.Sequence)[7:39]
	grant("access-declaration", "author", "declaration.author", "declaration", declarationID, nil)
	hosts := store.NewHostActionRepository(f.Authority)
	credentials := store.NewCredentialRepository(f.Authority)
	if e = api.RegisterHostAccessOperations(f.App, api.HostAccessOperations{Hosts: hosts, Declarations: f.Declarations, Credentials: credentials, Renderer: accessAcceptanceRenderer{}, Results: f.Results}); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(request)
	httpRequest := httptest.NewRequest("POST", "/api/v1/host-access/draft", bytes.NewReader(raw)).WithContext(ctx)
	httpRequest.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.App.ServeHTTP(w, httpRequest)
	if w.Code != 200 && w.Code != 201 {
		t.Fatalf("draft HTTP%d: %s", w.Code, w.Body.String())
	}
	var envelope struct {
		Data generated.HostActionSubmission `json:"data"`
	}
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || envelope.Data.DeclarationID != declarationID {
		t.Fatal("wrong draft response")
	}
	revisions := store.NewPlanRepository(f.Authority)
	observations, e := planengine.NewStateObservationReader(revisions)
	if e != nil {
		t.Fatal(e)
	}
	plans, e := planengine.NewService(planengine.Config{HostActions: hosts, HostActionCredentials: credentials, Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if e != nil {
		t.Fatal(e)
	}
	declaration, e := f.Declarations.Get(ctx, declarationID, 1)
	if e != nil {
		t.Fatal(e)
	}
	current, e := revisions.CurrentRevision(ctx)
	if e != nil {
		t.Fatal(e)
	}
	fingerprint, e := observations.CurrentFingerprint(ctx, declarationID, declaration.Operations)
	if e != nil {
		t.Fatal(e)
	}
	created, e := plans.Create(ctx, planengine.AuthorScope{PrincipalID: "operator-a", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "access-test"}, generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: declarationID, DeclarationRevision: 1, ExpectedStateRevision: current.StateRevision, RecoveryEpoch: current.RecoveryEpoch, ObservationFingerprint: fingerprint, IdempotencyKey: "access-plan", Extensions: declaration.Extensions})
	if e != nil {
		t.Fatal(e)
	}
	p := created.Plan
	grant("access-execute", "execute", "host.action.execute", "execution-target", "synthetic-host", "human")
	grant("access-local-probe", "execute", debianaccess.LocalProbeOperation, "execution-target", "synthetic-host", "human")
	// Adoption already granted this exact host acknowledgement scope.
	policy := store.NewEffectiveAuthorizationRepository(f.Authority)
	ack, e := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(f.Authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: authorization.NewEvaluator(policy), Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	human := identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	card, e := ack.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "access-nonce"}, p.PlanID)
	if e != nil {
		t.Fatal(e)
	}
	approved := hostActionAcceptanceSlackApproval(t, ack, card)
	live, e := NewHostActionAuthority(hosts, f.Signer, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	composition := hostAccessComposition{store: f.Authority, hosts: hosts, allowed: []string{f.DestinationIdentity}}
	recorder := accessAcceptanceRecorder{actual: composition, state: state, db: f.DB, t: t}
	implementation, e := transport.NewWithAccess(hostActionTargets{repository: hosts, allowed: []string{f.DestinationIdentity}}, &HostActionBundleIssuer{Repository: hosts, Signer: f.Signer, Clock: time.Now}, live, composition, accessAcceptanceLocalProbe{state}, recorder)
	if e != nil {
		t.Fatal(e)
	}
	registry := adapter.NewRegistry()
	if e = registry.Register(hostaction.AdapterID, implementation); e != nil {
		t.Fatal(e)
	}
	if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: "host-action", ProfileID: "synthetic-profile", CapabilityID: "synthetic-capability", Enabled: true}, hostActionAcceptanceCredential{key: f.Key}); e != nil {
		t.Fatal(e)
	}
	engine, e := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(f.Authority), Plans: plans, Admission: runengine.NewAdmissionGate(ack, time.Now), Adapters: registry, SecretGate: hostActionGate{targets: hosts, allowed: []string{f.DestinationIdentity}}, CredentialStep: &runengine.CredentialStep{Bindings: credentials, Resolvers: registry, Profiles: hostActionAcceptanceProfile{}, Plans: plans, Clock: time.Now}, Clock: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	branch := "human"
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "access-decision", PrincipalID: human.ID, Action: "execute", TargetID: "synthetic-host", Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, PlanDigest: p.PlanDigest, DecidedAt: time.Now().UTC().Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	applied, err := engine.Submit(ctx, runengine.SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: p.PlanID, PlanDigest: p.PlanDigest, IdempotencyKey: "run-access", Extensions: []generated.ContractExtension{}}, Authorization: decision, Acknowledgement: &approved, Attribution: audit.Attribution{AuthenticatedPrincipalID: human.ID, AuthenticatedPrincipalMethod: human.Method, ResponsibleHumanPrincipalID: &human.ID}})
	raw, e = os.ReadFile(state.path)
	if e != nil {
		t.Fatalf("apply did not execute: run=%+v err=%v read=%v", applied, err, e)
	}
	if state.mode == "success" {
		if err != nil || applied.Status != "succeeded" || string(raw) != "confirmed" {
			t.Fatalf("sequence failed: %+v %v file=%s", applied, err, raw)
		}
	} else if applied.Status == "succeeded" || string(raw) != "armed" {
		t.Fatalf("unsafe denial: %+v %v file=%s", applied, err, raw)
	}
	switch state.mode {
	case "forged-result":
		if state.recorderCalls != 1 || state.recorderError != generated.ErrorCodeIntegrityFailure {
			t.Fatal("forged-result branch not exercised", state.recorderCalls, state.recorderError)
		}
	case "persistence-failure":
		if state.recorderCalls != 1 || state.recorderError == "" {
			t.Fatal("persistence branch not exercised")
		}
	case "failed-probe":
		if !state.failedProbe.Load() || state.recorderCalls < 3 {
			t.Fatal("failed actual probe branch not reached", state.recorderCalls)
		}
	}
	var n int
	if e = f.DB.QueryRow(`SELECT count(*) FROM gate_applied_evidence`).Scan(&n); e != nil || n != 0 {
		t.Fatal("software test promoted admission", n, e)
	}
	if state.mode == "post-record-failure" {
		rows, err := store.NewGateRepository(f.Authority).ReadHostControlResults(ctx, "synthetic-host")
		if err != nil || len(rows) != 0 {
			t.Fatal("unverified step exposed evidence", rows, err)
		}
		if e = f.DB.QueryRow(`SELECT count(*) FROM host_control_results`).Scan(&n); e != nil || n != 1 {
			t.Fatal("expected retained audit observation", n, e)
		}
	}
	if state.mode == "success" {
		if e = f.DB.QueryRow(`SELECT count(*) FROM host_control_results`).Scan(&n); e != nil || n != 10 {
			t.Fatal("missing actual result rows", n, e)
		}
	}
}

type accessAcceptanceOS struct {
	mode, path    string
	recorderCalls int
	recorderError string
	failedProbe   atomic.Bool
}
type accessAcceptanceLocalProbe struct{ s *accessAcceptanceOS }

func (p accessAcceptanceLocalProbe) Execute(_ context.Context, in generated.AccessProbeInput, _ []*credentialref.Value) ([]generated.AccessMeasurement, error) {
	p.s.failedProbe.Store(p.s.mode == "failed-probe")
	return accessAcceptanceMeasurements(in, p.s.mode), nil
}
func accessAcceptanceMeasurements(in generated.AccessProbeInput, mode string) []generated.AccessMeasurement {
	out := []generated.AccessMeasurement{}
	for i, c := range in.Cases {
		actual, status := c.Expected, "passed"
		if mode == "failed-probe" && i == 0 {
			actual = "error"
			status = "failed"
		}
		kind := "ssh"
		if strings.HasPrefix(c.Kind, "host-") {
			kind = "host-flow"
		}
		if strings.HasPrefix(c.Kind, "container-") {
			kind = "container-flow"
		}
		m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: c.ProbeID, Kind: kind, Status: status, SubjectHostID: in.SubjectHostID, SubjectIdentityDigest: in.SubjectIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ProducerID: "debian-access-probe", ProducerVersion: "1.0.0", BundleDigest: hostaction.Digest(in), ObservedAt: time.Now().UTC().Format(time.RFC3339), ConfigurationDigest: in.ApplyInputDigest, PositiveProbeDigest: hostaction.Digest("synthetic-positive"), NegativeProbeDigest: hostaction.Digest("synthetic-negative"), Reason: "synthetic-os-observation", Probe: &generated.AccessProbeObservation{Schema: generated.SchemaIDAccessProbeObservation, SchemaVersion: "1.0.0", ProbeID: c.ProbeID, SourceHostID: in.Source.HostID, SourceIdentityDigest: in.Source.IdentityDigest, SourceContextDigest: in.Source.ContextDigest, ActualSourceAddress: in.Source.Address, SourceNamespaceDigest: hostaction.Digest("synthetic-namespace"), DestinationDigest: hostaction.Digest(c.Destination), WitnessDigest: hostaction.Digest(c.Witness), Expected: c.Expected, Actual: actual}}
		m.MeasurementDigest = hostaction.MeasurementDigest(m)
		out = append(out, m)
	}
	return out
}

type accessAcceptanceHandler struct{ s *accessAcceptanceOS }

func (h accessAcceptanceHandler) Lookup(id, version string) (hostaction.Handler, bool) {
	return h, version == "1.0.0" && (id == "debian.access.apply" || id == "debian.access.collect" || id == "debian.access.probe-source" || id == "debian.access.confirm")
}
func (h accessAcceptanceHandler) Execute(_ context.Context, b generated.HostActionBundle) (generated.HostActionResult, error) {
	digest, _ := hostaction.BundleDigest(b)
	result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: digest, Status: "succeeded", Reason: "measured", EffectObserved: true}
	if b.ActionID == "debian.access.probe-source" {
		var in generated.AccessProbeInput
		if e := json.Unmarshal([]byte(b.ActionInput), &in); e != nil {
			return result, e
		}
		result.ControlMeasurements = accessAcceptanceMeasurements(in, h.s.mode)
	} else {
		var in generated.DebianAccessInput
		var profile, inputDigest string
		if b.ActionID == "debian.access.confirm" {
			var confirm generated.AccessConfirmInput
			if e := json.Unmarshal([]byte(b.ActionInput), &confirm); e != nil {
				return result, e
			}
			if b.VerificationEvidence == nil || b.VerificationEvidence.RollbackRecordDigest != hostaction.Digest("synthetic-rollback-record") {
				return result, fmt.Errorf("missing receipt-backed confirmation")
			}
			profile = confirm.ProfileLockDigest
			inputDigest = confirm.ApplyInputDigest
			if e := os.WriteFile(h.s.path, []byte("confirmed"), 0600); e != nil {
				return result, e
			}
		} else {
			if e := json.Unmarshal([]byte(b.ActionInput), &in); e != nil {
				return result, e
			}
			profile = in.ProfileLockDigest
			inputDigest = b.ActionInputDigest
			if b.ActionID == "debian.access.apply" {
				if e := os.WriteFile(h.s.path, []byte("armed"), 0600); e != nil {
					return result, e
				}
			} else if raw, e := os.ReadFile(h.s.path); e != nil || string(raw) != "armed" {
				return result, fmt.Errorf("missing applied state")
			}
		}
		m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: "debian.ssh", Kind: "ssh", Status: "passed", SubjectHostID: b.HostID, SubjectIdentityDigest: b.HostIdentityDigest, ProfileLockDigest: profile, ProducerID: "synthetic-os", ProducerVersion: "1.0.0", BundleDigest: digest, ObservedAt: time.Now().UTC().Format(time.RFC3339), ConfigurationDigest: inputDigest, PositiveProbeDigest: hostaction.Digest("synthetic-positive"), NegativeProbeDigest: hostaction.Digest("synthetic-negative"), Reason: "synthetic-os-observation"}
		if b.ActionID == "debian.access.apply" {
			m.Status = "partial"
			m.RollbackRecordDigest = hostaction.Digest("synthetic-rollback-record")
		}
		result.ControlMeasurements = []generated.AccessMeasurement{m}
	}
	for i := range result.ControlMeasurements {
		result.ControlMeasurements[i].BundleDigest = digest
		result.ControlMeasurements[i].MeasurementDigest = hostaction.MeasurementDigest(result.ControlMeasurements[i])
	}
	result.ResultDigest = hostaction.ResultDigest(result)
	return result, nil
}
func (h accessAcceptanceHandler) Verify(_ context.Context, b generated.HostActionBundle, _ generated.HostActionResult) error {
	if b.ActionID == "debian.access.apply" || b.ActionID == "debian.access.confirm" {
		raw, e := os.ReadFile(h.s.path)
		expected := "armed"
		if b.ActionID == "debian.access.confirm" {
			expected = "confirmed"
		}
		if e != nil || string(raw) != expected {
			return fmt.Errorf("effect absent")
		}
	}
	return nil
}

type accessAcceptanceRecorder struct {
	t      *testing.T
	actual hostAccessComposition
	state  *accessAcceptanceOS
	db     *sql.DB
}

func (r accessAcceptanceRecorder) RecordVerifiedControlResults(ctx context.Context, op adapter.Operation, b adapter.ExactExecutionBinding, e adapter.Effect, result generated.HostActionResult) error {
	r.state.recorderCalls++
	if r.state.mode == "forged-result" {
		result.ControlMeasurements[0].Reason = "forged"
		result.ControlMeasurements[0].MeasurementDigest = hostaction.MeasurementDigest(result.ControlMeasurements[0])
		result.ResultDigest = hostaction.ResultDigest(result)
		e.ResultDigest = result.ResultDigest
	}
	if r.state.mode == "persistence-failure" {
		if _, err := r.db.ExecContext(ctx, `CREATE TRIGGER test_result_persistence_failure BEFORE INSERT ON host_control_results BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END`); err != nil {
			return err
		}
	}
	err := r.actual.RecordVerifiedControlResults(ctx, op, b, e, result)
	r.state.recorderError = store.Code(err)
	r.t.Logf("recorder actual result for %s: %v", op.OperationID, err)
	if err == nil && r.state.mode == "post-record-failure" {
		return fmt.Errorf("synthetic failure after actual receipt-backed append")
	}
	return err
}

func accessAcceptancePeer(t *testing.T, key ssh.Signer, signer ActionSigner, directory string, state *accessAcceptanceOS) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	receiptsPath := filepath.Join(directory, "receipts")
	if err = os.Mkdir(receiptsPath, 0700); err != nil {
		t.Fatal(err)
	}
	receipts, err := hostaction.OpenReceipts(receiptsPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receipts.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
					if !bytes.Equal(k.Marshal(), key.PublicKey().Marshal()) {
						return nil, fmt.Errorf("wrong synthetic credential")
					}
					return nil, nil
				}}
				cfg.AddHostKey(key)
				server, channels, requests, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer server.Close()
				go ssh.DiscardRequests(requests)
				for channel := range channels {
					if channel.ChannelType() != "session" {
						_ = channel.Reject(ssh.UnknownChannelType, "denied")
						continue
					}
					ch, reqs, err := channel.Accept()
					if err != nil {
						return
					}
					defer ch.Close()
					for req := range reqs {
						var command struct{ Command string }
						if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil || command.Command != "/usr/bin/sudo -n -- /usr/local/bin/vsk-labs host-action-once" {
							_ = req.Reply(false, nil)
							continue
						}
						_ = req.Reply(true, nil)
						policy := hostaction.Policy{HostID: "synthetic-host", HostIdentityDigest: hostadoption.IdentityDigest("product-serial", "synthetic-serial"), CallerUID: 1001, KeyID: signer.KeyID(), PublicKey: signer.PublicKey()}
						err = hostaction.RunOnce(context.Background(), ch, ch, policy, receipts, accessAcceptanceHandler{state}, time.Now, rand.Reader)
						code := uint32(0)
						if err != nil {
							code = 1
						}
						_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}
