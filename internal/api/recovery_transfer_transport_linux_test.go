//go:build linux

package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/server"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
)

func TestRecoveryTransferAPIApprovedReceiveSuspendsSource(t *testing.T) {
	recoveryTransferTransport(t, "")
}
func TestRecoveryTransferRejectsHistoryAfterStaging(t *testing.T) {
	recoveryTransferTransport(t, "preparation")
}
func TestRecoveryTransferRejectsHistoryBeforeSuspension(t *testing.T) {
	recoveryTransferTransport(t, "suspension")
}
func recoveryTransferTransport(t *testing.T, drift string) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sshKey, e := ssh.NewSignerFromKey(key)
	if e != nil {
		t.Fatal(e)
	}
	api.RunRecoveryTransferAcceptance(t, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshKey.PublicKey()))), func(f api.RecoveryTransferAcceptance) {
		ex := func(q string, args ...any) {
			t.Helper()
			if _, e := f.DB.Exec(q, args...); e != nil {
				t.Fatal(e)
			}
		}
		hosts := store.NewHostActionRepository(f.Authority)
		credentials := store.NewCredentialRepository(f.Authority)
		revisions := store.NewPlanRepository(f.Authority)
		descriptor := f.Descriptor
		host := descriptor.Replacement.NewHostID
		private, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		keyBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
		signer := transferSigner{key}
		destination := filepath.Join(t.TempDir(), "control.db")
		if e = os.Chmod(filepath.Dir(destination), 0700); e != nil {
			t.Fatal(e)
		}
		open := func(ctx context.Context, p string) (*store.Store, error) {
			return store.Open(ctx, store.Config{DatabasePath: p, Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "1.0.0", BuildVersion: "build-a", Clock: f.Clock})
		}
		bundles := recovery.StoreRecoveryBundleStore{Authority: f.Authority, Open: open, Plans: revisions, Restores: store.NewRestoreRepository(f.Authority)}
		receiver := recovery.CandidateTransferReceiver{DatabasePath: destination, ExpectedUID: uint32(os.Geteuid()), Authority: recovery.StoreCandidateAuthority{Open: open}, Bundles: bundles, Destination: transferPhysicalBoundary{descriptor}}
		peer := transferSSHPeer(t, sshKey, signer, descriptor, receiver)
		authority, e := server.NewHostActionAuthority(hosts, signer, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		a, e := transport.New(transferTarget{hosts, peer}, &server.HostActionBundleIssuer{Repository: hosts, Signer: signer, Clock: time.Now}, authority)
		if e != nil {
			t.Fatal(e)
		}
		if e = a.SetRecoveryPayloadSource(func(ctx context.Context, b generated.HostActionBundle) (*transport.RecoveryPayload, error) {
			s, e := recovery.OpenCandidateTransfer(ctx, f.DatabasePath, uint32(os.Geteuid()), descriptor)
			if e != nil {
				return nil, e
			}
			return &transport.RecoveryPayload{Descriptor: s.Descriptor, Candidate: s.Candidate, Journal: s.Journal}, nil
		}); e != nil {
			t.Fatal(e)
		}
		appendUnrelated := func() {
			var ordinal int64
			if err := f.DB.QueryRow(`SELECT COALESCE(MAX(event_ordinal),0)+1 FROM host_alias_history`).Scan(&ordinal); err != nil {
				t.Fatal(err)
			}
			event := store.HostAliasEvent{Ordinal: ordinal, Alias: generated.HostReplacementAliasBinding{Schema: generated.SchemaIDHostReplacementAliasBinding, SchemaVersion: "1.0.0", AliasID: "after-staging-unrelated", OwnerHostID: "unrelated-host", OwnerIdentityDigest: hostaction.Digest("unrelated"), OwnerRevision: 1, OwnershipGeneration: 1}, Execution: store.HostReplacementExecution{DraftID: "synthetic-unrelated-claim"}, StateRevision: f.Descriptor.Replacement.ExpectedStateRevision}
			raw, _ := json.Marshal(event)
			digest := hostaction.Digest(event)
			ex(`INSERT INTO host_alias_history VALUES(?,?,?,?,?,?,?,?,?)`, ordinal, event.Alias.AliasID, int64(1), event.Alias.OwnerHostID, event.Alias.OwnerIdentityDigest, int64(1), nil, digest, raw)
			ex(`INSERT INTO host_alias_owners VALUES(?,?,?,?,?,?,?)`, event.Alias.AliasID, event.Alias.OwnerHostID, event.Alias.OwnerIdentityDigest, int64(1), int64(1), digest, nil)
		}
		if e = a.SetRecoveryReceiveFinalizer(func(ctx context.Context, b generated.HostActionBundle, d generated.ControlRecoveryReceiveInput, r generated.HostActionResult) error {
			if drift == "suspension" {
				appendUnrelated()
			}
			return f.Authority.SuspendRecoverySource(ctx, b, d, r)
		}); e != nil {
			t.Fatal(e)
		}
		resolver := transferCredential{keyBytes}
		registry := adapter.NewRegistry()
		if e = registry.Register(hostaction.AdapterID, a); e != nil {
			t.Fatal(e)
		}
		if e = registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "native-systemd", ConsumerID: hostaction.AdapterID, ProfileID: "transfer-profile", CapabilityID: "transfer-ssh", Enabled: true}, resolver); e != nil {
			t.Fatal(e)
		}
		ex(`INSERT INTO effective_authorization_principals VALUES('transfer-automation','agent','active',1,'now','now')`)
		ex(`INSERT INTO credential_reference_versions VALUES('transfer-credential','transfer-credential','host-action','host-action-ssh',?,'native-systemd','version-a',?,'active',1,0,?,?,'fixture-declaration',1,'fixture-plan',?,'fixture-run','fixture-step','fixture-lease','human-a','now')`, host, hostaction.BytesDigest(keyBytes), f.Clock().Format(time.RFC3339), []byte(`["host-action"]`), hostaction.Digest("credential-plan"))
		grant := func(id, principal, action, cap, kind, target string, branch any) {
			var existing int
			if err := f.DB.QueryRow(`SELECT count(*) FROM effective_authorization_grants WHERE principal_id=? AND role_id='control-plane-admin' AND action=? AND capability=? AND resource_kind=? AND resource_id=? AND branch IS ? AND status='active' AND grant_revision=1`, principal, action, cap, kind, target, branch).Scan(&existing); err != nil {
				t.Fatal(err)
			}
			if existing == 1 {
				return
			}

			ex(`INSERT INTO effective_authorization_grants VALUES(?,?,'control-plane-admin',?,?,?,?,?,1,'active','now','now')`, id, principal, action, cap, kind, target, branch)
		}
		for _, subject := range []string{descriptor.Replacement.OldHostID, host} {
			grant("transfer-exec-"+subject, "human-a", "execute", "host.action.execute", "execution-target", subject, "human")
			grant("transfer-human-"+subject, "human-a", "acknowledge", "plan.acknowledge", "plan-target", subject, "human")
		}
		grant("transfer-auto", "transfer-automation", "execute", "host.action.execute", "execution-target", host, "human")
		factory := f.Results
		prep := server.NewRecoveryReceivePreparer(f.Authority, f.Gates, f.DatabasePath, uint32(os.Geteuid()), f.Clock)
		if e = api.RegisterHostActionOperations(f.App, api.HostActionOperations{Hosts: hosts, Declarations: f.Declarations, Credentials: credentials, RecoveryReceivePreparer: prep, Results: factory}); e != nil {
			t.Fatal(e)
		}
		evaluator := authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(f.Authority))
		engine, e := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(f.Authority), Plans: f.Plans, Admission: runengine.NewAdmissionGate(f.Acknowledgements, f.Clock), Adapters: registry, SecretGate: transferSecretGate{hosts}, CredentialStep: &runengine.CredentialStep{Bindings: credentials, Resolvers: registry, Profiles: resolver, Plans: f.Plans, Clock: f.Clock}, Clock: f.Clock})
		if e != nil {
			t.Fatal(e)
		}
		if e = api.RegisterRunOperations(f.App, api.RunOperationConfig{Runs: engine, Plans: revisions, Acknowledgements: f.Acknowledgements, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: evaluator, Recorder: store.NewEffectiveAuthorizationRepository(f.Authority), Clock: f.Clock}}); e != nil {
			t.Fatal(e)
		}
		callAs := func(principal, method, path string, in any) *httptest.ResponseRecorder {
			var raw []byte
			if in != nil {
				raw, _ = json.Marshal(in)
			}
			r := httptest.NewRequest(method, path, bytes.NewReader(raw))
			r.Header.Set("Content-Type", "application/json")
			r = r.WithContext(identity.WithVerifiedPrincipal(r.Context(), identity.Principal{ID: principal, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
			w := httptest.NewRecorder()
			f.App.ServeHTTP(w, r)
			return w
		}
		call := func(method, path string, in any) *httptest.ResponseRecorder {
			return callAs("human-a", method, path, in)
		}
		rev, e := revisions.CurrentRevision(f.Context)
		if e != nil {
			t.Fatal(e)
		}
		selector := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: descriptor.Binding.PlanID, PlanDigest: descriptor.Binding.PlanDigest, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "receive-source", Extensions: []generated.ContractExtension{}}
		raw, _ := json.Marshal(selector)
		request := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: hostaction.RecoveryReceiveAction, ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), HostID: host, TargetRevision: descriptor.Replacement.NewTargetRevision, TargetDigest: descriptor.Replacement.NewTargetDigest, AutomationPrincipalID: "transfer-automation", CallerUID: descriptor.ServiceUID, CredentialReferenceID: "transfer-credential", CredentialMaterialVersion: "version-a", ExpectedStateRevision: rev.StateRevision, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "receive-action", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: descriptor.Replacement.NewTargetDigest, HostIdentityDigest: descriptor.Replacement.NewIdentityDigest}}
		if drift == "preparation" {
			appendUnrelated()
			latest, err := revisions.CurrentRevision(f.Context)
			if err != nil {
				t.Fatal(err)
			}
			request.ExpectedStateRevision = latest.StateRevision
			request.RecoveryEpoch = latest.RecoveryEpoch
			if _, err = prep.PrepareRecoveryReceive(f.Context, request); err == nil {
				t.Fatal("new unrelated history omitted by current-revision receive preparation")
			}
			return
		}
		for _, variant := range []string{"stale-revision", "wrong-pending", "revoked-author"} {
			t.Run(variant, func(t *testing.T) {
				bad := request
				principal := "human-a"
				switch variant {
				case "stale-revision":
					bad.ExpectedStateRevision--
				case "wrong-pending":
					wrong := selector
					wrong.PlanID = "unrelated-restore"
					raw, _ := json.Marshal(wrong)
					bad.ActionInput = string(raw)
					bad.ActionInputDigest = hostaction.BytesDigest(raw)
				case "revoked-author":
					principal = "transfer-revoked-human"
					ex(`INSERT INTO effective_authorization_principals VALUES(?,'human','active',1,'now','now')`, principal)
					ex(`INSERT INTO effective_authorization_grants SELECT 'revoked-copy-' || grant_id,?,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at FROM effective_authorization_grants WHERE principal_id='human-a'`, principal)
					ex(`UPDATE effective_authorization_grants SET status='revoked' WHERE principal_id=? AND action='author' AND capability='host.action.prepare' AND resource_id=?`, principal, host)
				}
				response := callAs(principal, http.MethodPost, "/api/v1/host-actions/draft", bad)
				if response.Code < 400 || response.Code >= 500 {
					t.Fatalf("denial %s: %d %s", variant, response.Code, response.Body.String())
				}
				var count int
				if e := f.DB.QueryRow(`SELECT count(*) FROM audit_events WHERE event_type='recovery.source-suspended'`).Scan(&count); e != nil || count != 0 {
					t.Fatal("denied request suspended source", count, e)
				}
				if _, e := os.Lstat(destination); !os.IsNotExist(e) {
					t.Fatal("denied request created receiver authority", e)
				}
			})
		}
		rendered, e := prep.PrepareRecoveryReceive(f.Context, request)
		if e != nil {
			t.Fatal("server receive prep", e)
		}
		id := hostaction.DraftID(rendered)
		grant("transfer-author", "human-a", "author", "declaration.author", "declaration", id, nil)
		w := call(http.MethodPost, "/api/v1/host-actions/draft", request)
		if w.Code != 200 {
			t.Fatalf("receive draft %d %s", w.Code, w.Body.String())
		}
		var draft struct {
			Data generated.HostActionSubmission
		}
		if json.Unmarshal(w.Body.Bytes(), &draft) != nil || draft.Data.OriginalRequestDigest != hostaction.Digest(request) {
			t.Fatal("original selector binding")
		}
		grant("transfer-plan", "human-a", "author", "plan.author", "declaration", id, nil)
		w = call(http.MethodGet, "/api/v1/declarations/"+id+"/revisions/1/plan-preparation", nil)
		var preparation struct{ Data generated.PlanPreparation }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &preparation) != nil {
			t.Fatalf("prepare plan %d %s", w.Code, w.Body.String())
		}
		p := preparation.Data
		declaration, e := f.Declarations.Get(f.Context, id, 1)
		if e != nil {
			t.Fatal(e)
		}
		w = call(http.MethodPost, "/api/v1/declarations/"+id+"/plans", generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: id, DeclarationRevision: p.DeclarationRevision, ExpectedStateRevision: p.ExpectedStateRevision, RecoveryEpoch: p.RecoveryEpoch, ObservationFingerprint: p.ObservationFingerprint, IdempotencyKey: "transfer-plan", Extensions: declaration.Extensions})
		var planned struct{ Data generated.PlanPresentation }
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &planned) != nil {
			t.Fatalf("receive plan %d %s", w.Code, w.Body.String())
		}
		card, e := f.Acknowledgements.Request(f.Context, acknowledgement.Scope{Human: identity.Principal{ID: "human-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}, AuthorityID: "fixture-authority", Nonce: "receive-nonce"}, planned.Data.Plan.PlanID)
		if e != nil {
			t.Fatal(e)
		}
		api.ApproveRecoveryTransferPlan(t, f.Acknowledgements, card)
		w = call(http.MethodPost, "/api/v1/plans/"+planned.Data.Plan.PlanID+"/execute", generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: planned.Data.Plan.PlanID, PlanDigest: planned.Data.Plan.PlanDigest, RecoveryEpoch: rev.RecoveryEpoch, IdempotencyKey: "receive-execution", Extensions: []generated.ContractExtension{}})
		if drift == "suspension" {
			var mode string
			var count int
			if err := f.DB.QueryRow(`SELECT authority_mode FROM system_meta WHERE id=1`).Scan(&mode); err != nil || mode != "ready" {
				t.Fatal("history drift suspended source", mode, err)
			}
			if err := f.DB.QueryRow(`SELECT count(*) FROM audit_events WHERE event_type='recovery.source-suspended'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("history drift suspension audit", count, err)
			}
			if _, err := os.Stat(destination); err != nil {
				t.Fatal("test failed before actual receive", err)
			}
			return
		}
		var mode string
		var count int
		if e = f.DB.QueryRow(`SELECT authority_mode FROM system_meta WHERE id=1`).Scan(&mode); e != nil || mode != "recovery-required" {
			t.Fatalf("source not suspended mode=%s err=%v response=%d %s", mode, e, w.Code, w.Body.String())
		}
		if e = f.DB.QueryRow(`SELECT count(*) FROM audit_events WHERE event_type='recovery.source-suspended'`).Scan(&count); e != nil || count != 1 {
			t.Fatal("suspension audit", count, e)
		}
		var runStatus string
		if e = f.DB.QueryRow(`SELECT status FROM plan_runs WHERE plan_id=?`, planned.Data.Plan.PlanID).Scan(&runStatus); e != nil || runStatus == "succeeded" {
			t.Fatal("source claimed finalization after suspension", runStatus, e)
		}
		h, e := f.Authority.Health(f.Context)
		if e != nil || h.MutationEnabled {
			t.Fatal("former authority writable", e)
		}
		forbidden := request
		forbidden.IdempotencyKey = "former-authority-write"
		response := call(http.MethodPost, "/api/v1/host-actions/draft", forbidden)
		if response.Code < 400 {
			t.Fatalf("suspended source accepted mutation: %d %s", response.Code, response.Body.String())
		}
		recovered, e := open(context.Background(), destination)
		if e != nil {
			t.Fatal(e)
		}
		defer recovered.Close()
		receiverHealth, e := recovered.Health(context.Background())
		if e != nil || receiverHealth.MutationEnabled || !receiverHealth.RecoveryPending {
			t.Fatal("receiver enabled before canary", e)
		}
		current, e := recovered.CurrentAuthority(context.Background())
		if e != nil || current.InstanceID != descriptor.Binding.NewInstanceID || current.RecoveryEpoch != descriptor.Binding.NextRecoveryEpoch {
			t.Fatal("receiver authority", current, e)
		}
	})
}

type transferSigner struct{ key ed25519.PrivateKey }

func (s transferSigner) Sign(_ context.Context, b []byte) ([]byte, error) {
	return ed25519.Sign(s.key, b), nil
}
func (transferSigner) KeyID() string                  { return "transfer-signer" }
func (s transferSigner) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

type transferCredential struct{ key []byte }

func (c transferCredential) Resolve(context.Context, credentialref.StepBinding) (*credentialref.Value, error) {
	return credentialref.NewValue(append([]byte{}, c.key...))
}
func (transferCredential) GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error) {
	return store.GateAppliedProfile{ProfileID: "transfer-profile", Capabilities: []string{"transfer-ssh"}, StateRevision: 1}, nil
}

type transferSecretGate struct{ hosts *store.HostActionRepository }

func (g transferSecretGate) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	if p.HostAction == nil || p.HostAction.HostID != op.TargetID {
		return fmt.Errorf("wrong target")
	}
	r := p.HostAction
	return g.hosts.VerifyHostActionConsole(ctx, r.HostID, generated.HostActionCredentialConfirmation{Method: r.ConsoleConfirmation.Method, TargetDigest: r.TargetDigest, HostIdentityDigest: r.ConsoleConfirmation.HostIdentityDigest, TargetRevision: r.TargetRevision}, p.Binding.RecoveryEpoch)
}

type transferTarget struct {
	hosts *store.HostActionRepository
	port  int
}

func (s transferTarget) Resolve(ctx context.Context, b generated.HostActionBundle) (transport.Target, error) {
	x, e := s.hosts.ExecutionForBundle(ctx, b)
	if e != nil {
		return transport.Target{}, e
	}
	r := x.Draft.Request
	return transport.Target{HostID: r.HostID, HostIdentityDigest: r.ConsoleConfirmation.HostIdentityDigest, Address: "127.0.0.1", Port: uint16(s.port), HostKey: x.Target.HostKey, User: x.Target.User, AutomationPrincipalID: r.AutomationPrincipalID, CallerUID: uint32(r.CallerUID), Revision: x.Target.Revision}, nil
}

// Only actual physical-host identity and installed role observation are replaced.
type transferPhysicalBoundary struct {
	expected generated.ControlRecoveryReceiveInput
}

func (p transferPhysicalBoundary) VerifyCandidateTransferDestination(_ context.Context, d generated.ControlRecoveryReceiveInput) error {
	if hostaction.Digest(d) != hostaction.Digest(p.expected) {
		return fmt.Errorf("physical destination mismatch")
	}
	return nil
}

type transferReceiveHandler struct {
	receiver recovery.CandidateTransferReceiver
}

func (h transferReceiveHandler) Lookup(id, version string) (hostaction.Handler, bool) {
	return h, id == hostaction.RecoveryReceiveAction && version == "1.0.0"
}
func (transferReceiveHandler) Execute(context.Context, generated.HostActionBundle) (generated.HostActionResult, error) {
	return generated.HostActionResult{}, fmt.Errorf("payload required")
}
func (transferReceiveHandler) Verify(_ context.Context, b generated.HostActionBundle, r generated.HostActionResult) error {
	if r.Status != "succeeded" || r.BundleDigest != hostaction.Digest(b) {
		return fmt.Errorf("receive failed")
	}
	return nil
}
func (h transferReceiveHandler) ExecuteRecoveryPayload(ctx context.Context, b generated.HostActionBundle, wire io.Reader) (generated.HostActionResult, error) {
	var d generated.ControlRecoveryReceiveInput
	if e := json.Unmarshal([]byte(b.ActionInput), &d); e != nil {
		return generated.HostActionResult{}, e
	}
	var candidate, journal bytes.Buffer
	if e := hostaction.CopyRecoveryPayload(ctx, &candidate, wire, d.CandidateBytes, hostaction.MaximumRecoveryCandidateBytes, d.CandidateBytesDigest); e != nil {
		return generated.HostActionResult{}, e
	}
	if e := hostaction.CopyRecoveryPayload(ctx, &journal, wire, d.JournalBytes, hostaction.MaximumRecoveryJournalBytes, d.JournalDigest); e != nil {
		return generated.HostActionResult{}, e
	}
	var extra [1]byte
	if n, e := wire.Read(extra[:]); n != 0 || e != io.EOF {
		return generated.HostActionResult{}, fmt.Errorf("trailing transfer bytes")
	}
	if _, e := h.receiver.Receive(ctx, d, bytes.NewReader(candidate.Bytes()), bytes.NewReader(journal.Bytes())); e != nil {
		return generated.HostActionResult{}, e
	}
	r := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: hostaction.Digest(b), Status: "succeeded", Changed: true, EffectObserved: true, Reason: "recovery-required"}
	r.ResultDigest = hostaction.ResultDigest(r)
	return r, nil
}
func transferSSHPeer(t *testing.T, key ssh.Signer, signer transferSigner, d generated.ControlRecoveryReceiveInput, receiver recovery.CandidateTransferReceiver) int {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	dir := t.TempDir()
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	receipts, e := hostaction.OpenReceipts(dir, uint32(os.Geteuid()))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { receipts.Close() })
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, p ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(p.Marshal(), key.PublicKey().Marshal()) {
				return nil, fmt.Errorf("wrong key")
			}
			return nil, nil
		}}
		cfg.AddHostKey(key)
		server, channels, requests, e := ssh.NewServerConn(conn, cfg)
		if e != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for channel := range channels {
			if channel.ChannelType() != "session" {
				channel.Reject(ssh.UnknownChannelType, "denied")
				continue
			}
			ch, requests, e := channel.Accept()
			if e != nil {
				return
			}
			defer ch.Close()
			for req := range requests {
				var command struct{ Command string }
				if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil || command.Command != "/usr/bin/sudo -n -- /usr/local/bin/vsk-labs host-action-once" {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				policy := hostaction.Policy{HostID: d.Replacement.NewHostID, HostIdentityDigest: d.Replacement.NewIdentityDigest, CallerUID: uint32(d.ServiceUID), KeyID: signer.KeyID(), PublicKey: signer.PublicKey()}
				e = hostaction.RunOnce(context.Background(), ch, ch, policy, receipts, transferReceiveHandler{receiver}, time.Now, rand.Reader)
				code := uint32(0)
				if e != nil {
					code = 1
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
				return
			}
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}
