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
	collector "github.com/vegastack/vegastack-labs/internal/adapter/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Real built executable, protected local socket, SQLite, engine and synthetic SSH peer.
func TestNodeCLIDiscoveryAdoptionInspection(t *testing.T) { runNodeCLIScenario(t) }
func runNodeCLIScenario(t *testing.T) {
	binary := os.Getenv("VSK_NODE_CLI_BINARY")
	if binary == "" {
		t.Skip("requires an explicitly built current Linux executable via VSK_NODE_CLI_BINARY")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute executable path required")
	}
	principal := identity.Principal{ID: "operator-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	ctx := identity.WithVerifiedPrincipal(context.Background(), principal)
	captureStart := time.Now().UTC().Truncate(time.Second)
	fixtureNow := captureStart
	clock := func() time.Time { return fixtureNow }
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.db")
	authority, err := store.Open(ctx, store.Config{DatabasePath: path, Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "test", BuildVersion: "test", Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO effective_authorization_principals VALUES('operator-a','human','active',1,'now','now')`)
	grant := func(capability, kind, id, action string) {
		t.Helper()
		exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?, ?,NULL,1,'active','now','now')`, "grant-"+hostdiscovery.Digest([]string{capability, id})[7:25], action, capability, kind, id)
	}
	for _, c := range []string{"host.discovery.collect", "host.discovery.read"} {
		grant(c, "host-discovery-target", "candidate-a", "read")
	}
	grant("host.adoption.prepare", "host-discovery-target", "candidate-a", "author")
	grant("host.read", "host", "synthetic-host", "read")
	exec(`INSERT INTO read_principals VALUES('operator-a','active',1,'now','now')`)
	exec(`INSERT INTO read_grants VALUES('operator-a','host.discovery.read','host-discovery-target','candidate-a',1,'active','now','now')`)
	repo := store.NewHostAdoptionRepository(authority)
	revisions := store.NewPlanRepository(authority)
	declarations, err := change.NewService(store.NewDeclarationRepository(authority), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(revisions)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := planengine.NewService(planengine.Config{HostAdoptions: repo, Repository: revisions, Observations: observations, Clock: time.Now, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	var requestNumber atomic.Int64
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) {
		return fmt.Sprintf("request-discovery-%d", requestNumber.Add(1)), nil
	})
	app, err := api.NewApplication(api.Config{Authority: authority, Authorizer: store.NewReadAuthorizer(authority), Reads: store.NewReadRepository(authority), Results: factory})
	if err != nil {
		t.Fatal(err)
	}
	policy := store.NewEffectiveAuthorizationRepository(authority)
	if err := api.RegisterDeclarationPlanOperations(app, api.DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(policy), Recorder: policy, Clock: time.Now}}); err != nil {
		t.Fatal(err)
	}
	target, private, calls := discoveryAcceptancePeer(t, "13.6")
	target.ProfileID = "debian-13-amd64"
	dr := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "fixture-target"}
	raw, _ := json.Marshal(dr)
	digest := hostdiscovery.Digest(dr)
	exec(`INSERT INTO host_discovery_drafts VALUES('fixture-target','candidate-a',1,0,'activate',?,?,'operator-a',0,0)`, digest, raw)
	hash := hostdiscovery.Digest("fixture")
	exec(`INSERT INTO declaration_revisions VALUES('fixture-declaration',1,'host.discovery-target',0,0,?,?,'draft',?,'now','operator-a','session-a')`, hash, hash, []byte(`{}`))
	exec(`INSERT INTO immutable_plans VALUES('fixture-plan',?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-01-01T00:00:00Z','2026-12-01T00:00:00Z')`, hash, hash, hash, hash, []byte(`{}`), "fixture", hash)
	exec(`INSERT INTO host_discovery_targets VALUES('candidate-a',1,'fixture-target','active','fixture-plan',0)`)
	exec(`UPDATE system_meta SET state_revision=1 WHERE id=1`)
	discoveryRepo := store.NewHostDiscoveryRepository(authority)
	registry := adapter.NewRegistry()
	if err := registry.RegisterCredentialResolver(adapter.CredentialCapabilityScope{ResolverID: "fixture-discovery", ConsumerID: hostdiscovery.Consumer, ProfileID: target.ProfileID, CapabilityID: "credential.discovery.read", Enabled: true}, &discoveryAcceptanceResolver{key: private}); err != nil {
		t.Fatal(err)
	}
	activated := time.Now().UTC().Format(time.RFC3339)
	borrower := hostDiscoveryCredentials{targets: discoveryRepo, references: recoveryReferenceStub{reference: generated.CredentialReference{ReferenceID: target.CredentialReferenceID, ConsumerID: hostdiscovery.Consumer, PurposeID: hostdiscovery.Purpose, TargetID: target.TargetID, ResolverID: "fixture-discovery", MaterialVersion: target.MaterialVersion, Status: "active", ActivatedAt: &activated, VerifiedConsumerIDs: []string{hostdiscovery.Consumer}}}, profiles: recoveryProfileStub{profile: store.GateAppliedProfile{ProfileID: target.ProfileID, Capabilities: []string{"credential.discovery.read"}}}, resolvers: registry}
	discovery := &hostdiscovery.Service{Repository: discoveryRepo, Collector: &collector.Collector{Borrower: borrower, Clock: clock}}
	if err := api.RegisterHostDiscoveryOperations(app, api.HostDiscoveryOperations{Service: discovery, Targets: discoveryRepo, Declarations: declarations, Results: factory}); err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterHostAdoptionOperations(app, api.HostAdoptionOperations{Hosts: repo, Declarations: declarations, Results: factory}); err != nil {
		t.Fatal(err)
	}
	acknowledger, err := acknowledgement.NewService(acknowledgement.Config{Repository: store.NewAcknowledgementRepository(authority), Plans: lifecycleAcceptancePlanReader{plans}, Authorizer: lifecycleAcceptanceAuthorizer{}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := runengine.NewEngine(runengine.Config{Repository: store.NewRunRepository(authority), Plans: plans, Admission: runengine.NewAdmissionGate(acknowledger, time.Now), Adapters: adapter.NewRegistry(), Core: runengine.CoreRouter{Adoption: &runengine.HostAdoptionEffect{Repository: repo, Approvals: store.NewAcknowledgementRepository(authority)}}, Clock: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterRunOperations(app, api.RunOperationConfig{Runs: engine, Plans: plans, Acknowledgements: acknowledger, Results: factory, Authorization: api.EffectiveAuthorizationConfig{Authorizer: authorization.NewEvaluator(policy), Recorder: policy, Clock: time.Now}}); err != nil {
		t.Fatal(err)
	}
	socket := phase4ConsoleSocketPath(t)
	profile := serverconfig.Profile{SocketPath: socket, InventoryExportRoot: directory, SocketOwnerUID: uint32(os.Getuid()), SocketMode: 0600, ShutdownGrace: 5 * time.Second, PrincipalBindings: []identity.Binding{{UID: uint32(os.Getuid()), PrincipalID: "operator-a"}}}
	service, err := New(Config{Profile: profile, Application: app, Results: factory, PlatformProbe: staticPlatformProbe{platform: testSupportedPlatform()}})
	if err != nil {
		t.Fatal(err)
	}
	serviceCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(serviceCtx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("unix", socket)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server socket not ready", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	configPath := filepath.Join(directory, "client.json")
	writeProtectedJSON(t, configPath, generated.ServerProfile{Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.3.0", SocketPath: socket, SocketOwnerUID: int64(os.Getuid()), SocketMode: "0600", ShutdownGraceSeconds: 5, InventoryExportRoot: directory, PrincipalBindings: []generated.LocalPrincipalBinding{{UID: int64(os.Getuid()), PrincipalID: "operator-a"}}, RemoteRead: generated.RemoteReadProfile{Enabled: false}})
	call := func(input any, human bool, args ...string) (generated.RunResult, string, int) {
		t.Helper()
		args = append(args, "--config", configPath)
		if input != nil {
			p := filepath.Join(directory, "input.json")
			writeProtectedJSON(t, p, input)
			args = append(args, "--file", p)
		}
		if !human {
			args = append(args, "--output", "json")
		}
		command := osexec.Command(binary, args...)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		code := 0
		if err != nil {
			if e, ok := err.(*osexec.ExitError); ok {
				code = e.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if stderr.Len() != 0 {
			t.Fatalf("unexpected stderr %s", stderr.String())
		}
		var envelope generated.RunResult
		if !human && json.Unmarshal(stdout.Bytes(), &envelope) != nil {
			t.Fatalf("invalid CLI JSON %s", stdout.String())
		}
		return envelope, stdout.String(), code
	}
	decode := func(envelope generated.RunResult, code int, out any) {
		t.Helper()
		if code != 0 {
			t.Fatalf("CLI failed: %+v", envelope.Errors)
		}
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			t.Fatal(err)
		}
	}
	scan := generated.HostDiscoveryRequest{Schema: generated.SchemaIDHostDiscoveryRequest, SchemaVersion: "1.0.0", TargetID: target.TargetID, TargetRevision: 1, ExpectedStateRevision: 1, IdempotencyKey: "cli-discover"}
	envelope, _, code := call(scan, false, "node", "discover")
	var discovered generated.HostDiscoverySubmission
	decode(envelope, code, &discovered)
	if calls.Load() != 10 || discovered.Observation.TargetID != target.TargetID {
		t.Fatalf("collector calls %d observation %+v", calls.Load(), discovered.Observation)
	}
	_, humanDiscovery, code := call(scan, true, "node", "discover")
	if code != 0 || !strings.Contains(humanDiscovery, discovered.Observation.ObservationID) || !strings.Contains(humanDiscovery, "hardening-unverified") {
		t.Fatal("discovery human/JSON mismatch", humanDiscovery)
	}
	obs := discovered.Observation
	req := generated.HostAdoptionRequest{Schema: generated.SchemaIDHostAdoptionRequest, SchemaVersion: "1.0.0", HostID: "synthetic-host", ObservationID: obs.ObservationID, ObservationDigest: obs.ContentDigest, IdempotencyKey: "cli-add", ExpectedStateRevision: obs.StateRevision, RecoveryEpoch: obs.RecoveryEpoch, Confirmation: generated.HostIdentityConfirmation{Schema: generated.SchemaIDHostIdentityConfirmation, SchemaVersion: "1.0.0", TargetRevision: 1, TargetDigest: obs.TargetDigest, IdentityClass: "physical", IdentityKind: "product-serial", IdentityDigest: hostadoption.IdentityDigest("product-serial", "synthetic-serial"), ConfirmedAt: clock().Format(time.RFC3339)}}
	grantDraft := func(r generated.HostAdoptionRequest) {
		t.Helper()
		id := "host-adoption-" + hostadoption.Digest(r)[7:39]
		grant("declaration.author", "declaration", id, "author")
	}
	grantDraft(req)
	for _, variant := range []string{"stale", "changed-target"} {
		bad := req
		bad.IdempotencyKey = "negative-" + variant
		if variant == "stale" {
			fixtureNow = fixtureNow.Add(time.Hour)
		}
		if variant == "changed-target" {
			bad.Confirmation.TargetDigest = hash
		}
		grantDraft(bad)
		r, _, c := call(bad, false, "node", "add")
		if c == 0 || len(r.Errors) != 1 {
			t.Fatalf("accepted %s", variant)
		}
		want := generated.ErrorCodePrerequisiteBlocked
		if r.Errors[0].Code != want {
			t.Fatalf("%s wrong reason: %+v", variant, r.Errors)
		}
		fixtureNow = captureStart
	}
	envelope, _, code = call(req, false, "node", "add")
	var draft generated.HostAdoptionSubmission
	decode(envelope, code, &draft)
	var hosts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM managed_hosts`).Scan(&hosts); err != nil || hosts != 0 {
		t.Fatal("add was not inert", err, hosts)
	}
	replay, _, replayCode := call(req, false, "node", "add")
	if replayCode == 0 || len(replay.Errors) != 1 || replay.Errors[0].Code != generated.ErrorCodeStateConflict {
		t.Fatalf("stale add replay accepted %+v", replay)
	}
	humanRequest := req
	humanRequest.IdempotencyKey = "human-add"
	currentRevision, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	humanRequest.ExpectedStateRevision = currentRevision.StateRevision
	grantDraft(humanRequest)
	_, humanDraft, code := call(humanRequest, true, "node", "add")
	humanDraftID := "host-adoption-" + hostadoption.Digest(humanRequest)[7:39]
	if code != 0 || !strings.Contains(humanDraft, humanDraftID) || !strings.Contains(humanDraft, "revision 1") {
		t.Fatal("human add mismatch", humanDraft)
	}
	applyDraft := func(draft generated.HostAdoptionSubmission) (generated.RunResult, int) {
		grant("declaration.read", "declaration", draft.DeclarationID+":1", "read")
		grant("plan.author", "declaration", draft.DeclarationID, "author")
		exec(`INSERT INTO read_grants VALUES('operator-a','declaration.read','declaration',?,1,'active','now','now')`, draft.DeclarationID+":1")
		envelope, _, code := call(nil, false, "plan", "--declaration-id", draft.DeclarationID, "--revision", "1")
		var presentation generated.PlanPresentation
		decode(envelope, code, &presentation)
		plan := presentation.Plan
		grant("plan.read", "plan", plan.PlanID, "read")
		exec(`INSERT INTO read_grants VALUES('operator-a','plan.read','plan',?,1,'active','now','now')`, plan.PlanID)
		for _, g := range []struct{ action, cap, kind string }{{"acknowledge", "plan.acknowledge", "plan-target"}, {"execute", "host.adopt", "execution-target"}} {
			exec(`INSERT INTO effective_authorization_grants VALUES(?,'operator-a','control-plane-admin',?,?,?,?,'human',1,'active','now','now')`, g.action+"-"+draft.DraftID, g.action, g.cap, g.kind, draft.DraftID)
		}
		human := identity.Principal{ID: "operator-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
		card, err := acknowledger.Request(ctx, acknowledgement.Scope{Human: human, AuthorityID: "fixture-authority", Nonce: "fixture-nonce-" + plan.PlanID}, plan.PlanID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = acknowledger.Decide(ctx, acknowledgement.Candidate{Human: human, AuthorityID: card.Request.AuthorityID, Action: acknowledgement.ActionApprove, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, Nonce: card.Nonce, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: mustAcceptanceTime(t, plan.ExpiresAt), DecidedAt: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		envelope, _, code = call(nil, false, "apply", "--plan-id", plan.PlanID)
		return envelope, code
	}
	envelope, code = applyDraft(draft)
	var applied generated.RunPresentation
	decode(envelope, code, &applied)
	if applied.Run.Status != "succeeded" {
		t.Fatalf("run failed %+v", applied)
	}
	envelope, _, code = call(nil, false, "node", "inspect", "--host-id", req.HostID)
	var host generated.ManagedHost
	decode(envelope, code, &host)
	_, humanHost, code := call(nil, true, "node", "inspect", "--host-id", req.HostID)
	if code != 0 || host.Status != "adopted-unadmitted" || !strings.Contains(humanHost, host.HostID) || !strings.Contains(humanHost, host.Status) {
		t.Fatal("inspect human/JSON mismatch", humanHost)
	}
	duplicate := req
	duplicate.HostID = "duplicate-host"
	duplicate.IdempotencyKey = "duplicate"
	revision, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	duplicate.ExpectedStateRevision = revision.StateRevision
	grantDraft(duplicate)
	envelope, _, code = call(duplicate, false, "node", "add")
	var duplicateDraft generated.HostAdoptionSubmission
	decode(envelope, code, &duplicateDraft)
	denied, code := applyDraft(duplicateDraft)
	if code == 0 || len(denied.Errors) != 1 || denied.Errors[0].Code != generated.ErrorCodeExecutionFailed {
		t.Fatalf("duplicate apply outcome %+v", denied)
	}
	var failed generated.RunPresentation
	if err := json.Unmarshal(denied.Data, &failed); err != nil {
		t.Fatal(err)
	}
	if failed.Run.Status != "failed" || failed.Run.Changed || len(failed.Run.Steps) != 1 || failed.Run.Steps[0].Status != "failed" || failed.Run.Steps[0].ProgressState != "not-started" {
		t.Fatalf("duplicate effect escaped atomic denial %+v", failed)
	}
	var originalID, originalIdentity string
	if err := db.QueryRow(`SELECT host_id,identity_digest FROM managed_hosts WHERE target_id=?`, target.TargetID).Scan(&originalID, &originalIdentity); err != nil || originalID != req.HostID || originalIdentity != duplicate.Confirmation.IdentityDigest {
		t.Fatal("duplicate identity/target changed", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM managed_hosts`).Scan(&hosts); err != nil || hosts != 1 {
		t.Fatal("duplicate registered", err, hosts)
	}
	// A newly activated synthetic target/key revision invalidates the old observation.
	replacement := dr
	replacement.Target.Revision = 2
	replacement.Target.Port++
	_, replacementPrivate, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	replacementSigner, keyErr := ssh.NewSignerFromKey(replacementPrivate)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	replacement.Target.HostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(replacementSigner.PublicKey())))
	replacement.ExpectedTargetRevision = 1
	replacement.IdempotencyKey = "replacement"
	replacementRaw, _ := json.Marshal(replacement)
	replacementDigest := hostdiscovery.Digest(replacement)
	exec(`INSERT INTO host_discovery_drafts VALUES('replacement-target','candidate-a',2,1,'activate',?,?,'operator-a',0,0)`, replacementDigest, replacementRaw)
	exec(`INSERT INTO host_discovery_targets VALUES('candidate-a',2,'replacement-target','active','fixture-plan',0)`)
	staleTarget := req
	staleTarget.HostID = "old-observation-host"
	staleTarget.IdempotencyKey = "old-observation"
	current, err := revisions.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	staleTarget.ExpectedStateRevision = current.StateRevision
	grantDraft(staleTarget)
	denied, _, code = call(staleTarget, false, "node", "add")
	if code == 0 || len(denied.Errors) != 1 || denied.Errors[0].Code != generated.ErrorCodePlanStale {
		t.Fatalf("changed target outcome %+v", denied)
	}
	if calls.Load() != 10 {
		t.Fatalf("add/inspect contacted host: %d", calls.Load())
	}
	for _, table := range []string{"gate_applied_evidence", "gate_applied_profiles", "credential_reference_versions"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("node flow changed authority", table, err, count)
		}
	}
	exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.adoption.prepare'`)
	denied, _, code = call(staleTarget, false, "node", "add")
	if code == 0 || len(denied.Errors) != 1 || denied.Errors[0].Code != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("revoked preparation outcome %+v", denied)
	}
	exec(`UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.read'`)
	denied, _, code = call(nil, false, "node", "inspect", "--host-id", req.HostID)
	if code == 0 || len(denied.Errors) != 1 || denied.Errors[0].Code != generated.ErrorCodeAuthorizationDenied {
		t.Fatal("revoked read succeeded")
	}
}
