//go:build linux

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// OS observations and external backup/fence custody are synthetic. Claim,
// freeze, Slack acknowledgement, snapshot and staged authority are actual.
type RecoveryTransferAcceptance struct {
	Results          *result.Factory
	Authority        *store.Store
	Gates            *store.GateRepository
	DB               *sql.DB
	Context          context.Context
	DatabasePath     string
	Clock            func() time.Time
	Descriptor       generated.ControlRecoveryReceiveInput
	App              *Application
	Declarations     *change.Service
	Plans            *planengine.Service
	Acknowledgements *acknowledgement.Service
}

func TestRecoveryTransferApprovedSourcePipeline(t *testing.T) {
	RunRecoveryTransferAcceptance(t, "", nil)
}

// RunRecoveryTransferAcceptance exposes only a test fixture to the external
// test package so it can compose the actual server without an import cycle.
func RunRecoveryTransferAcceptance(t *testing.T, sshHostKey string, use func(RecoveryTransferAcceptance)) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("cold transfer needs non-root service identity")
	}
	var source recovery.VerifiedSource
	var database string
	var input generated.RestoreRequest
	runReplacementPipeline(t, nil, nil, replacementControlTransferFixture{SSHHostKey: sshHostKey,
		BeforeFreeze: func(f roleAdmissionFixture, at *time.Time, q *generated.HostReplacementRequest) {
			var seq int
			var name string
			if e := f.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &database); e != nil {
				t.Fatal(e)
			}
			a, e := f.authority.CurrentAuthority(f.ctx)
			if e != nil {
				t.Fatal(e)
			}
			d := hostaction.Digest
			binding := generated.RestoreSourceBinding{Schema: generated.SchemaIDRestoreSourceBinding, SchemaVersion: "1.1.0", PointID: "transfer-point", PointDigest: d("point"), ManifestDigest: d("manifest"), VerificationDigest: d("verified"), SourceClass: "local", RepositoryGenerationID: "transfer-generation", KeyReferenceID: "transfer-key", DeclaredRPOSeconds: 3600, CreatedAt: at.Format(time.RFC3339), VerifiedAt: at.Format(time.RFC3339), RecoveryEpoch: a.RecoveryEpoch, DependencyDigests: []string{d("binary")}, RequiredDependencies: []generated.RestoreDependencyBinding{{DependencyID: "restic-binary", Kind: "binary", Digest: d("binary")}}, TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "24"}
			audit := recovery.AuditContinuity{IndependentCheckpointDigest: d("checkpoint"), DecisionDigest: d("audit-decision")}
			source = replacementTransferSnapshot(t, f.ctx, f.authority, database, binding, audit)
			q.RestorationClass = "control-database"
			q.Source = &generated.HostReplacementSourceReference{Schema: generated.SchemaIDHostReplacementSourceReference, SchemaVersion: "1.0.0", PointID: binding.PointID, ManifestDigest: binding.ManifestDigest, SourceBindingDigest: d(binding), CustodyReferenceID: "transfer-custody", CustodyBindingDigest: d("source-admission")}
			input = recoveryTransferRequest(binding, a.InstanceID, q.OldHostID, q.NewHostID, q.Source.CustodyReferenceID, q.Source.CustodyBindingDigest)
		},
		AfterFreeze: func(f roleAdmissionFixture, at *time.Time, q generated.HostReplacementRequest, role generated.LinuxRoleInput, app *Application, declarations *change.Service, planService *planengine.Service, ack *acknowledgement.Service) {
			clock := func() time.Time { return *at }
			rev, e := store.NewPlanRepository(f.authority).CurrentRevision(f.ctx)
			if e != nil {
				t.Fatal(e)
			}
			input.ExpectedStateRevision = rev.StateRevision
			guard := recovery.StoreReplacementContinuityGuard{Authority: f.authority, Replacements: store.NewHostReplacementRepository(f.authority)}
			input.ReplacementContinuity, e = guard.PrepareReplacementContinuity(f.ctx, input, source)
			if e != nil {
				t.Fatal("continuity", e)
			}
			input.CanaryBindingDigest, e = change.RestoreCanaryBindingDigest(input)
			if e != nil {
				t.Fatal(e)
			}
			plans := store.NewPlanRepository(f.authority)
			restores := store.NewRestoreRepository(f.authority)
			planner := recovery.StoreRestorePlanner{Declarations: store.NewDeclarationRepository(f.authority), Plans: plans, Restores: restores, Clock: clock}
			b, e := planner.CreateRestorePlan(f.ctx, input, source, recovery.FenceResult{Items: input.Fences, FenceSetDigest: input.FenceSetDigest}, source.Audit, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
			if e != nil {
				t.Fatal("restore plan", e)
			}
			p, e := plans.GetPlan(f.ctx, b.PlanID)
			if e != nil {
				t.Fatal(e)
			}
			for _, op := range p.Plan.Operations {
				f.seed.exec(`INSERT INTO effective_authorization_grants VALUES(?,'human-a','control-plane-admin','acknowledge','plan.acknowledge','plan-target',?,'human',1,'active','now','now')`, "transfer-ack-"+op.TargetID, op.TargetID)
			}
			*at = time.Now().UTC().Truncate(time.Second)
			card, e := ack.Request(f.ctx, acknowledgement.Scope{Human: identity.Principal{ID: "human-a", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}, AuthorityID: "fixture-authority", Nonce: "transfer-restore-nonce"}, p.Plan.PlanID)
			if e != nil {
				t.Fatal("restore approval", e)
			}
			approved := approveHostLifecycleViaSlack(t, ack, card)
			b.HumanAcknowledgementID = approved.AcknowledgementID
			expected := store.RevisionToken{StateRevision: p.Plan.Binding.StateRevision, RecoveryEpoch: b.PriorRecoveryEpoch}
			sessions := recovery.StoreRestoreSessions{Repository: restores}
			if e = sessions.CreateRestoreSession(f.ctx, b, expected); e != nil {
				t.Fatal(e)
			}
			if e = sessions.TransitionRestore(f.ctx, b, "planned", "fenced", b.FenceSetDigest, expected); e != nil {
				t.Fatal(e)
			}
			opener := func(ctx context.Context, path string) (*store.Store, error) {
				return store.Open(ctx, store.Config{DatabasePath: path, Mode: store.OpenExisting, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "1.0.0", BuildVersion: "build-a", Clock: clock})
			}
			bundles := recovery.StoreRecoveryBundleStore{Authority: f.authority, Open: opener, Plans: plans, Restores: restores}
			manager := recovery.CandidateManager{DatabasePath: database, Storage: recovery.LocalCandidateStorage{ExpectedUID: uint32(os.Geteuid())}, Authority: recovery.StoreCandidateAuthority{Open: opener}, Bundles: bundles}
			stager := recovery.StoreCandidateStager{Manager: manager, Repository: restores, Plans: plans}
			if e = sessions.TransitionRestore(f.ctx, b, "fenced", "restoring", b.CandidateDigest, expected); e != nil {
				t.Fatal(e)
			}
			receipt, e := stager.StageRestoreCandidate(f.ctx, b, source, recovery.FenceResult{FenceSetDigest: b.FenceSetDigest}, expected)
			if e != nil {
				t.Fatal("stage transfer source", e)
			}
			if e = sessions.TransitionRestore(f.ctx, b, "restoring", "verification-required", b.CandidateDigest, expected); e != nil {
				t.Fatal(e)
			}
			for _, id := range []string{q.OldHostID, q.NewHostID} {
				f.seed.exec(`INSERT INTO effective_authorization_grants VALUES(?,'human-a','control-plane-admin','author','host.action.prepare','host',?,NULL,1,'active','now','now')`, "transfer-prepare-"+id, id)
			}
			pending, found, err := restores.PendingPromotion(f.ctx)
			if err != nil || !found || hostaction.Digest(pending.Binding) != hostaction.Digest(b) {
				t.Fatalf("pending transfer mismatch found=%v error=%v binding=%s/%s", found, err, hostaction.Digest(pending.Binding), hostaction.Digest(b))
			}
			if _, err := store.NewHostReplacementRepository(f.authority).ResolveReplacementDestination(f.ctx, b); err != nil {
				t.Fatalf("current frozen destination: %v", err)
			}
			var observed []byte
			if err := f.db.QueryRow(`SELECT canonical_bytes FROM host_observations WHERE observation_id=?`, q.OSPreparation.ObservationID).Scan(&observed); err != nil {
				t.Fatal("transfer observation", err)
			}
			var measured generated.HostObservation
			if json.Unmarshal(observed, &measured) != nil {
				t.Fatal("transfer observation decode")
			}
			if len(measured.Facts) == 0 {
				t.Fatal("missing destination physical observation")
			}
			descriptor, e := store.NewHostActionRepository(f.authority).ResolveRecoveryReceivePreparation(f.ctx, b)
			if e != nil {
				t.Fatal("receive preparation", e)
			}
			transfer, e := recovery.OpenCandidateTransfer(f.ctx, database, uint32(os.Geteuid()), descriptor)
			if e != nil {
				t.Fatal("open transfer", e)
			}
			defer transfer.Close()
			if transfer.Descriptor.BundleDigest != receipt.BundleDigest || transfer.Descriptor.RoleInput.RoleBindingDigest != role.RoleBindingDigest || linuxrole.RoleBindingDigest(role) != role.RoleBindingDigest {
				t.Fatal("source descriptor lost exact role or candidate")
			}
			raw, e := json.Marshal(transfer.Descriptor)
			if e != nil || generated.ValidateContractJSON(generated.SchemaIDControlRecoveryReceiveInput, raw, generated.ContractExact) != nil {
				t.Fatal("rendered transfer contract", e)
			}
			if use != nil {
				use(RecoveryTransferAcceptance{Results: app.config.Results, Authority: f.authority, Gates: f.repo, DB: f.db, Context: f.ctx, DatabasePath: database, Clock: clock, Descriptor: transfer.Descriptor, App: app, Declarations: declarations, Plans: planService, Acknowledgements: ack})
			}
		},
	})
}

func recoveryTransferRequest(source generated.RestoreSourceBinding, prior, old, newHost, custody, admission string) generated.RestoreRequest {
	d := hostaction.Digest
	fence := generated.RestoreFenceItem{Schema: generated.SchemaIDRestoreFenceItem, SchemaVersion: "1.1.0", Boundary: "host-service", SubjectID: old, TargetID: "transfer-control", AdapterID: "adapter-a", FormerIdentityID: "former-identity", ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "recovery-policy", PolicyVersion: "1.0.0", ReleaseBuildID: "build-a", EvaluatorVersion: "1.0.0", RecoveryEpoch: source.RecoveryEpoch, RequiredEvidenceKinds: []string{"service-denied"}, Required: true, EvidenceIDs: []string{admission, d("fence-qualified")}, EvidenceDigest: d("fence"), Status: "required"}
	audit := generated.RestoreAuditDecision{Schema: generated.SchemaIDRestoreAuditDecision, SchemaVersion: "1.1.0", IndependentCheckpointDigest: d("checkpoint"), Strategy: "matched", DecisionDigest: d("audit-decision")}
	return generated.RestoreRequest{Schema: generated.SchemaIDRestoreRequest, SchemaVersion: "1.1.0", RecoveryEpoch: source.RecoveryEpoch, TargetDigest: d("transfer-target"), IdempotencyKey: "transfer-restore", Source: source, Fences: []generated.RestoreFenceItem{fence}, AuditDecision: audit, PointID: source.PointID, DependencyIDs: []string{"restic-binary"}, TargetIDs: []string{"transfer-control"}, PriorInstanceID: prior, NewInstanceID: "transferred-controller", PriorRecoveryEpoch: source.RecoveryEpoch, NextRecoveryEpoch: source.RecoveryEpoch + 1, FenceSetDigest: d("fence"), AuditDecisionDigest: audit.DecisionDigest, CandidateDigest: d("candidate"), FormerHostID: old, ReplacementHostID: newHost, RecoveryDraftID: custody, CiphertextFingerprint: d("ciphertext"), SourceAdmissionDigest: admission, FenceQualificationDigest: d("fence-qualified"), RecoveryRunID: "restore-run", RecoveryStepID: "restore-step", RecoveryLeaseID: "restore-lease", RecoveryChallengeID: "restore-challenge", RecoveryReceiptID: "restore-receipt", CanaryRunID: "canary-run", CanaryStepID: "canary-step", CanaryLeaseID: "canary-lease", CanaryChallengeID: "canary-challenge", CanaryReceiptID: "canary-receipt"}
}

// ApproveRecoveryTransferPlan retains the actual Slack decoding fixture for the
// external test package; it does not manufacture an acknowledgement record.
func ApproveRecoveryTransferPlan(t *testing.T, service *acknowledgement.Service, card acknowledgement.RequestCard) generated.Acknowledgement {
	return approveHostLifecycleViaSlack(t, service, card)
}
