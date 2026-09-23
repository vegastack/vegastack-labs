//go:build linux

package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/r2retention"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type acceptanceRules struct{ current r2retention.RuleSet }

type acceptanceFilesystem struct{}

func (acceptanceFilesystem) InspectParent(context.Context, string, uint32) (store.FileIdentity, error) {
	return store.FileIdentity{Device: 1, Inode: 1, Links: 1, Local: true, Mode: 0o700}, nil
}
func (acceptanceFilesystem) CreateDatabase(_ context.Context, path string, uid uint32) (store.FileIdentity, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return store.FileIdentity{}, err
	}
	if err := file.Close(); err != nil {
		return store.FileIdentity{}, err
	}
	return store.FileIdentity{Device: 1, Inode: 2, Links: 1, UID: uid, Local: true, Mode: 0o600}, nil
}
func (acceptanceFilesystem) InspectDatabase(context.Context, string, uint32) (store.FileIdentity, error) {
	return store.FileIdentity{Device: 1, Inode: 2, Links: 1, Local: true, Mode: 0o600}, nil
}
func (acceptanceFilesystem) AcquireWriterLock(context.Context, string, uint32) (io.Closer, error) {
	return io.NopCloser(strings.NewReader("")), nil
}
func (acceptanceFilesystem) SameFile(left, right store.FileIdentity) bool {
	return left.Device == right.Device && left.Inode == right.Inode
}
func (acceptanceFilesystem) SyncDatabase(_ context.Context, path string, _ store.FileIdentity) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = file.Sync()
	return errors.Join(err, file.Close())
}

func (c *acceptanceRules) ReadRules(context.Context, string) (r2retention.RuleSet, error) {
	return c.current, nil
}
func (c *acceptanceRules) PutRules(_ context.Context, _ string, rules r2retention.RuleSet) error {
	c.current = rules
	return nil
}

type acceptanceObjects struct{ values []r2retention.Object }

func (c *acceptanceObjects) ListExact(context.Context, string) ([]r2retention.Object, error) {
	return append([]r2retention.Object(nil), c.values...), nil
}
func (c *acceptanceObjects) DeleteExact(_ context.Context, key string) error {
	for i, value := range c.values {
		if value.Key == key {
			c.values = append(c.values[:i], c.values[i+1:]...)
			return nil
		}
	}
	return nil
}

type acceptanceVerifier struct {
	now                    time.Time
	ruleDigest             string
	offsiteInventoryDigest string
}

func (v acceptanceVerifier) VerifyOffsiteSurvivor(_ context.Context, pointID string) (backup.OffsiteSurvivorProof, error) {
	return backup.OffsiteSurvivorProof{PointID: pointID, GenerationID: "generation-good", RuleDigest: v.ruleDigest, InventoryDigest: v.offsiteInventoryDigest, FullReadDigest: "sha256:" + strings.Repeat("b", 64), RestoreDigest: "sha256:" + strings.Repeat("c", 64), FullReadAt: v.now, RestoredAt: v.now, ObservedAt: v.now, RecoveryEpoch: 0}, nil
}

type acceptanceProviders struct {
	rules    *acceptanceRules
	objects  *acceptanceObjects
	verifier backup.OffsiteSurvivorVerifier
}

func (p acceptanceProviders) Clients(context.Context, store.OffsiteRetirementIntent, adapter.ExactExecutionBinding, *credentialref.Value, *credentialref.Value, map[string]*credentialref.Value) (r2retention.RuleClient, r2retention.ObjectClient, backup.OffsiteSurvivorVerifier, error) {
	return p.rules, p.objects, p.verifier, nil
}

type acceptanceRetirementSource struct{ providers acceptanceProviders }

func (s acceptanceRetirementSource) Execution(_ context.Context, _ serverconfig.Profile, authority *store.Store) (runengine.OffsiteRetirementExecution, bool, error) {
	execution, err := backup.NewSQLRetirementExecution(authority, s.providers, func() time.Time { return s.providers.verifier.(acceptanceVerifier).now })
	return execution, err == nil, err
}

func TestProductionOffsiteRetirementSQLRunAcceptance(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	clock := now
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	authority, err := store.Open(ctx, store.Config{DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew, ExpectedUID: uint32(os.Geteuid()), ToolVersion: "1.0.0", BuildVersion: "test-build", Clock: func() time.Time { return clock }, Filesystem: acceptanceFilesystem{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	d := "sha256:" + strings.Repeat("a", 64)
	bundle, bundleBytes, bundleDigest := acceptanceG008Bundle(t, now, d)
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	repository := store.NewBackupRepository(authority)
	repositoryID := backupidentity.CriticalRepository
	enc, recovery := "enc-a", "recovery-a"
	policy := generated.BackupPolicy{Schema: generated.SchemaIDBackupPolicy, SchemaVersion: "1.2.0", PolicyID: "policy-a", OwnerID: "owner-a", SourceID: backupidentity.ControlDatabaseSource, SourceSelectors: []string{backupidentity.ControlDatabaseSelector}, ConsistencyHookID: "sqlite-online", RepositoryID: &repositoryID, RepositoryClass: "critical", ScheduleIntent: "daily", ExpectedBytes: 1024, ExpectedGrowthBytes: 1, MinimumFreeBytes: 1, EncryptionKeyReferenceID: &enc, RecoveryKeyReferenceID: &recovery, RetentionDays: 14, RestoreTargetID: "restore-a", Dependencies: []generated.BackupDependency{}, FunctionalTestRequired: true, FullPayloadIntervalHours: 24, FunctionalTestIntervalHours: 24, RecoveryEpoch: 0, Revision: 1}
	_, policySum, _ := stateexport.CanonicalJSON(policy)
	policyDigest := "sha256:" + hex.EncodeToString(policySum[:])
	if _, err := repository.CreateBackupPolicyDraft(ctx, generated.BackupPolicyDraftRequest{Schema: generated.SchemaIDBackupPolicyDraftRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 0, RecoveryEpoch: 0, TargetDigest: policyDigest, IdempotencyKey: "policy-a", Policy: policy}, attribution); err != nil {
		t.Fatal(err)
	}
	points := map[string]store.PendingRecoveryPoint{}
	for index, pointID := range []string{"point-old", "point-good"} {
		points[pointID] = seedAcceptancePoint(t, ctx, repository, policyDigest, pointID, index, now)
	}

	offsite := store.NewOffsiteRepository(authority)
	old := acceptanceGeneration("generation-old", "point-old", "key-old", points["point-old"], now)
	good := acceptanceGeneration("generation-good", "point-good", "key-good", points["point-good"], now)
	clock = now.Add(-15 * 24 * time.Hour)
	appendAcceptanceGeneration(t, ctx, offsite, old)
	clock = now
	appendAcceptanceGeneration(t, ctx, offsite, good)
	for index, generation := range []backup.PendingOffsiteGeneration{old, good} {
		proofID := "proof-" + generation.GenerationID
		proofDigest := d
		if index == 0 {
			proofDigest = "sha256:" + strings.Repeat("8", 64)
		}
		if err := offsite.AppendProof(ctx, store.OffsiteProofRecord{ProofID: proofID, ProofDigest: proofDigest, GenerationID: generation.GenerationID, Status: backup.OffsiteStatusVerified, ProofClass: backup.OffsiteProofQualified, CanonicalJSON: []byte(`{}`), FullReadAt: now.Add(-time.Minute), ObservedAt: now.Add(-time.Minute), RecoveryEpoch: 0}); err != nil {
			t.Fatal(err)
		}
	}
	if err := offsite.AppendLastGood(ctx, "proof-generation-good", d, good.GenerationID, 1, 1, 0); err != nil {
		t.Fatal(err)
	}

	var allRules []r2retention.Rule
	for _, generation := range []backup.PendingOffsiteGeneration{old, good} {
		for _, rule := range generation.ProtectedRules {
			allRules = append(allRules, r2retention.Rule{RuleID: rule.RuleID, Prefix: rule.Prefix})
		}
	}
	selection := backup.RetirementSelection{Targets: []backup.RetirementCandidate{{PointID: old.SourcePointID}}, Survivors: []backup.RetirementCandidate{{PointID: good.SourcePointID}}, RecoveryEpoch: 0}
	catalog := backup.OffsiteRetirementCatalog{Generations: []backup.PendingOffsiteGeneration{good, old}, GenerationCreatedAt: map[string]time.Time{old.GenerationID: now.Add(-15 * 24 * time.Hour), good.GenerationID: now}, VerifiedPointIDs: []string{old.SourcePointID, good.SourcePointID}, LastGoodPointIDs: []string{good.SourcePointID}, BucketID: "bucket-a", CatalogDigest: d, G008BundleDigest: bundleDigest, QualificationDigest: d, PutCutoffDigest: d, MultipartCutoffDigest: d, ExclusiveAdminDigest: d, RuleCount: len(allRules), RuleLimit: 1000, TotalBytes: 100, AvailableBytes: 80, ObservedAt: now}
	for _, rule := range allRules {
		catalog.CurrentRules = append(catalog.CurrentRules, backup.RetentionRuleRef{RuleID: rule.RuleID, Prefix: rule.Prefix})
	}
	catalog.RuleSetDigest = r2retention.DigestRuleSet(r2retention.RuleSet{Rules: allRules})
	candidate, err := backup.SelectOffsiteRetirement(catalog, selection, now)
	if err != nil {
		t.Fatal(err)
	}

	operationID := "retire-offsite-a"
	bindings := []credentialref.StepBinding{
		{OperationID: operationID, AdapterID: "r2.retention", TargetID: candidate.GenerationID, ReferenceID: "lock-admin", ConsumerID: "r2.retention", PurposeID: "lock-admin", MaterialVersion: "v1", ResolverID: "native-systemd", StateRevision: 4, RecoveryEpoch: 0},
		{OperationID: operationID, AdapterID: "r2.retention", TargetID: candidate.GenerationID, ReferenceID: "retention", ConsumerID: "r2.retention", PurposeID: "retention", MaterialVersion: "v1", ResolverID: "native-systemd", StateRevision: 4, RecoveryEpoch: 0},
		{OperationID: operationID, AdapterID: "r2.retention", TargetID: candidate.GenerationID, ReferenceID: "key-good", ConsumerID: "r2.retention", PurposeID: "repository-key", MaterialVersion: "v1", ResolverID: "native-systemd", StateRevision: 4, RecoveryEpoch: 0},
	}
	credentialDigest := credentialref.OperationManifestDigest(bindings, operationID)
	intent := acceptanceIntent(candidate, credentialDigest)
	intent.IntentDigest, _, err = store.OffsiteRetirementIntentDigests(intent)
	if err != nil {
		t.Fatal(err)
	}
	plan := commitAcceptancePlan(t, ctx, authority, intent, bindings, operationID, attribution, now)
	intent.PlanID, intent.PlanDigest = plan.PlanID, plan.PlanDigest
	if _, err := store.NewOffsiteRetirementRepository(authority).StageOffsiteRetirement(ctx, intent); err != nil {
		t.Fatal(err)
	}
	seedAcceptanceAuthority(t, filepath.Join(directory, "control.db"), plan, intent, bundle, bundleBytes, bundleDigest, attribution, now)

	providerRules := &acceptanceRules{current: r2retention.RuleSet{Rules: append([]r2retention.Rule(nil), allRules...)}}
	providerObjects := &acceptanceObjects{}
	for _, object := range old.Objects {
		providerObjects.values = append(providerObjects.values, r2retention.Object{Key: object.Key, Digest: object.Digest, Bytes: object.Bytes})
	}
	source := acceptanceRetirementSource{providers: acceptanceProviders{rules: providerRules, objects: providerObjects, verifier: acceptanceVerifier{now: now, ruleDigest: good.RuleDigest, offsiteInventoryDigest: good.OffsiteInventoryDigest}}}
	effectAdapter, err := NewProductionOffsiteRetirementEffectFactory(source)(ctx, serverconfig.Profile{OffsiteBackup: &serverconfig.OffsiteBackup{}}, authority)
	if err != nil {
		t.Fatal(err)
	}
	effect := effectAdapter.(*runengine.OffsiteRetirementEffect)
	values := make([]*credentialref.Value, len(bindings))
	op := adapter.Operation{OperationID: operationID, OperationType: "backup.retire.offsite", AdapterID: "r2.retention", ExecutorID: "executor-central", TargetID: candidate.GenerationID, InputDigest: credentialDigest, ArtifactDigest: intent.IntentDigest, SecretReferences: make([]adapter.SecretReference, len(bindings))}
	for i, binding := range bindings {
		values[i], _ = credentialref.NewValue([]byte("secret-" + binding.ReferenceID))
		defer values[i].Close()
		op.SecretReferences[i] = adapter.SecretReference{ID: binding.ReferenceID, Consumer: binding.ConsumerID}
	}
	binding := adapter.ExactExecutionBinding{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: "run-a", StepID: "step-a", LeaseID: "lease-a", StateRevision: 4, RecoveryEpoch: 0, MaximumExpiresAt: now.Add(20 * time.Minute).Format(time.RFC3339), ContractExtensions: plan.Extensions}
	result, err := effect.ExecuteBoundWithCredentials(ctx, op, binding, values)
	if err != nil || !result.EffectObserved || result.ResultDigest == "" {
		t.Fatalf("effect=%+v err=%v", result, err)
	}
	verified, err := effect.Verify(ctx, op, result)
	if err != nil || !verified.Verified || len(providerObjects.values) != 0 || len(providerRules.current.Rules) != 5 {
		t.Fatalf("verification=%+v objects=%d rules=%d err=%v", verified, len(providerObjects.values), len(providerRules.current.Rules), err)
	}
}

// seedAcceptanceAuthority supplies the already-qualified live G-008 proof and
// human-owned run that precede retirement. The retirement lease, provider
// journal, survivor proofs, and settlement remain production-created by the
// execution under test; none of those records are synthesized here.
func seedAcceptanceAuthority(t *testing.T, databasePath string, plan generated.Plan, intent store.OffsiteRetirementIntent, bundle generated.GateEvidenceBundle, bundleBytes []byte, bundleDigest string, attribution audit.Attribution, now time.Time) {
	t.Helper()
	database, err := sql.Open("sqlite3", "file:"+databasePath+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	d := "sha256:" + strings.Repeat("a", 64)
	evidence := generated.GateEvidence{Schema: generated.SchemaIDGateEvidence, SchemaVersion: "1.1.0", EvidenceID: "owner-proof", GateID: "G-008", SubjectID: intent.BucketID, DefinitionVersion: "1.0.0", EvaluatorVersion: "1.0.0", ReleaseBuildID: "test-build", ToolVersion: "1.0.0", ProfileID: "vegastack-labs", ProfileVersion: "1.0.0", PolicyID: "policy-a", PolicyVersion: "1.0.0", DeclarationID: "gate-declaration", DeclarationRevision: 1, StateRevision: intent.StateRevision, SourceKind: "local", ProofClass: "live", CollectorID: bundle.CollectorID, HumanID: attribution.AuthenticatedPrincipalID, ArtifactDigest: d, BundleDigest: bundleDigest, ObservedAt: bundle.ObservedAt, AppliedAt: now.Add(-30 * time.Second).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), RecoveryEpoch: 0, Status: "applied"}
	evidenceBytes, err := json.Marshal(evidence)
	contractErr := generated.ValidateContractJSON(generated.SchemaIDGateEvidence, evidenceBytes, generated.ContractExact)
	if err != nil || contractErr != nil {
		t.Fatalf("gate evidence contract: marshal=%v validation=%v body=%s", err, contractErr, evidenceBytes)
	}
	ackID := "ack-retirement-a"
	ackRequest := generated.AcknowledgementRequest{Schema: generated.SchemaIDAcknowledgementRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, HumanID: attribution.AuthenticatedPrincipalID, AuthorityID: "infra-admin", NonceDigest: "sha256:" + strings.Repeat("b", 64), StateRevision: plan.Binding.StateRevision, RecoveryEpoch: 0, ExpiresAt: plan.ExpiresAt, Extensions: []generated.ContractExtension{}}
	ackProof := generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, HumanID: attribution.AuthenticatedPrincipalID, AuthorityID: "infra-admin", NonceDigest: ackRequest.NonceDigest, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: 0, ExpiresAt: plan.ExpiresAt, AcknowledgementID: ackID, ProofDigest: "sha256:" + strings.Repeat("c", 64), Status: "approved", ReceivedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	requestBytes, _ := json.Marshal(ackRequest)
	proofBytes, _ := json.Marshal(ackProof)
	ackPtr := ackID
	run := generated.Run{Schema: generated.SchemaIDRun, SchemaVersion: "1.0.0", RunID: "run-a", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AuthorizationDecisionID: "decision-a", AcknowledgementID: &ackPtr, PolicyVersion: plan.Binding.PolicyVersion, ExecutorMode: "central", ExecutorID: "executor-central", ExecutorBindingDigest: d, Status: "running", Steps: []generated.RunStep{{Sequence: 1, OperationID: plan.Operations[0].OperationID, OperationType: plan.Operations[0].OperationType, AdapterID: plan.Operations[0].AdapterID, ExecutorID: plan.Operations[0].ExecutorID, TargetID: plan.Operations[0].TargetID, InputDigest: plan.Operations[0].InputDigest, ArtifactDigest: plan.Operations[0].ArtifactDigest, Idempotent: false, StepID: "step-a", Status: "running", EffectState: "intent-recorded"}}, CancellationRequested: false, RollbackStatus: "not-requested", VerificationStatus: "pending", Changed: false, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: 0, CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	runBytes, _ := json.Marshal(run)
	lease := generated.ExecutorLease{Schema: generated.SchemaIDExecutorLease, SchemaVersion: "1.0.0", LeaseID: "lease-a", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: run.RunID, StepID: "step-a", OperationID: plan.Operations[0].OperationID, ExecutorID: "executor-central", AdapterID: "r2.retention", TargetID: intent.GenerationID, ArtifactDigest: intent.IntentDigest, BindingDigest: d, NonceDigest: "sha256:" + strings.Repeat("d", 64), RecoveryEpoch: 0, ClaimedAt: now.Format(time.RFC3339), RenewAfter: now.Add(5 * time.Minute).Format(time.RFC3339), LeaseExpiresAt: now.Add(20 * time.Minute).Format(time.RFC3339), MaximumExpiresAt: now.Add(20 * time.Minute).Format(time.RFC3339), Status: "active", Extensions: []generated.ContractExtension{}}
	leaseBytes, _ := json.Marshal(lease)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO gate_evidence_drafts(draft_id,evidence_id,gate_id,subject_id,definition_version,evaluator_version,source_kind,proof_class,artifact_digest,bundle_digest,bundle_bytes,observed_at,state_revision,recovery_epoch,human_id,created_at) VALUES('gate-draft','owner-proof','G-008',?,'1.0.0','1.0.0','local','live',?,?,?,?,4,0,?,?)`, []any{intent.BucketID, d, bundleDigest, bundleBytes, bundle.ObservedAt, attribution.AuthenticatedPrincipalID, now.Format(time.RFC3339)}},
		{`INSERT INTO gate_applied_evidence(evidence_id,draft_id,gate_id,subject_id,status,source_kind,proof_class,bundle_digest,canonical_bytes,state_revision,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,applied_at) VALUES('owner-proof','gate-draft','G-008',?,'applied','local','live',?,?,4,0,'gate-declaration',1,'gate-plan',?,'gate-run','gate-step','gate-lease',?)`, []any{intent.BucketID, bundleDigest, evidenceBytes, d, now.Format(time.RFC3339)}},
		{`INSERT INTO gate_applied_profiles(binding_id,profile_id,profile_version,policy_id,policy_version,capabilities_bytes,state_revision,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,applied_at) VALUES('profile-binding','vegastack-labs','1.0.0','policy-a','1.0.0',?,4,0,'gate-declaration',1,'gate-plan',?,'gate-run','gate-step','gate-lease',?,?)`, []any{[]byte(`[]`), d, attribution.AuthenticatedPrincipalID, now.Format(time.RFC3339)}},
		{`INSERT INTO acknowledgement_requests(acknowledgement_id,plan_id,plan_digest,target_digest,reason_digest,human_id,authority_id,nonce_digest,state_revision,recovery_epoch,expires_at,status,request_bytes,pending_bytes,created_at,decided_at,consumed_at) VALUES(?,?,?,?,?,?,?,?,?,0,?,'approved',?,?,?,?,?)`, []any{ackID, plan.PlanID, plan.PlanDigest, plan.Binding.TargetDigest, plan.Binding.ReasonDigest, attribution.AuthenticatedPrincipalID, "infra-admin", ackRequest.NonceDigest, plan.Binding.StateRevision, plan.ExpiresAt, requestBytes, proofBytes, now.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339)}},
		{`INSERT INTO acknowledgement_proofs(acknowledgement_id,proof_digest,status,canonical_bytes,received_at) VALUES(?,?,'approved',?,?)`, []any{ackID, ackProof.ProofDigest, proofBytes, ackProof.ReceivedAt}},
		{`INSERT INTO plan_runs(run_id,plan_id,plan_digest,authorization_decision_id,acknowledgement_id,policy_version,executor_mode,executor_id,executor_binding_digest,status,cancellation_requested,rollback_status,verification_status,changed,state_revision,recovery_epoch,submit_key_digest,request_digest,canonical_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?,'central','executor-central',?,'running',0,'not-requested','pending',0,?,0,?,?,?,?,?)`, []any{run.RunID, plan.PlanID, plan.PlanDigest, run.AuthorizationDecisionID, ackID, run.PolicyVersion, d, run.StateRevision, "sha256:" + strings.Repeat("e", 64), "sha256:" + strings.Repeat("f", 64), runBytes, run.CreatedAt, run.UpdatedAt}},
		{`INSERT INTO plan_run_steps(step_id,run_id,sequence,operation_id,operation_type,adapter_id,executor_id,target_id,input_digest,artifact_digest,idempotent,status,effect_state,active_lease_id,started_at) VALUES('step-a','run-a',1,?,'backup.retire.offsite','r2.retention','executor-central',?,?,?,0,'running','intent-recorded','lease-a',?)`, []any{plan.Operations[0].OperationID, intent.GenerationID, intent.CredentialBindingDigest, intent.IntentDigest, now.Format(time.RFC3339)}},
		{`INSERT INTO target_execution_leases(lease_id,run_id,step_id,target_id,binding_digest,nonce_digest,recovery_epoch,claimed_at,renew_after,expires_at,maximum_expires_at,status,canonical_bytes) VALUES('lease-a','run-a','step-a',?,?,?,?,?,?,?,?,'active',?)`, []any{intent.GenerationID, lease.BindingDigest, lease.NonceDigest, 0, lease.ClaimedAt, lease.RenewAfter, lease.LeaseExpiresAt, lease.MaximumExpiresAt, leaseBytes}},
	}
	for index, statement := range statements {
		if _, err := database.ExecContext(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed authority statement %d: %v", index, err)
		}
	}
}

func acceptanceG008Bundle(t *testing.T, now time.Time, digest string) (generated.GateEvidenceBundle, []byte, string) {
	t.Helper()
	bundle := generated.GateEvidenceBundle{Schema: generated.SchemaIDGateEvidenceBundle, SchemaVersion: "1.1.0", Facts: []generated.GateEvidenceFact{{Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "r2-offsite-qualification", ValueDigest: digest}, {Schema: generated.SchemaIDGateEvidenceFact, SchemaVersion: "1.1.0", FactID: "r2-exclusive-retention-admin", ValueDigest: digest}}, Checks: []generated.GateEvidenceCheck{{Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: "r2-expired-put-denied", VerifierVersion: "1.0.0", Result: "passed", ResultDigest: digest}, {Schema: generated.SchemaIDGateEvidenceCheck, SchemaVersion: "1.1.0", CheckID: "r2-expired-multipart-completion-denied", VerifierVersion: "1.0.0", Result: "passed", ResultDigest: digest}}, Attachments: []generated.GateEvidenceAttachment{}, CollectorID: "collector-a", ObservedAt: now.Add(-time.Minute).Format(time.RFC3339)}
	raw, err := json.Marshal(bundle)
	contractErr := generated.ValidateContractJSON(generated.SchemaIDGateEvidenceBundle, raw, generated.ContractExact)
	if err != nil || contractErr != nil {
		t.Fatalf("gate bundle contract: marshal=%v validation=%v", err, contractErr)
	}
	sum := sha256.Sum256(raw)
	return bundle, raw, "sha256:" + hex.EncodeToString(sum[:])
}

func seedAcceptancePoint(t *testing.T, ctx context.Context, repository *store.BackupRepository, policyDigest, pointID string, index int, now time.Time) store.PendingRecoveryPoint {
	t.Helper()
	t.Logf("seed point %s", pointID)
	leaseID, jobID := "writer-"+pointID, "job-"+pointID
	if err := repository.AcquireBackupWriterLease(ctx, store.BackupWriterLeaseRequest{LeaseID: leaseID, JobID: jobID, PolicyID: "policy-a", PolicyDigest: policyDigest, PlanID: "backup-plan", PlanDigest: "sha256:" + strings.Repeat("9", 64), RunID: "backup-run-" + pointID, StepID: "backup-step", RepositoryID: backupidentity.CriticalRepository, RepositoryClass: "critical", TargetID: "control-database", SourceRevision: 1, RecoveryEpoch: 0, MaximumExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatalf("acquire writer: %v", err)
	}
	snapshotID := strings.Repeat(string(rune('1'+index)), 64)
	objects := []backup.ExpectedObject{{Type: "config", Name: "config", Bytes: 1, Digest: "sha256:" + strings.Repeat("1", 64)}, {Type: "keys", Name: strings.Repeat("a", 64), Bytes: 1, Digest: "sha256:" + strings.Repeat("2", 64)}, {Type: "snapshots", Name: snapshotID, Bytes: 1, Digest: "sha256:" + strings.Repeat("3", 64)}}
	manifest := backup.CreationManifest{Schema: backup.CreationManifestSchema, SchemaVersion: backup.CreationManifestVersion, PolicyID: "policy-a", PolicyDigest: policyDigest, PointID: pointID, RunID: "backup-run-" + pointID, StepID: "backup-step", RepositoryID: backupidentity.CriticalRepository, RepositoryClass: "critical", SourceID: backupidentity.ControlDatabaseSource, SourceSelectors: []string{backupidentity.ControlDatabaseSelector}, SourceRevision: 1, RecoveryEpoch: 0, DatabaseSchemaVersion: 1, CatalogDigest: "sha256:" + strings.Repeat("4", 64), ContentDigest: "sha256:" + strings.Repeat("5", 64), ConsistencyHookID: "sqlite-online", ConsistencySuccess: true, SnapshotID: snapshotID, SnapshotCount: 1, ExpectedObjectCount: int64(len(objects)), ExpectedObjectBytes: 3, InventoryDigest: backup.ExpectedInventoryDigest(objects), ExpectedObjects: objects, DependencyInventoryDigest: backup.ExpectedDependencyInventoryDigest(nil), ExpectedDependencies: []backup.ExpectedDependency{}, KeyReferenceID: "enc-a", ResticDigest: "sha256:" + strings.Repeat("6", 64), PlatformDigest: "sha256:" + strings.Repeat("7", 64), StartedAt: now.Add(-time.Minute).Format(time.RFC3339), CompletedAt: now.Format(time.RFC3339)}
	manifestBytes, manifestDigest, err := backup.CanonicalCreationManifest(manifest)
	if err != nil {
		t.Fatalf("canonical manifest: %v", err)
	}
	rows := make([]store.ExpectedObjectRow, len(objects))
	for i, object := range objects {
		rows[i] = store.ExpectedObjectRow{Type: object.Type, Name: object.Name, Bytes: object.Bytes, Digest: object.Digest}
	}
	if _, _, err := repository.AppendPendingRecoveryPoint(ctx, store.PendingRecoveryPointRequest{LeaseID: leaseID, PointID: pointID, SnapshotID: snapshotID, SnapshotCount: 1, ObjectCount: int64(len(rows)), ObjectBytes: 3, ContentDigest: manifest.ContentDigest, ManifestDigest: manifestDigest, ManifestJSON: manifestBytes, InventoryDigest: manifest.InventoryDigest, SourceRevision: 1, RecoveryEpoch: 0, SourceKind: "local", ProofClass: "fixture", ExpectedObjects: rows}); err != nil {
		t.Fatalf("append point: %v", err)
	}
	point, err := repository.GetPendingRecoveryPoint(ctx, pointID)
	if err != nil {
		t.Fatalf("read point: %v", err)
	}
	readLease := store.BackupReadLeaseRequest{LeaseID: "reader-" + pointID, PointID: pointID, RepositoryID: backupidentity.CriticalRepository, RepositoryClass: "critical", SourceRevision: 1, Expected: store.RevisionToken{StateRevision: 1, RecoveryEpoch: 0}, MaximumExpiresAt: now.Add(time.Hour)}
	if err := repository.AcquireBackupReadLease(ctx, readLease); err != nil {
		t.Fatalf("acquire reader: %v", err)
	}
	if _, err := repository.AppendLocalVerification(ctx, store.LocalVerificationRequest{VerificationID: "verify-" + pointID, RunID: "verify-run-" + pointID, PointID: pointID, ReadLeaseID: readLease.LeaseID, ManifestDigest: point.ManifestDigest, InventoryDigest: point.InventoryDigest, ObservedDigest: point.InventoryDigest, ContentDigest: point.ContentDigest, CatalogDigest: manifest.CatalogDigest, DependencyDigest: manifest.DependencyInventoryDigest, KeyReferenceID: manifest.KeyReferenceID, SourceRevision: 1, CapacityTotalBytes: 100, CapacityAvailableBytes: 80, Expected: readLease.Expected, ProofClass: "live", Result: "passed", FullReadAt: now.Add(-2 * time.Minute), FunctionalRestoredAt: now.Add(-time.Minute), DependencyTrust: []store.BackupDependencyTrustEvidence{}}); err != nil {
		t.Fatalf("append verification: %v", err)
	}
	if err := repository.ReleaseBackupReadLease(ctx, readLease.LeaseID); err != nil {
		t.Fatalf("release reader: %v", err)
	}
	return point
}

func acceptanceGeneration(id, pointID, key string, point store.PendingRecoveryPoint, now time.Time) backup.PendingOffsiteGeneration {
	d := "sha256:" + strings.Repeat("a", 64)
	base := "critical/" + id + "/"
	objects := []backup.OffsiteObject{{Key: "data/a", Digest: d, Bytes: 10}}
	return backup.PendingOffsiteGeneration{SourcePointID: pointID, SourceSnapshotID: strings.Repeat("8", 64), SourceManifestDigest: point.ManifestDigest, SourceInventoryDigest: point.InventoryDigest, SourceContentDigest: point.ContentDigest, SourceDependencyDigest: backup.ExpectedDependencyInventoryDigest(nil), SourceResticDigest: "sha256:" + strings.Repeat("6", 64), KeyReferenceID: key, GenerationID: id, RepositoryID: strings.Repeat("d", 64), OffsiteSnapshotID: strings.Repeat("e", 64), OffsiteInventoryDigest: backup.DigestOffsiteInventory(objects), RuleDigest: d, ProtectedRules: []adapter.RetentionRule{{RuleID: id + "-config", Prefix: base + "config"}, {RuleID: id + "-keys", Prefix: base + "keys/"}, {RuleID: id + "-data", Prefix: base + "data/"}, {RuleID: id + "-index", Prefix: base + "index/"}, {RuleID: id + "-snapshots", Prefix: base + "snapshots/"}}, Objects: objects, SessionExpiries: []time.Time{now.Add(-time.Hour)}, SourceRevision: 1, StateRevision: 1, RecoveryEpoch: 0, ObjectCount: 1, ObjectBytes: 10, IssuanceStoppedAt: now.Add(-2 * time.Hour)}
}

func appendAcceptanceGeneration(t *testing.T, ctx context.Context, repository *store.OffsiteRepository, value backup.PendingOffsiteGeneration) {
	t.Helper()
	body, _ := json.Marshal(value)
	rules := make([]store.OffsiteRuleRecord, len(value.ProtectedRules))
	for i, rule := range value.ProtectedRules {
		rules[i] = store.OffsiteRuleRecord{RuleID: rule.RuleID, Prefix: rule.Prefix}
	}
	objects := make([]store.OffsiteObjectRecord, len(value.Objects))
	for i, object := range value.Objects {
		objects[i] = store.OffsiteObjectRecord{Key: object.Key, Digest: object.Digest, Bytes: object.Bytes}
	}
	if err := repository.AppendGeneration(ctx, store.OffsiteGenerationRecord{GenerationID: value.GenerationID, SourcePointID: value.SourcePointID, RepositoryID: value.RepositoryID, SnapshotID: value.OffsiteSnapshotID, CanonicalJSON: body, Rules: rules, Objects: objects, SessionExpiries: value.SessionExpiries, SourceRevision: value.SourceRevision, StateRevision: value.StateRevision, RecoveryEpoch: value.RecoveryEpoch, IssuanceStoppedAt: value.IssuanceStoppedAt}); err != nil {
		t.Fatal(err)
	}
}

func acceptanceIntent(candidate backup.OffsiteRetirementCandidate, credentialDigest string) store.OffsiteRetirementIntent {
	intent := store.OffsiteRetirementIntent{IntentID: "intent-a", GenerationID: candidate.GenerationID, PointID: candidate.PointID, BucketID: candidate.BucketID, RuleSetDigest: candidate.RuleSetDigest, SurvivorRuleDigest: candidate.SurvivorRuleDigest, ManifestDigest: candidate.ManifestDigest, CatalogDigest: candidate.CatalogDigest, InventoryDigest: candidate.InventoryDigest, OneOwnerProofID: "owner-proof", LockAdminReferenceID: "lock-admin", RetentionReferenceID: "retention", G008BundleDigest: candidate.G008BundleDigest, QualificationDigest: candidate.QualificationDigest, PutCutoffDigest: candidate.PutCutoffDigest, MultipartCutoffDigest: candidate.MultipartCutoffDigest, ExclusiveAdminDigest: candidate.ExclusiveAdminDigest, CredentialBindingDigest: credentialDigest, SurvivorPointIDs: append([]string(nil), candidate.SurvivorPointIDs...), SurvivorKeyReferences: []store.OffsiteRetirementSurvivorKey{{PointID: "point-good", GenerationID: "generation-good", ReferenceID: "key-good"}}, SourceRevision: candidate.SourceRevision, StateRevision: 4, RecoveryEpoch: 0, MaxWorkObjects: candidate.MaxWorkObjects, MaxMutationBytes: candidate.MaxMutationBytes, PreRuleCount: candidate.PreRuleCount, SurvivorRuleCount: candidate.SurvivorRuleCount}
	for _, rule := range candidate.Rules {
		intent.Rules = append(intent.Rules, store.OffsiteRetirementRule{RuleID: rule.RuleID, Prefix: rule.Prefix})
	}
	for _, object := range candidate.Objects {
		intent.Objects = append(intent.Objects, store.OffsiteRetirementObject{Key: object.Key, Digest: object.Digest, Bytes: object.Bytes})
	}
	return intent
}

func commitAcceptancePlan(t *testing.T, ctx context.Context, authority *store.Store, intent store.OffsiteRetirementIntent, bindings []credentialref.StepBinding, operationID string, attribution audit.Attribution, now time.Time) generated.Plan {
	t.Helper()
	d := "sha256:" + strings.Repeat("a", 64)
	extensions := []generated.ContractExtension{{Name: "x-backup-offsite-retirement", ValueDigest: intent.IntentDigest}, {Name: "x-credential-bindings", ValueDigest: credentialref.ManifestDigest(bindings)}}
	operation := generated.DeclarationOperation{Sequence: 1, OperationID: operationID, OperationType: "backup.retire.offsite", AdapterID: "r2.retention", TargetID: intent.GenerationID, InputDigest: intent.CredentialBindingDigest, ArtifactDigest: intent.IntentDigest, Idempotent: false}
	document := generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: "declaration-a", DeclarationType: "backup.retirement.offsite", Revision: 1, StateRevision: 2, RecoveryEpoch: 0, Status: "draft", Operations: []generated.DeclarationOperation{operation}, CreatedAt: now.Format(time.RFC3339), CreatedBy: "human-a", AgentSessionID: "session-a", Extensions: extensions}
	document.ContentDigest = acceptanceDeclarationDigest(document, d)
	created, err := store.NewDeclarationRepository(authority).CreateRevision(ctx, store.DeclarationRevisionRequest{Document: document, ReasonDigest: d, Expected: store.RevisionToken{StateRevision: 1, RecoveryEpoch: 0}, KeyDigest: "sha256:" + strings.Repeat("1", 64), RequestDigest: "sha256:" + strings.Repeat("2", 64), Attribution: attribution})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.NewCredentialRepository(authority).StageStepBindings(ctx, store.CredentialBindingStageRequest{DeclarationID: document.DeclarationID, DeclarationRevision: 1, Bindings: bindings, Expected: store.RevisionToken{StateRevision: 2, RecoveryEpoch: 0}, Attribution: attribution, KeyDigest: "sha256:" + strings.Repeat("3", 64), RequestDigest: "sha256:" + strings.Repeat("4", 64)}); err != nil {
		t.Fatal(err)
	}
	desired := created.Document
	desired.Revision, desired.StateRevision, desired.Status = 2, 4, "committed"
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: document.DeclarationID, Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 3, StateRevision: 4, DeclarationRevision: 2, ObservationFingerprint: d, TargetDigest: intent.IntentDigest, ReasonDigest: d, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: operationID, OperationType: "backup.retire.offsite", AdapterID: "r2.retention", ExecutorID: "executor-central", TargetID: intent.GenerationID, InputDigest: intent.CredentialBindingDigest, ArtifactDigest: intent.IntentDigest, Idempotent: false}}, Status: "planned", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339), Extensions: extensions}
	readable := "offsite retirement\n"
	readableSum := sha256.Sum256([]byte(readable))
	plan.ReadableDigest = "sha256:" + hex.EncodeToString(readableSum[:])
	preimage, _ := json.Marshal(plan)
	planSum := sha256.Sum256(preimage)
	plan.PlanDigest = "sha256:" + hex.EncodeToString(planSum[:])
	plan.PlanID = "plan-" + hex.EncodeToString(planSum[:16])
	canonical, _ := json.Marshal(plan)
	if err := generated.ValidateContractJSON(generated.SchemaIDPlan, canonical, generated.ContractExact); err != nil {
		t.Fatalf("plan contract: %v; %s", err, canonical)
	}
	if err := generated.ValidatePlanTiming(plan); err != nil {
		t.Fatalf("plan timing: %v", err)
	}
	committed, err := store.NewPlanRepository(authority).CommitDeclarationAndPlan(ctx, store.PlanCommitRequest{Plan: plan, DesiredDeclaration: desired, SourceDeclarationRevision: 1, ReasonDigest: d, CanonicalBytes: canonical, Readable: readable, Expected: store.RevisionToken{StateRevision: 3, RecoveryEpoch: 0}, KeyDigest: "sha256:" + strings.Repeat("5", 64), RequestDigest: "sha256:" + strings.Repeat("6", 64), Attribution: attribution})
	if err != nil {
		t.Fatal(err)
	}
	return committed.Plan
}

func acceptanceDeclarationDigest(document generated.DeclarationRevision, reasonDigest string) string {
	body, _ := json.Marshal(struct {
		DeclarationID   string                           `json:"declarationId"`
		DeclarationType string                           `json:"declarationType"`
		Operations      []generated.DeclarationOperation `json:"operations"`
		ReasonDigest    string                           `json:"reasonDigest"`
		Extensions      []generated.ContractExtension    `json:"extensions"`
	}{document.DeclarationID, document.DeclarationType, document.Operations, reasonDigest, document.Extensions})
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
