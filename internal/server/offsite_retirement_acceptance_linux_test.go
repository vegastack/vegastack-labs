//go:build linux

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/r2retention"
	"github.com/vegastack/vegastack-labs/internal/adapters/r2"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
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

type acceptanceRetirementSource struct {
	providers backup.OffsiteRetirementProviderFactory
	clock     func() time.Time
}

func (s acceptanceRetirementSource) Execution(_ context.Context, _ serverconfig.Profile, authority *store.Store) (runengine.OffsiteRetirementExecution, bool, error) {
	execution, err := backup.NewSQLRetirementExecution(authority, s.providers, s.clock)
	return execution, err == nil, err
}

type acceptanceInventory struct {
	observation backup.OffsiteInventoryObservation
}

func (inventory acceptanceInventory) Inventory(context.Context, string, r2.S3Credentials, int64, int64) (backup.OffsiteInventoryObservation, error) {
	return inventory.observation, nil
}

type acceptanceLocalRetirementSource struct{ intent store.LocalRetirementIntent }

func (source acceptanceLocalRetirementSource) GetLocalRetirementIntentBySelection(context.Context, string) (store.LocalRetirementIntent, error) {
	return source.intent, nil
}

type acceptanceRetirementCatalogSource struct {
	catalog backup.OffsiteRetirementCatalog
}

func (source acceptanceRetirementCatalogSource) CurrentOffsiteRetirementCatalog(context.Context) (backup.OffsiteRetirementCatalog, error) {
	return source.catalog, nil
}

type acceptanceAdmission struct{}

func (acceptanceAdmission) Verify(context.Context, generated.Plan, generated.AuthorizationDecision, *generated.Acknowledgement) error {
	return nil
}
func (acceptanceAdmission) Activate(context.Context, generated.Plan, generated.AuthorizationDecision, generated.Run, *generated.Acknowledgement) error {
	return nil
}
func (acceptanceAdmission) VerifyRun(context.Context, generated.Plan, generated.Run) error {
	return nil
}

type acceptanceCredentialSource struct {
	bindings   *store.CredentialRepository
	references map[string]generated.CredentialReference
}

func (source acceptanceCredentialSource) GetStepBindings(ctx context.Context, plan generated.Plan, operationID string) ([]credentialref.StepBinding, error) {
	return source.bindings.GetStepBindings(ctx, plan, operationID)
}
func (source acceptanceCredentialSource) GetReference(_ context.Context, id string) (generated.CredentialReference, error) {
	if reference, ok := source.references[id]; ok {
		return reference, nil
	}
	return generated.CredentialReference{}, errors.New("credential reference unavailable")
}

type acceptanceCredentialResolver struct{}

func (acceptanceCredentialResolver) Resolve(_ context.Context, binding credentialref.StepBinding) (*credentialref.Value, error) {
	return credentialref.NewValue([]byte("secret-" + binding.ReferenceID))
}

type acceptanceReadAuthorizer struct{}

func (acceptanceReadAuthorizer) AuthorizeRead(_ context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
	return authorization.ReadScope{PrincipalID: principal.ID, Capability: target.Capability, ResourceKind: target.ResourceKind, GrantRevision: 1, ScopeDigest: "sha256:" + strings.Repeat("d", 64)}, nil
}

type acceptanceExecutionAuthorizer struct{}

func (acceptanceExecutionAuthorizer) Authorize(_ context.Context, principal identity.Principal, request authorization.Request) (authorization.Decision, error) {
	branch := authorization.BranchHuman
	scope := authorization.EffectiveScope{PrincipalID: principal.ID, Action: request.Action, Capability: request.Target.Capability, ResourceKind: request.Target.ResourceKind, ResourceID: request.Target.ResourceID, Role: authorization.RoleInfrastructureAdmin, GrantRevision: 1, StateRevision: request.Plan.Binding.StateRevision, RecoveryEpoch: request.Plan.Binding.RecoveryEpoch, ScopeDigest: "sha256:" + strings.Repeat("e", 64)}
	return authorization.Decision{PrincipalID: principal.ID, Action: request.Action, Target: request.Target, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: scope.GrantRevision, StateRevision: scope.StateRevision, RecoveryEpoch: scope.RecoveryEpoch, PlanDigest: request.Plan.PlanDigest, Risk: authorization.RiskDestructive, Scope: scope}, nil
}

type acceptanceDecisionRecorder struct{}

func (acceptanceDecisionRecorder) RecordDecision(context.Context, authorization.DecisionRecord) error {
	return nil
}

type acceptanceAcknowledgementSource struct {
	repository *store.AcknowledgementRepository
}

func (source acceptanceAcknowledgementSource) Status(ctx context.Context, planID string) (generated.Acknowledgement, error) {
	stored, err := source.repository.Get(ctx, planID)
	return stored.Acknowledgement, err
}

func TestProductionOffsiteRetirementHTTPCompositionAcceptance(t *testing.T) {
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
	credentialDirectory := t.TempDir()
	lockSecret := []byte("fixture-lock-admin-token")
	retentionSecret := []byte(`{"accountId":"fixture-account","accessKeyId":"fixture-access","secretAccessKey":"fixture-secret"}`)
	repositorySecret := []byte("fixture-repository-password")
	credentialFingerprint := func(value []byte) string {
		sum := sha256.Sum256(value)
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	for name, value := range map[string][]byte{"lock-admin": lockSecret, "retention": retentionSecret, "key-good": repositorySecret} {
		if err := os.WriteFile(filepath.Join(credentialDirectory, name), value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentialDirectory)
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
	catalog := backup.OffsiteRetirementCatalog{Generations: []backup.PendingOffsiteGeneration{good, old}, GenerationCreatedAt: map[string]time.Time{old.GenerationID: now.Add(-15 * 24 * time.Hour), good.GenerationID: now}, VerifiedPointIDs: []string{old.SourcePointID, good.SourcePointID}, LastGoodPointIDs: []string{good.SourcePointID}, BucketID: "bucket-a", CatalogDigest: d, G008BundleDigest: bundleDigest, QualificationDigest: d, PutCutoffDigest: d, MultipartCutoffDigest: d, ExclusiveAdminDigest: d, LockAdminReferenceID: "lock-admin", LockAdminFingerprint: credentialFingerprint(lockSecret), RetentionReferenceID: "retention", RetentionFingerprint: credentialFingerprint(retentionSecret), RuleCount: len(allRules), RuleLimit: 1000, TotalBytes: 100, AvailableBytes: 80, ObservedAt: now}
	for _, rule := range allRules {
		catalog.CurrentRules = append(catalog.CurrentRules, backup.RetentionRuleRef{RuleID: rule.RuleID, Prefix: rule.Prefix})
	}
	catalog.RuleSetDigest = r2retention.DigestRuleSet(r2retention.RuleSet{Rules: allRules})
	candidate, err := backup.SelectOffsiteRetirement(catalog, selection, now)
	if err != nil {
		t.Fatal(err)
	}
	localSelectionDigest := "sha256:" + strings.Repeat("b", 64)
	localIntent := store.LocalRetirementIntent{Request: store.LocalRetirementStageRequest{SelectionDigest: localSelectionDigest, StateRevision: 4, RecoveryEpoch: 0, Targets: []store.LocalRetirementTarget{{PointID: old.SourcePointID}}, Survivors: []store.LocalRetirementSurvivor{{PointID: good.SourcePointID}}}}
	stageService, err := api.NewOffsiteRetirementStageService(acceptanceLocalRetirementSource{intent: localIntent}, store.NewOffsiteRetirementRepository(authority), acceptanceRetirementCatalogSource{catalog: catalog})
	if err != nil {
		t.Fatal(err)
	}
	stageResults := result.NewFactory(result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "test-build"}, func() (string, error) { return "request-offsite-stage", nil })
	stageApplication, err := api.NewApplication(api.Config{Authority: authority, Authorizer: acceptanceReadAuthorizer{}, Reads: store.NewReadRepository(authority), Results: stageResults})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterBackupOperations(stageApplication, api.BackupOperations{Drafts: repository, OffsiteRetirements: stageService, Results: stageResults}); err != nil {
		t.Fatal(err)
	}
	principal := identity.Principal{ID: attribution.AuthenticatedPrincipalID, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	dryRequest := generated.BackupOffsiteRetirementDryRunRequest{Schema: generated.SchemaIDBackupOffsiteRetirementDryRunRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 4, RecoveryEpoch: 0, SelectionDigest: localSelectionDigest, OneOwnerProofID: "owner-proof", LockAdminReferenceID: "lock-admin", RetentionReferenceID: "retention"}
	var dryEnvelope struct {
		Data generated.BackupOffsiteRetirementDryRunData `json:"data"`
	}
	if response := acceptanceHTTP(t, stageApplication, "/api/v1/backups/offsite-retirements/dry-run", dryRequest, principal, &dryEnvelope); response.Code != http.StatusOK {
		t.Fatalf("dry-run status=%d body=%s", response.Code, response.Body.String())
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
	if err != nil || intent.IntentDigest != dryEnvelope.Data.IntentDigest {
		t.Fatalf("HTTP dry-run mismatch: computed=%s response=%s err=%v", intent.IntentDigest, dryEnvelope.Data.IntentDigest, err)
	}
	seedAcceptanceCredentials(t, filepath.Join(directory, "control.db"), intent, attribution, now)
	// The qualified G008 evidence, deployment profile, and effective grant are
	// observed authority inputs. Establish them before the immutable plan is
	// committed, then leave them unchanged through the restarted server run.
	seedAcceptanceGate(t, filepath.Join(directory, "control.db"), intent, bundle, bundleBytes, bundleDigest, attribution, now)
	plan := commitAcceptancePlan(t, ctx, authority, intent, bindings, operationID, attribution, now)
	stageRequest := generated.BackupOffsiteRetirementStageRequest{Schema: generated.SchemaIDBackupOffsiteRetirementStageRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 4, RecoveryEpoch: 0, TargetDigest: dryEnvelope.Data.IntentDigest, IdempotencyKey: "retire-a", SelectionDigest: localSelectionDigest, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, OneOwnerProofID: "owner-proof", LockAdminReferenceID: "lock-admin", RetentionReferenceID: "retention", CredentialBindingDigest: credentialDigest}
	var stageEnvelope struct {
		Data generated.BackupOffsiteRetirementStageSubmission `json:"data"`
	}
	if response := acceptanceHTTP(t, stageApplication, "/api/v1/backups/offsite-retirements/stage", stageRequest, principal, &stageEnvelope); response.Code != http.StatusOK || stageEnvelope.Data.Status != "staged" {
		t.Fatalf("stage status=%d body=%s", response.Code, response.Body.String())
	}
	stagedIntent, err := store.NewOffsiteRetirementRepository(authority).GetOffsiteRetirementIntentByDigest(ctx, dryEnvelope.Data.IntentDigest)
	if err != nil || stagedIntent.IntentID != stageEnvelope.Data.IntentID {
		t.Fatalf("durable staged intent unavailable for restart reconciliation: %+v %v", stagedIntent, err)
	}
	authorizeAcceptancePlan(t, ctx, authority, plan, attribution, now)
	assertAcceptancePlanCurrent(t, ctx, authority, plan)
	assertAcceptanceAcknowledgementAuthority(t, ctx, authority, plan, attribution.AuthenticatedPrincipalID)

	providerRules := &acceptanceRules{current: r2retention.RuleSet{Rules: append([]r2retention.Rule(nil), allRules...)}}
	providerObjects := &acceptanceObjects{}
	for _, object := range old.Objects {
		providerObjects.values = append(providerObjects.values, r2retention.Object{Key: object.Key, Digest: object.Digest, Bytes: object.Bytes})
	}
	providerProfile := &serverconfig.OffsiteBackup{Endpoint: "https://fixture.invalid", Bucket: "bucket-a", Prefix: "critical", ParentReferenceID: "parent-a", ParentFingerprint: d, ObserverReferenceID: "observer-a", LockAdminReferenceID: "lock-admin", LockAdminFingerprint: credentialFingerprint(lockSecret), RetentionReferenceID: "retention", RetentionFingerprint: credentialFingerprint(retentionSecret)}
	parentValue, _ := credentialref.NewValue(retentionSecret)
	repositoryValue, _ := credentialref.NewValue(repositorySecret)
	failingVerifier := &labsR2SurvivorVerifier{authority: authority, profile: providerProfile, local: &serverconfig.LocalBackup{ResticBinaryPath: "/opt/vsk/restic", CustodyPolicyPath: "/etc/vsk/custody.json"}, intent: stagedIntent, binding: adapter.ExactExecutionBinding{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: "restore-failure-run", StepID: "restore-failure-step", LeaseID: "restore-failure-lease", RecoveryEpoch: 0, MaximumExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}, repository: store.NewOffsiteRetirementRepository(authority), inventory: acceptanceInventory{observation: backup.OffsiteInventoryObservation{InventoryDigest: good.OffsiteInventoryDigest, ObjectCount: int64(len(good.Objects)), ObjectBytes: good.ObjectBytes, Objects: append([]backup.OffsiteObject(nil), good.Objects...)}}, restore: func(context.Context, r2.RetirementSurvivorVerificationConfig, string) (backup.OffsiteSurvivorProof, error) {
		return backup.OffsiteSurvivorProof{}, errors.New("hermetic isolated restore failed")
	}, credentials: r2.S3Credentials{AccessKeyID: []byte("fixture-access"), SecretAccessKey: []byte("fixture-secret")}, parent: parentValue, repositoryKeys: map[string]*credentialref.Value{"key-good": repositoryValue}, prefix: "critical", clock: func() time.Time { return now }}
	if _, err := failingVerifier.VerifyOffsiteSurvivor(ctx, good.SourcePointID); err == nil {
		t.Fatal("isolated restore failure was accepted")
	}
	_ = failingVerifier.Close()
	restoreCalls := 0
	restore := func(_ context.Context, config r2.RetirementSurvivorVerificationConfig, pointID string) (backup.OffsiteSurvivorProof, error) {
		restoreCalls++
		if config.Intent.IntentDigest != dryEnvelope.Data.IntentDigest || config.RepositoryKey == nil || pointID != good.SourcePointID {
			return backup.OffsiteSurvivorProof{}, errors.New("isolated restore binding mismatch")
		}
		return backup.OffsiteSurvivorProof{PointID: pointID, GenerationID: good.GenerationID, RuleDigest: good.RuleDigest, InventoryDigest: good.OffsiteInventoryDigest, FullReadDigest: "sha256:" + strings.Repeat("b", 64), RestoreDigest: "sha256:" + strings.Repeat("c", 64), FullReadAt: now, RestoredAt: now, ObservedAt: now, RecoveryEpoch: 0}, nil
	}
	requestBody := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: 0, IdempotencyKey: "submit-a", Extensions: []generated.ContractExtension{}}
	rawRequest, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}
	profilePath, socketPath := writeOffsiteAcceptanceProfile(t, directory, bundleDigest, d, credentialFingerprint(lockSecret), credentialFingerprint(retentionSecret))
	if err := authority.Close(); err != nil {
		t.Fatal(err)
	}
	operations := NewOperations(result.BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "test-build"}, func() (string, error) { return "request-offsite-operations", nil },
		WithOffsiteRetirementEffectFactory(func(_ context.Context, _ serverconfig.Profile, opened *store.Store) (adapter.Adapter, error) {
			source := acceptanceRetirementSource{providers: labsR2RetirementProviders{profile: providerProfile, local: &serverconfig.LocalBackup{ResticBinaryPath: "/opt/vsk/restic", CustodyPolicyPath: "/etc/vsk/custody.json"}, authority: opened, rules: providerRules, objects: providerObjects, inventory: acceptanceInventory{observation: backup.OffsiteInventoryObservation{InventoryDigest: good.OffsiteInventoryDigest, ObjectCount: int64(len(good.Objects)), ObjectBytes: good.ObjectBytes, Objects: append([]backup.OffsiteObject(nil), good.Objects...)}}, restore: restore}, clock: func() time.Time { return now }}
			return NewProductionOffsiteRetirementEffectFactory(source)(context.Background(), serverconfig.Profile{OffsiteBackup: providerProfile}, opened)
		}),
		WithOffsiteRetirementCatalogSource(acceptanceRetirementCatalogSource{catalog: catalog}),
	)
	operations.databasePath = filepath.Join(directory, "control.db")
	operations.platformProbe = fixedPlatformProbe{platform: testSupportedPlatform()}
	operations.openStore = func(openContext context.Context, config store.Config) (*store.Store, error) {
		config.Filesystem = acceptanceFilesystem{}
		config.Clock = func() time.Time { return now }
		return store.Open(openContext, config)
	}
	serverContext, stopServer := context.WithCancel(ctx)
	serverDone := make(chan error, 1)
	go func() { serverDone <- operations.Run(serverContext, profilePath) }()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, statErr := os.Stat(socketPath); statErr == nil {
			break
		}
		select {
		case startErr := <-serverDone:
			stopServer()
			t.Fatalf("Operations.Run startup failed: %v", startErr)
		default:
		}
		if time.Now().After(deadline) {
			stopServer()
			t.Fatalf("Operations.Run did not create control socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
	transport := &http.Transport{DialContext: func(dialContext context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(dialContext, "unix", socketPath)
	}}
	httpRequest, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://control/api/v1/plans/"+plan.PlanID+"/execute", bytes.NewReader(rawRequest))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpResponse, requestErr := (&http.Client{Transport: transport, Timeout: 10 * time.Second}).Do(httpRequest)
	var responseBody []byte
	if httpResponse != nil {
		responseBody, _ = io.ReadAll(httpResponse.Body)
		_ = httpResponse.Body.Close()
	}
	stopServer()
	serverErr := <-serverDone
	if requestErr != nil || serverErr != nil || httpResponse == nil || httpResponse.StatusCode != http.StatusOK || !bytes.Contains(responseBody, []byte(`"status":"succeeded"`)) || len(providerObjects.values) != 0 || len(providerRules.current.Rules) != 5 || restoreCalls != 1 {
		t.Fatalf("Operations.Run execute response=%v body=%s requestErr=%v serverErr=%v objects=%d rules=%d restores=%d", httpResponse, responseBody, requestErr, serverErr, len(providerObjects.values), len(providerRules.current.Rules), restoreCalls)
	}
}

// seedAcceptanceAuthority supplies the already-qualified live G-008 proof and
// human-owned run that precede retirement. The retirement lease, provider
// journal, survivor proofs, and settlement remain production-created by the
// execution under test; none of those records are synthesized here.
func seedAcceptanceGate(t *testing.T, databasePath string, intent store.OffsiteRetirementIntent, bundle generated.GateEvidenceBundle, bundleBytes []byte, bundleDigest string, attribution audit.Attribution, now time.Time) {
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
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO gate_evidence_drafts(draft_id,evidence_id,gate_id,subject_id,definition_version,evaluator_version,source_kind,proof_class,artifact_digest,bundle_digest,bundle_bytes,observed_at,state_revision,recovery_epoch,human_id,created_at) VALUES('gate-draft','owner-proof','G-008',?,'1.0.0','1.0.0','local','live',?,?,?,?,4,0,?,?)`, []any{intent.BucketID, d, bundleDigest, bundleBytes, bundle.ObservedAt, attribution.AuthenticatedPrincipalID, now.Format(time.RFC3339)}},
		{`INSERT INTO gate_applied_evidence(evidence_id,draft_id,gate_id,subject_id,status,source_kind,proof_class,bundle_digest,canonical_bytes,state_revision,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,applied_at) VALUES('owner-proof','gate-draft','G-008',?,'applied','local','live',?,?,4,0,'gate-declaration',1,'gate-plan',?,'gate-run','gate-step','gate-lease',?)`, []any{intent.BucketID, bundleDigest, evidenceBytes, d, now.Format(time.RFC3339)}},
		{`INSERT INTO gate_applied_profiles(binding_id,profile_id,profile_version,policy_id,policy_version,capabilities_bytes,state_revision,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,applied_at) VALUES('profile-binding','vegastack-labs','1.0.0','policy-a','1.0.0',?,4,0,'gate-declaration',1,'gate-plan',?,'gate-run','gate-step','gate-lease',?,?)`, []any{[]byte(`["credential.native.read"]`), d, attribution.AuthenticatedPrincipalID, now.Format(time.RFC3339)}},
		{`INSERT INTO effective_authorization_principals(principal_id,principal_kind,status,grant_revision,created_at,updated_at) VALUES(?,'human','active',1,?,?)`, []any{attribution.AuthenticatedPrincipalID, now.Format(time.RFC3339), now.Format(time.RFC3339)}},
		{`INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES('grant-offsite-execute',?,'infrastructure-admin','execute','backup.retire.offsite','execution-target',?,'human',1,'active',?,?)`, []any{attribution.AuthenticatedPrincipalID, intent.GenerationID, now.Format(time.RFC3339), now.Format(time.RFC3339)}},
		{`INSERT INTO effective_authorization_grants(grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,branch,grant_revision,status,created_at,updated_at) VALUES('grant-offsite-acknowledge',?,'infrastructure-admin','acknowledge','plan.acknowledge','plan-target',?,'human',1,'active',?,?)`, []any{attribution.AuthenticatedPrincipalID, intent.GenerationID, now.Format(time.RFC3339), now.Format(time.RFC3339)}},
	}
	for index, statement := range statements {
		if _, err := database.ExecContext(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed authority statement %d: %v", index, err)
		}
	}
}

func seedAcceptanceCredentials(t *testing.T, databasePath string, intent store.OffsiteRetirementIntent, attribution audit.Attribution, now time.Time) {
	t.Helper()
	database, err := sql.Open("sqlite3", "file:"+databasePath+"?mode=rw")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	d := "sha256:" + strings.Repeat("a", 64)
	credentials := []struct{ id, purpose, fingerprint string }{{intent.LockAdminReferenceID, "lock-admin", intent.LockAdminFingerprint}, {intent.RetentionReferenceID, "retention", intent.RetentionFingerprint}}
	for _, survivor := range intent.SurvivorKeyReferences {
		credentials = append(credentials, struct{ id, purpose, fingerprint string }{survivor.ReferenceID, "repository-key", d})
	}
	for index, credential := range credentials {
		if _, err := database.ExecContext(context.Background(), `INSERT INTO credential_reference_versions(version_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at) VALUES(?,?,?,?,?,'native-systemd','v1',?,'active',1,0,?,?,'credential-declaration',1,'credential-plan',?,'credential-run','credential-step','credential-lease',?,?)`, "credential-version-"+credential.id, credential.id, "r2.retention", credential.purpose, intent.GenerationID, credential.fingerprint, now.Format(time.RFC3339), []byte(`["r2.retention"]`), d, attribution.AuthenticatedPrincipalID, now.Format(time.RFC3339)); err != nil {
			t.Fatalf("seed credential reference %d: %v", index, err)
		}
	}
}

func authorizeAcceptancePlan(t *testing.T, ctx context.Context, authority *store.Store, plan generated.Plan, attribution audit.Attribution, now time.Time) generated.Acknowledgement {
	t.Helper()
	request := generated.AcknowledgementRequest{Schema: generated.SchemaIDAcknowledgementRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, HumanID: attribution.AuthenticatedPrincipalID, AuthorityID: "infra-admin", NonceDigest: "sha256:" + strings.Repeat("b", 64), StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: plan.ExpiresAt, Extensions: []generated.ContractExtension{}}
	receivedAt := now.UTC().Truncate(time.Second)
	pending := generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", PlanID: request.PlanID, PlanDigest: request.PlanDigest, TargetDigest: request.TargetDigest, ReasonDigest: request.ReasonDigest, HumanID: request.HumanID, AuthorityID: request.AuthorityID, NonceDigest: request.NonceDigest, StateRevision: request.StateRevision, RecoveryEpoch: request.RecoveryEpoch, ExpiresAt: request.ExpiresAt, AcknowledgementID: "ack-retirement-a", Status: "pending", ReceivedAt: receivedAt.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	pending.ProofDigest = acceptanceAcknowledgementProofDigest(request, pending.Status, receivedAt)
	repository := store.NewAcknowledgementRepository(authority)
	if _, _, err := repository.Create(ctx, acknowledgement.CreateRecord{Request: request, Pending: pending, CreatedAt: now, Attribution: attribution}); err != nil {
		t.Fatal(err)
	}
	approved := pending
	approved.Status = "approved"
	approved.ProofDigest = acceptanceAcknowledgementProofDigest(request, approved.Status, receivedAt)
	if _, _, err := repository.Decide(ctx, acknowledgement.DecisionRecord{Expected: request, Outcome: approved, DecidedAt: now, Attribution: attribution}); err != nil {
		t.Fatal(err)
	}
	return approved
}

func acceptanceAcknowledgementProofDigest(request generated.AcknowledgementRequest, status string, receivedAt time.Time) string {
	preimage := strings.Join([]string{"acknowledgement-proof-v1", request.PlanID, request.PlanDigest, request.TargetDigest, request.ReasonDigest, request.HumanID, request.AuthorityID, request.NonceDigest, request.ExpiresAt, status, receivedAt.UTC().Truncate(time.Second).Format(time.RFC3339), strconv.FormatInt(request.StateRevision, 10), strconv.FormatInt(request.RecoveryEpoch, 10)}, "\x00")
	sum := sha256.Sum256([]byte(preimage))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func assertAcceptancePlanCurrent(t *testing.T, ctx context.Context, authority *store.Store, plan generated.Plan) {
	t.Helper()
	repository := store.NewPlanRepository(authority)
	current, err := repository.CurrentRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current != (store.RevisionToken{StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch}) {
		t.Fatalf("authority drift before restarted execution: current=%+v plan=%+v", current, plan.Binding)
	}
	declaration, err := repository.GetDeclaration(ctx, plan.DeclarationID, plan.Binding.DeclarationRevision)
	if err != nil {
		t.Fatal(err)
	}
	observations, err := planengine.NewStateObservationReader(repository)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := observations.CurrentFingerprint(ctx, declaration.DeclarationID, declaration.Operations)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != plan.Binding.ObservationFingerprint {
		t.Fatalf("observation drift before restarted execution: current=%s plan=%s", fingerprint, plan.Binding.ObservationFingerprint)
	}
}

func assertAcceptanceAcknowledgementAuthority(t *testing.T, ctx context.Context, authority *store.Store, plan generated.Plan, humanID string) {
	t.Helper()
	principal := identity.Principal{ID: humanID, Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
	target := authorization.Target{Capability: "plan.acknowledge", ResourceKind: "plan-target", ResourceID: plan.Operations[0].TargetID}
	decision, err := authorization.NewEvaluator(store.NewEffectiveAuthorizationRepository(authority)).Authorize(ctx, principal, authorization.Request{Action: authorization.ActionAcknowledge, Target: target, Plan: &plan, Branches: []authorization.Branch{authorization.BranchHuman}})
	if err != nil || !decision.Allowed {
		t.Fatalf("acknowledgement authority drift before restarted execution: decision=%+v err=%v", decision, err)
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
	if err := repository.AppendRunSpec(ctx, store.OffsiteRunSpecRecord{GenerationID: value.GenerationID, SourcePointID: value.SourcePointID, SnapshotPath: "/srv/backup/control.db", RepositoryURL: "s3:https://fixture.invalid/bucket-a/critical/" + value.GenerationID, ParentReferenceID: "parent-a", RepositoryKeyReferenceID: value.KeyReferenceID, ObserverReferenceID: "observer-a", RuleDigest: value.RuleDigest, G008EvidenceDigest: "sha256:" + strings.Repeat("a", 64), CanonicalJSON: []byte(`{}`), MaximumBytes: 1024, MaximumPUTs: 10, MaximumLISTs: 10, MaximumRetainedGenerations: 10, RuleLimit: 1000, RetentionSeconds: 86400, SessionTTLSeconds: 60, SourceRevision: value.SourceRevision, StateRevision: value.StateRevision, RecoveryEpoch: value.RecoveryEpoch}); err != nil {
		t.Fatal(err)
	}
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
	intent := store.OffsiteRetirementIntent{IntentID: "intent-a", GenerationID: candidate.GenerationID, PointID: candidate.PointID, BucketID: candidate.BucketID, RuleSetDigest: candidate.RuleSetDigest, SurvivorRuleDigest: candidate.SurvivorRuleDigest, ManifestDigest: candidate.ManifestDigest, CatalogDigest: candidate.CatalogDigest, InventoryDigest: candidate.InventoryDigest, OneOwnerProofID: "owner-proof", LockAdminReferenceID: candidate.LockAdminReferenceID, RetentionReferenceID: candidate.RetentionReferenceID, LockAdminFingerprint: candidate.LockAdminFingerprint, RetentionFingerprint: candidate.RetentionFingerprint, G008BundleDigest: candidate.G008BundleDigest, QualificationDigest: candidate.QualificationDigest, PutCutoffDigest: candidate.PutCutoffDigest, MultipartCutoffDigest: candidate.MultipartCutoffDigest, ExclusiveAdminDigest: candidate.ExclusiveAdminDigest, CredentialBindingDigest: credentialDigest, SurvivorPointIDs: append([]string(nil), candidate.SurvivorPointIDs...), SurvivorKeyReferences: []store.OffsiteRetirementSurvivorKey{{PointID: "point-good", GenerationID: "generation-good", ReferenceID: "key-good", DependencyDigest: backup.ExpectedDependencyInventoryDigest(nil)}}, SourceRevision: candidate.SourceRevision, StateRevision: 4, RecoveryEpoch: 0, MaxWorkObjects: candidate.MaxWorkObjects, MaxMutationBytes: candidate.MaxMutationBytes, PreRuleCount: candidate.PreRuleCount, SurvivorRuleCount: candidate.SurvivorRuleCount}
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
	observationReader, err := planengine.NewStateObservationReader(store.NewPlanRepository(authority))
	if err != nil {
		t.Fatal(err)
	}
	observationFingerprint, err := observationReader.CurrentFingerprint(ctx, desired.DeclarationID, desired.Operations)
	if err != nil {
		t.Fatal(err)
	}
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: document.DeclarationID, Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 3, StateRevision: 4, DeclarationRevision: 2, ObservationFingerprint: observationFingerprint, TargetDigest: intent.IntentDigest, ReasonDigest: d, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: operationID, OperationType: "backup.retire.offsite", AdapterID: "r2.retention", ExecutorID: "executor-central", TargetID: intent.GenerationID, InputDigest: intent.CredentialBindingDigest, ArtifactDigest: intent.IntentDigest, Idempotent: false}}, Status: "planned", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339), Extensions: extensions}
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

func acceptanceHTTP(t *testing.T, handler http.Handler, path string, input any, principal identity.Principal, output any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code == http.StatusOK && output != nil {
		if err := json.Unmarshal(response.Body.Bytes(), output); err != nil {
			t.Fatalf("decode %s response: %v; body=%s", path, err, response.Body.String())
		}
	}
	return response
}

func writeOffsiteAcceptanceProfile(t *testing.T, directory, bundleDigest, digest, lockFingerprint, retentionFingerprint string) (string, string) {
	t.Helper()
	shortDirectory, err := os.MkdirTemp(os.TempDir(), "p.")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shortDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shortDirectory) })
	directory = shortDirectory
	pointer := func(value string) *string { return &value }
	integer := func(value int64) *int64 { return &value }
	socketPath := filepath.Join(directory, "control.sock")
	exportRoot := filepath.Join(directory, "exports")
	if err := os.Mkdir(exportRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	account := strings.Repeat("a", 32)
	endpoint := "https://" + account + ".r2.cloudflarestorage.com"
	standardRoot, criticalRoot := filepath.Join(directory, "standard"), filepath.Join(directory, "critical")
	resticPath, custodyPath := filepath.Join(directory, "restic"), filepath.Join(directory, "custody.json")
	profile := generated.ServerProfile{Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.3.0", SocketPath: socketPath, SocketOwnerUID: int64(os.Getuid()), SocketMode: "0600", ShutdownGraceSeconds: 5, InventoryExportRoot: exportRoot, PrincipalBindings: []generated.LocalPrincipalBinding{{UID: int64(os.Getuid()), PrincipalID: "human-a"}}, RemoteRead: generated.RemoteReadProfile{Enabled: false}, AcknowledgementAdapterConfigPath: filepath.Join(directory, "acknowledgement.json"), StandardBackupRoot: &standardRoot, CriticalBackupRoot: &criticalRoot, ResticBinaryPath: &resticPath, CustodyPolicyPath: &custodyPath, OffsiteEndpoint: &endpoint, OffsiteBucket: pointer("bucket-a"), OffsitePrefix: pointer("critical"), OffsiteParentReferenceID: pointer("parent-a"), OffsiteObserverReferenceID: pointer("observer-a"), OffsiteLockAdminReferenceID: pointer("lock-admin"), OffsiteLockAdminFingerprint: &lockFingerprint, OffsiteRetentionReferenceID: pointer("retention"), OffsiteRetentionFingerprint: &retentionFingerprint, OffsiteParentFingerprint: &digest, OffsiteRuleDigest: &digest, OffsiteG008EvidenceDigest: &bundleDigest, OffsiteAccountID: &account, OffsiteQualificationDigest: &digest, OffsitePutCutoffDigest: &digest, OffsiteMultipartCutoffDigest: &digest, OffsiteAvailableBytes: integer(80), OffsiteAvailablePUTs: integer(100), OffsiteAvailableLISTs: integer(100), OffsiteRuleCount: integer(10), OffsiteRetainedGenerations: integer(2)}
	raw, err := json.Marshal(profile)
	contractErr := generated.ValidateContractJSON(generated.SchemaIDServerProfile, raw, generated.ContractExact)
	if err != nil || contractErr != nil {
		t.Fatalf("acceptance server profile invalid: marshal=%v contract=%v body=%s", err, contractErr, raw)
	}
	profilePath := filepath.Join(directory, "server.json")
	if err := os.WriteFile(profilePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return profilePath, socketPath
}
