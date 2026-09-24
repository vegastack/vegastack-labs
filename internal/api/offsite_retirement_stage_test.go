package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/r2retention"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type localOffsiteSelectionFixture struct{ value store.LocalRetirementIntent }

func (f localOffsiteSelectionFixture) GetLocalRetirementIntentBySelection(context.Context, string) (store.LocalRetirementIntent, error) {
	return f.value, nil
}

type offsiteStagerFixture struct {
	staged *store.OffsiteRetirementIntent
}

func (f offsiteStagerFixture) StageOffsiteRetirement(_ context.Context, intent store.OffsiteRetirementIntent) (string, error) {
	if f.staged != nil {
		*f.staged = intent
	}
	return intent.IntentID, nil
}

type offsiteCatalogFixture struct {
	value backup.OffsiteRetirementCatalog
}

func (f offsiteCatalogFixture) CurrentOffsiteRetirementCatalog(context.Context) (backup.OffsiteRetirementCatalog, error) {
	return f.value, nil
}

func TestOffsiteRetirementStageFailsClosedWithoutQualifiedCatalog(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	local := store.LocalRetirementIntent{Request: store.LocalRetirementStageRequest{SelectionDigest: d, StateRevision: 7, RecoveryEpoch: 2, Targets: []store.LocalRetirementTarget{{PointID: "point-old"}}, Survivors: []store.LocalRetirementSurvivor{{PointID: "point-good"}}}}
	service, err := NewOffsiteRetirementStageService(localOffsiteSelectionFixture{local}, offsiteStagerFixture{}, UnavailableOffsiteRetirementCatalogSource{})
	if err != nil {
		t.Fatal(err)
	}
	input := generated.BackupOffsiteRetirementStageRequest{Schema: generated.SchemaIDBackupOffsiteRetirementStageRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: d, IdempotencyKey: "key-test", SelectionDigest: d, PlanID: "plan-a", PlanDigest: d, OneOwnerProofID: "proof-a", LockAdminReferenceID: "lock-admin", RetentionReferenceID: "retention", CredentialBindingDigest: d}
	_, err = service.Stage(context.Background(), input, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman})
	if apiErrorCode(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("error=%v", err)
	}
	dry := generated.BackupOffsiteRetirementDryRunRequest{Schema: generated.SchemaIDBackupOffsiteRetirementDryRunRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, SelectionDigest: d, OneOwnerProofID: "proof-a", LockAdminReferenceID: "lock-admin", RetentionReferenceID: "retention"}
	if _, err := service.DryRun(context.Background(), dry, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}); apiErrorCode(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("missing G-008 dry-run error=%v", err)
	}
	dry.ExpectedStateRevision++
	if _, err := service.DryRun(context.Background(), dry, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}); apiErrorCode(err) != generated.ErrorCodePlanStale {
		t.Fatalf("stale revision dry-run error=%v", err)
	}
	dry.ExpectedStateRevision, dry.RecoveryEpoch = 7, 3
	if _, err := service.DryRun(context.Background(), dry, identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}); apiErrorCode(err) != generated.ErrorCodePlanStale {
		t.Fatalf("stale epoch dry-run error=%v", err)
	}
}

func TestOffsiteRetirementRouteDryRunBindsSurvivorKeysBeforeStage(t *testing.T) {
	now := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
	d := "sha256:" + strings.Repeat("a", 64)
	generation := func(id, point, key string) backup.PendingOffsiteGeneration {
		objects := []backup.OffsiteObject{{Key: "data/a", Digest: d, Bytes: 10}}
		base := "backups/" + id + "/"
		return backup.PendingOffsiteGeneration{SourcePointID: point, SourceSnapshotID: strings.Repeat("b", 64), SourceManifestDigest: d, SourceInventoryDigest: d, SourceContentDigest: d, SourceDependencyDigest: d, SourceResticDigest: d, KeyReferenceID: key, GenerationID: id, RepositoryID: strings.Repeat("d", 64), OffsiteSnapshotID: strings.Repeat("c", 64), OffsiteInventoryDigest: backup.DigestOffsiteInventory(objects), RuleDigest: d, ProtectedRules: []adapter.RetentionRule{{RuleID: id + "-config", Prefix: base + "config"}, {RuleID: id + "-keys", Prefix: base + "keys/"}, {RuleID: id + "-data", Prefix: base + "data/"}, {RuleID: id + "-index", Prefix: base + "index/"}, {RuleID: id + "-snapshots", Prefix: base + "snapshots/"}}, Objects: objects, SessionExpiries: []time.Time{now.Add(-time.Hour)}, SourceRevision: 2, StateRevision: 7, RecoveryEpoch: 2, ObjectCount: 1, ObjectBytes: 10, IssuanceStoppedAt: now.Add(-2 * time.Hour)}
	}
	old, good := generation("generation-old", "point-old", "key-old"), generation("generation-good", "point-good", "key-good")
	var rules []backup.RetentionRuleRef
	for _, g := range []backup.PendingOffsiteGeneration{old, good} {
		for _, rule := range g.ProtectedRules {
			rules = append(rules, backup.RetentionRuleRef{RuleID: rule.RuleID, Prefix: rule.Prefix})
		}
	}
	ruleValues := make([]r2retention.Rule, len(rules))
	for i, rule := range rules {
		ruleValues[i] = r2retention.Rule{RuleID: rule.RuleID, Prefix: rule.Prefix}
	}
	catalog := backup.OffsiteRetirementCatalog{Generations: []backup.PendingOffsiteGeneration{good, old}, GenerationCreatedAt: map[string]time.Time{old.GenerationID: now.Add(-15 * 24 * time.Hour), good.GenerationID: now}, CurrentRules: rules, VerifiedPointIDs: []string{old.SourcePointID, good.SourcePointID}, LastGoodPointIDs: []string{good.SourcePointID}, BucketID: "bucket-a", RuleSetDigest: r2retention.DigestRuleSet(r2retention.RuleSet{Rules: ruleValues}), CatalogDigest: d, G008BundleDigest: d, QualificationDigest: d, PutCutoffDigest: d, MultipartCutoffDigest: d, ExclusiveAdminDigest: d, LockAdminReferenceID: "lock-admin", LockAdminFingerprint: d, RetentionReferenceID: "retention", RetentionFingerprint: d, RuleCount: len(rules), RuleLimit: 1000, TotalBytes: 100, AvailableBytes: 80, ObservedAt: now}
	selection := "sha256:" + strings.Repeat("b", 64)
	local := store.LocalRetirementIntent{Request: store.LocalRetirementStageRequest{SelectionDigest: selection, StateRevision: 7, RecoveryEpoch: 2, Targets: []store.LocalRetirementTarget{{PointID: old.SourcePointID}}, Survivors: []store.LocalRetirementSurvivor{{PointID: good.SourcePointID}}}}
	var staged store.OffsiteRetirementIntent
	service, err := NewOffsiteRetirementStageService(localOffsiteSelectionFixture{local}, offsiteStagerFixture{staged: &staged}, offsiteCatalogFixture{catalog})
	if err != nil {
		t.Fatal(err)
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-offsite", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	effective := &effectiveAuthorizationStub{}
	app.effective = EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: func() time.Time { return now }}
	if err := RegisterBackupOperations(app, BackupOperations{Drafts: &backupDraftServiceStub{}, OffsiteRetirements: service, Results: factory}); err != nil {
		t.Fatal(err)
	}
	principal := identity.Principal{ID: "human-a", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	dryInput := generated.BackupOffsiteRetirementDryRunRequest{Schema: generated.SchemaIDBackupOffsiteRetirementDryRunRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, SelectionDigest: selection, OneOwnerProofID: "proof-a", LockAdminReferenceID: "lock-admin", RetentionReferenceID: "retention"}
	dryRaw, _ := json.Marshal(dryInput)
	dryRequest := httptest.NewRequest(http.MethodPost, "/api/v1/backups/offsite-retirements/dry-run", strings.NewReader(string(dryRaw)))
	dryRequest.Header.Set("Content-Type", "application/json")
	dryRequest = dryRequest.WithContext(identity.WithVerifiedPrincipal(dryRequest.Context(), principal))
	dryResponse := httptest.NewRecorder()
	app.ServeHTTP(dryResponse, dryRequest)
	if dryResponse.Code != http.StatusOK || !strings.Contains(dryResponse.Body.String(), "key-good") {
		t.Fatalf("dry-run status=%d body=%s", dryResponse.Code, dryResponse.Body.String())
	}
	dry, err := service.DryRun(context.Background(), dryInput, principal)
	if err != nil || len(dry.SurvivorKeyReferenceIDs) != 1 || dry.SurvivorKeyReferenceIDs[0] != "key-good" || len(dry.Rules) != 5 || len(dry.Objects) != 1 || len(dry.SurvivorBindings) != 1 || dry.SurvivorBindings[0].DependencyDigest != d || dry.MaxWorkObjects != 1 || dry.MaxMutationBytes != 10 || dry.RetainedBytes != 10 {
		t.Fatalf("dry-run=%+v err=%v", dry, err)
	}
	recomputed := store.OffsiteRetirementIntent{GenerationID: dry.GenerationID, PointID: dry.PointID, BucketID: dry.BucketID, RuleSetDigest: dry.RuleSetDigest, SurvivorRuleDigest: dry.SurvivorRuleDigest, ManifestDigest: dry.ManifestDigest, CatalogDigest: dry.CatalogDigest, InventoryDigest: dry.InventoryDigest, OneOwnerProofID: dry.OneOwnerProofID, LockAdminReferenceID: dry.LockAdminReferenceID, LockAdminFingerprint: dry.LockAdminFingerprint, RetentionReferenceID: dry.RetentionReferenceID, RetentionFingerprint: dry.RetentionFingerprint, G008BundleDigest: dry.G008BundleDigest, QualificationDigest: dry.QualificationDigest, PutCutoffDigest: dry.PutCutoffDigest, MultipartCutoffDigest: dry.MultipartCutoffDigest, ExclusiveAdminDigest: dry.ExclusiveAdminDigest, SurvivorPointIDs: append([]string(nil), dry.SurvivorPointIDs...), SourceRevision: dry.SourceRevision, StateRevision: dry.StateRevision, RecoveryEpoch: dry.RecoveryEpoch, MaxWorkObjects: dry.MaxWorkObjects, MaxMutationBytes: dry.MaxMutationBytes, PreRuleCount: int(dry.PreRuleCount), SurvivorRuleCount: int(dry.SurvivorRuleCount)}
	for _, rule := range dry.Rules {
		recomputed.Rules = append(recomputed.Rules, store.OffsiteRetirementRule{RuleID: rule.RuleID, Prefix: rule.Prefix})
	}
	for _, object := range dry.Objects {
		recomputed.Objects = append(recomputed.Objects, store.OffsiteRetirementObject{Key: object.Key, Digest: object.Digest, Bytes: object.Bytes})
	}
	for _, survivor := range dry.SurvivorBindings {
		recomputed.SurvivorKeyReferences = append(recomputed.SurvivorKeyReferences, store.OffsiteRetirementSurvivorKey{PointID: survivor.PointID, GenerationID: survivor.GenerationID, ReferenceID: survivor.ReferenceID, DependencyDigest: survivor.DependencyDigest})
	}
	recomputedDigest, _, err := store.OffsiteRetirementIntentDigests(recomputed)
	if err != nil || recomputedDigest != dry.IntentDigest {
		t.Fatalf("dry-run cannot independently reproduce intent digest: got=%s want=%s err=%v", recomputedDigest, dry.IntentDigest, err)
	}
	stageInput := generated.BackupOffsiteRetirementStageRequest{Schema: generated.SchemaIDBackupOffsiteRetirementStageRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: 7, RecoveryEpoch: 2, TargetDigest: dry.IntentDigest, IdempotencyKey: "retire-a", SelectionDigest: selection, PlanID: "plan-a", PlanDigest: d, OneOwnerProofID: "proof-a", LockAdminReferenceID: "lock-admin", RetentionReferenceID: "retention", CredentialBindingDigest: d}
	stageRaw, _ := json.Marshal(stageInput)
	stageRequest := httptest.NewRequest(http.MethodPost, "/api/v1/backups/offsite-retirements/stage", strings.NewReader(string(stageRaw)))
	stageRequest.Header.Set("Content-Type", "application/json")
	stageRequest = stageRequest.WithContext(identity.WithVerifiedPrincipal(stageRequest.Context(), principal))
	stageResponse := httptest.NewRecorder()
	app.ServeHTTP(stageResponse, stageRequest)
	if stageResponse.Code != http.StatusOK || staged.IntentDigest != dry.IntentDigest || len(staged.SurvivorKeyReferences) != 1 || staged.SurvivorKeyReferences[0].ReferenceID != "key-good" || staged.CredentialBindingDigest != d {
		t.Fatalf("stage status=%d intent=%+v body=%s", stageResponse.Code, staged, stageResponse.Body.String())
	}
}
