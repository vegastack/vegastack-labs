//go:build linux

package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestOffsiteRetirementSchemaRejectsDuplicateLeaseAndCrossIntentReceipt(t *testing.T) {
	db := openCredentialMigrationFixture(t)
	if _, err := db.Exec(`PRAGMA foreign_keys=ON; CREATE TABLE backup_offsite_generations(generation_id TEXT PRIMARY KEY); INSERT INTO backup_offsite_generations VALUES('g1'),('g2')`); err != nil {
		t.Fatal(err)
	}
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(catalog[23].SQL); err != nil {
		t.Fatal(err)
	}
	d := "sha256:" + strings.Repeat("a", 64)
	insertIntent := func(id, g string) {
		t.Helper()
		_, err := db.Exec(`INSERT INTO backup_offsite_retirement_intents(
			intent_id,plan_id,plan_digest,generation_id,point_id,bucket_id,rule_set_digest,survivor_rule_digest,manifest_digest,catalog_digest,inventory_digest,
			one_owner_proof_id,lock_admin_consumer_id,retention_consumer_id,canonical_json,g008_bundle_digest,qualification_digest,put_cutoff_digest,multipart_cutoff_digest,
			exclusive_admin_digest,intent_digest,credential_binding_digest,source_revision,state_revision,recovery_epoch,max_work_objects,max_mutation_bytes,pre_rule_count,survivor_rule_count,created_at)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id, "plan", d, g, "point-"+g, "bucket", d, d, d, d, d, "proof", "lock", "retention", "{}", d, d, d, d, d, d, d, 1, 1, 1, 1, 1, 5, 0, "now")
		if err != nil {
			t.Fatal(err)
		}
	}
	insertIntent("i1", "g1")
	insertIntent("i2", "g2")
	if _, err := db.Exec(`INSERT INTO backup_offsite_retirement_leases VALUES('l1','i1','run','step','executor','ack','human',1,'later','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO backup_offsite_retirement_leases VALUES('l2','i1','run','step','executor','ack','human',1,'later','now')`); err == nil {
		t.Fatal("duplicate lease accepted")
	}
	if _, err := db.Exec(`INSERT INTO backup_offsite_retirement_receipts VALUES('r','i2','l1','verified',?,?,1,'{}','now')`, d, d); err == nil {
		t.Fatal("cross-intent receipt accepted")
	}
}

func TestOffsiteRetirementRepositoryRecomputesVerifiedSettlement(t *testing.T) {
	ctx := context.Background()
	authority, err := Open(ctx, testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authority.Close() })
	if _, err := authority.conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatal(err)
	}
	d := "sha256:" + strings.Repeat("a", 64)
	rules := []OffsiteRetirementRule{{RuleID: "rule-a", Prefix: "critical/generation-target/config"}, {RuleID: "rule-b", Prefix: "critical/generation-target/keys/"}, {RuleID: "rule-c", Prefix: "critical/generation-target/data/"}, {RuleID: "rule-d", Prefix: "critical/generation-target/index/"}, {RuleID: "rule-e", Prefix: "critical/generation-target/snapshots/"}}
	intent := OffsiteRetirementIntent{IntentID: "intent-a", PlanID: "plan-a", PlanDigest: d, GenerationID: "generation-target", PointID: "point-target", BucketID: "bucket-a", RuleSetDigest: d, SurvivorRuleDigest: d, ManifestDigest: d, CatalogDigest: d, InventoryDigest: d, OneOwnerProofID: "proof-owner", LockAdminConsumerID: "lock-admin", RetentionConsumerID: "retention", G008BundleDigest: d, QualificationDigest: d, PutCutoffDigest: d, MultipartCutoffDigest: d, ExclusiveAdminDigest: d, Rules: rules, Objects: []OffsiteRetirementObject{{Key: "data/a", Digest: d, Bytes: 7}}, SurvivorPointIDs: []string{"point-survivor"}, SourceRevision: 1, StateRevision: 1, RecoveryEpoch: 1, MaxWorkObjects: 1, MaxMutationBytes: 7, PreRuleCount: 6, SurvivorRuleCount: 1}
	intent.IntentDigest, intent.CredentialBindingDigest, err = OffsiteRetirementIntentDigests(intent)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	pending, _ := json.Marshal(struct{ RuleDigest, OffsiteInventoryDigest, SourceManifestDigest string }{d, d, d})
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: intent.PlanID, PlanDigest: intent.PlanDigest, DeclarationID: "declaration-a", Binding: generated.PlanBinding{RecoveryEpoch: 1, PriorStateRevision: 0, StateRevision: 1, DeclarationRevision: 1, ObservationFingerprint: d, TargetDigest: intent.IntentDigest, ReasonDigest: d, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-a", OperationType: "backup.retire.offsite", AdapterID: "r2.retention", ExecutorID: "executor-central", TargetID: intent.GenerationID, InputDigest: intent.CredentialBindingDigest, ArtifactDigest: intent.IntentDigest, Idempotent: false}}, Status: "planned", Risk: "destructive", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), ReadableDigest: d, Extensions: []generated.ContractExtension{{Name: "x-backup-offsite-retirement", ValueDigest: intent.IntentDigest}, {Name: "x-credential-bindings", ValueDigest: intent.CredentialBindingDigest}}}
	planBytes, _ := json.Marshal(plan)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO backup_offsite_generations(generation_id,source_point_id,repository_id,offsite_snapshot_id,pending_json,source_revision,state_revision,recovery_epoch,issuance_stopped_at,created_at) VALUES(?,?,?,?,?,1,1,1,?,?)`, []any{"generation-target", "point-target", "repo", strings.Repeat("b", 64), string(pending), now.Format(time.RFC3339), now.Add(-30 * 24 * time.Hour).Format(time.RFC3339)}},
		{`INSERT INTO backup_offsite_generations(generation_id,source_point_id,repository_id,offsite_snapshot_id,pending_json,source_revision,state_revision,recovery_epoch,issuance_stopped_at,created_at) VALUES(?,?,?,?,?,1,1,1,?,?)`, []any{"generation-survivor", "point-survivor", "repo", strings.Repeat("c", 64), string(pending), now.Format(time.RFC3339), now.Format(time.RFC3339)}},
		{`INSERT INTO backup_offsite_proofs(proof_id,proof_digest,generation_id,status,proof_class,proof_json,full_read_at,observed_at,recovery_epoch,created_at) VALUES('proof-survivor',?,'generation-survivor','offsite-verified','qualified-provider','{}',?,?,1,?)`, []any{d, now.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339)}},
		{`INSERT INTO backup_local_verifications(verification_id,proof_digest,point_id,run_id,read_lease_id,status,proof_class,manifest_digest,inventory_digest,observed_digest,content_digest,catalog_digest,dependency_digest,key_reference_id,source_revision,state_revision,recovery_epoch,full_read_at,functional_restored_at,reason_code,created_at) VALUES('verification-survivor',?,'point-survivor','run-v','lease-v','local-verified','live',?,?,?,?,?,?, 'key',1,1,1,?,?,'',?)`, []any{d, d, d, d, d, d, d, now.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339)}},
		{`INSERT INTO backup_offsite_last_good_history(proof_id,generation_id,source_revision,state_revision,recovery_epoch,advanced_at) VALUES('proof-survivor','generation-survivor',1,1,1,?)`, []any{now.Format(time.RFC3339)}},
		{`UPDATE system_meta SET state_revision=1,recovery_epoch=1 WHERE id=1`, nil},
		{`INSERT INTO immutable_plans(plan_id,plan_digest,declaration_id,declaration_revision,state_revision,recovery_epoch,observation_fingerprint,idempotency_key_digest,request_digest,canonical_bytes,readable_plan,readable_digest,created_at,expires_at) VALUES(?,?,?,?,1,1,?,?,?,?,'retirement',?,?,?)`, []any{intent.PlanID, intent.PlanDigest, "declaration-a", 1, d, "sha256:" + strings.Repeat("b", 64), "sha256:" + strings.Repeat("c", 64), planBytes, d, plan.CreatedAt, plan.ExpiresAt}},
	}
	for index, statement := range statements {
		if _, err := authority.conn.ExecContext(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed %d: %v", index, err)
		}
	}
	repository := NewOffsiteRetirementRepository(authority)
	for index, rule := range rules {
		if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_offsite_retention_rules(generation_id,sequence,rule_id,protected_prefix) VALUES('generation-target',?,?,?)`, index+1, rule.RuleID, rule.Prefix); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_offsite_objects(generation_id,sequence,object_key,object_digest,object_bytes) VALUES('generation-target',1,'data/a',?,7)`, d); err != nil {
		t.Fatal(err)
	}
	if id, err := repository.StageOffsiteRetirement(ctx, intent); err != nil || id != intent.IntentID {
		t.Fatalf("stage = %q, %v", id, err)
	}
	if _, err := authority.conn.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_leases(lease_id,intent_id,run_id,step_id,executor_lease_id,acknowledgement_id,human_id,recovery_epoch,maximum_expires_at,acquired_at) VALUES('lease-a','intent-a','run-a','step-a','executor-a','ack-a','human-a',1,?,?)`, now.Add(time.Hour).Format(time.RFC3339), now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := repository.AppendReceipt(ctx, OffsiteRetirementReceipt{ReceiptID: "forged", IntentID: intent.IntentID, LeaseID: "lease-a", Status: "verified", EffectDigest: d, SurvivorProofDigest: d, ReclaimedBytes: 7, CanonicalJSON: []byte(`{}`)}); err == nil {
		t.Fatal("generic verified receipt accepted")
	}
	attempts := []OffsiteRetirementAttempt{
		{AttemptID: "a1", LeaseID: "lease-a", Sequence: 1, Kind: "rule-put", Target: "bucket-a", RequestDigest: d, Status: "attempted"},
		{AttemptID: "a2", LeaseID: "lease-a", Sequence: 2, Kind: "rule-put", Target: "bucket-a", RequestDigest: d, Status: "observed", ResponseDigest: d},
		{AttemptID: "a3", LeaseID: "lease-a", Sequence: 3, Kind: "object-delete", Target: "data/a", RequestDigest: offsiteDigestParts("delete", "data/a", d, "7"), Status: "attempted"},
		{AttemptID: "a4", LeaseID: "lease-a", Sequence: 4, Kind: "object-delete", Target: "data/a", RequestDigest: offsiteDigestParts("delete", "data/a", d, "7"), Status: "observed", ResponseDigest: d},
	}
	for _, attempt := range attempts {
		if err := repository.AppendAttempt(ctx, attempt); err != nil {
			t.Fatal(err)
		}
	}
	receipt, err := repository.SettleVerifiedReceipt(ctx, OffsiteRetirementVerifiedSettlement{ReceiptID: "receipt-a", IntentID: intent.IntentID, LeaseID: "lease-a", ReclaimedBytes: 7, Survivors: []OffsiteRetirementSurvivorSettlement{{PointID: "point-survivor", GenerationID: "generation-survivor", RuleDigest: d, InventoryDigest: d, FullReadDigest: d, RestoreDigest: d, RecoveryEpoch: 1, ObservedAt: now}}})
	if err != nil || receipt.Status != "verified" || receipt.EffectDigest == d {
		t.Fatalf("settlement = %#v, %v", receipt, err)
	}
	if ok, err := repository.VerifiedReceiptExists(ctx, "generation-target", receipt.EffectDigest); err != nil || !ok {
		t.Fatalf("verified receipt lookup = %v, %v", ok, err)
	}
}
