//go:build linux

package store

import (
	"strings"
	"testing"
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
