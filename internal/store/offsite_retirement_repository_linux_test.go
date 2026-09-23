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
		_, err := db.Exec(`INSERT INTO backup_offsite_retirement_intents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, "plan", d, g, "point-"+g, "bucket", d, d, d, d, d, "proof", "lock", "retention", "{}", 1, 1, 1, 1, 1, 5, 0, "now")
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
