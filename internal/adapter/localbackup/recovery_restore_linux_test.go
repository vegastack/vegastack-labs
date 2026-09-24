//go:build linux

package localbackup

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/ncruces/go-sqlite3/driver"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type recoveryExpectationStub struct{ value store.SnapshotExpectation }

func (stub recoveryExpectationStub) CurrentExpectation(context.Context) (store.SnapshotExpectation, error) {
	return stub.value, nil
}
func (recoveryExpectationStub) OnlineSnapshot(context.Context, store.OnlineSnapshotRequest) (store.OnlineSnapshotResult, error) {
	return store.OnlineSnapshotResult{}, nil
}

func TestRecoveryCompatibilityRequiresCurrentPinnedDependencyFacts(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	catalog := "sha256:" + strings.Repeat("b", 64)
	dependencies := []backup.ExpectedDependency{{DependencyID: "restic", Kind: "binary", Digest: pinnedResticDigest()}, {DependencyID: "catalog", Kind: "schema", Digest: catalog}}
	manifest := backup.CreationManifest{PointID: "point-a", PolicyDigest: digest, KeyReferenceID: "key-a", ResticDigest: pinnedResticDigest(), PlatformDigest: platformDigest(), CatalogDigest: catalog, DependencyInventoryDigest: backup.ExpectedDependencyInventoryDigest(dependencies), ExpectedDependencies: dependencies}
	raw, _ := jsonMarshal(manifest)
	source := store.LocalRecoverySource{Point: store.PendingRecoveryPoint{PointID: "point-a", PolicyDigest: digest, ManifestJSON: raw}, Verification: store.LocalVerificationReceipt{StateRevision: 7, RecoveryEpoch: 2, DependencyTrust: []store.BackupDependencyTrustEvidence{{DependencyID: "restic", Kind: "binary", Digest: pinnedResticDigest()}, {DependencyID: "catalog", Kind: "schema", Digest: catalog}}}, KeyReferenceID: "key-a", CatalogDigest: catalog, DependencyDigest: manifest.DependencyInventoryDigest, DatabaseSchemaVersion: 21}
	verifier := RecoveryCompatibilityVerifier{config: RecoveryRestoreConfig{Trust: NewProtectedLocalDependencyTrust(), Expectations: recoveryExpectationStub{store.SnapshotExpectation{SchemaVersion: 21, CatalogSHA256: digestBytes(catalog)}}}}
	selection := recovery.SourceSelection{TargetReleaseBuildID: "build-a", TargetToolVersion: "1.0.0", TargetSchemaVersion: "21"}
	if err := verifier.VerifyRestoreCompatibility(context.Background(), selection, source); err != nil {
		t.Fatal(err)
	}
	altered := source
	altered.Verification.DependencyTrust = append([]store.BackupDependencyTrustEvidence(nil), source.Verification.DependencyTrust...)
	altered.Verification.DependencyTrust[0].Digest = catalog
	if err := verifier.VerifyRestoreCompatibility(context.Background(), selection, altered); err == nil {
		t.Fatal("mismatched plan-bound dependency accepted")
	}
	source.KeyReferenceID = "other-key"
	if err := verifier.VerifyRestoreCompatibility(context.Background(), selection, source); err == nil {
		t.Fatal("unbound key reference accepted")
	}
}

func TestReadRestoredAuditPositionRequiresIndependentAnchorAtHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restored.sqlite")
	u := url.URL{Scheme: "file", Path: path}
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	key, verified := "key-a", time.Now().UTC().Format(time.RFC3339)
	checkpoint := generated.AuditCheckpoint{Schema: generated.SchemaIDAuditCheckpoint, SchemaVersion: "1.1.0", CheckpointID: "checkpoint-a", FirstEventID: 1, LastEventID: 1, ChainDigest: digest, InstanceID: "instance-audit", FirstSegmentSequence: 1, LastSegmentSequence: 1, SignerReferenceID: "signer-a", SignerMaterialVersion: "version-a", SignatureDigest: &digest, PublicKeyID: &key, ExportReceiptDigest: &digest, IndependentReadDigest: &digest, Status: "anchored", ReasonCode: "independent-match", IndependentCopyDigest: &digest, SourceKind: "independent", ProofClass: "live", VerifiedAt: &verified, VerificationStatus: "verified", RecoveryEpoch: 0}
	raw, _ := json.Marshal(checkpoint)
	statements := []struct {
		query string
		args  []any
	}{
		{query: `CREATE TABLE audit_chain_links(event_id INTEGER PRIMARY KEY)`},
		{query: `CREATE TABLE audit_checkpoints(last_event_id INTEGER,status TEXT,independent_read_digest TEXT,canonical_bytes BLOB)`},
		{query: `INSERT INTO audit_chain_links VALUES(1)`},
		{query: `INSERT INTO audit_checkpoints VALUES(1,'anchored',?,?)`, args: []any{digest, raw}},
	}
	for _, statement := range statements {
		if _, err = db.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := readRestoredAuditPosition(context.Background(), path)
	if err != nil || got.LocalLastEventID != 1 || got.IndependentLastEventID != 1 {
		t.Fatalf("position=%#v err=%v", got, err)
	}
	db, err = sql.Open("sqlite3", u.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO audit_chain_links VALUES(2)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := readRestoredAuditPosition(context.Background(), path); err == nil {
		t.Fatal("unanchored restored audit head accepted")
	}
}

func jsonMarshal(value any) ([]byte, error) { return json.Marshal(value) }
