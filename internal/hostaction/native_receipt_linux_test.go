//go:build linux

package hostaction

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeExecutionObservationRequiresExistingExactClaimAndResult(t *testing.T) {
	bundle, _, _, _ := fixtureBundle(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	receipts, err := OpenReceipts(root, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer receipts.Close()
	if _, err = receipts.inspectExecution(bundle); err == nil {
		t.Fatal("missing claim accepted")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("read observation created state")
	}
	digest, _ := BundleDigest(bundle)
	key := ExecutionDigest(bundle)
	if err = receipts.ClaimExecution(key, digest); err != nil {
		t.Fatal(err)
	}
	if _, err = receipts.inspectExecution(bundle); err == nil {
		t.Fatal("unfinished claim accepted")
	}
	result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: digest, ResultDigest: Digest("actual result"), Status: "succeeded", Changed: true, EffectObserved: true, Reason: "verified"}
	if err = receipts.FinishExecution(key, digest, result); err != nil {
		t.Fatal(err)
	}
	before, err := receipts.inspectExecution(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if before.ExecutionDigest != key || before.BundleDigest != digest || before.Status != "succeeded" {
		t.Fatal("observation binding lost")
	}
	if err = receipts.ClaimExecution(key, digest); err == nil {
		t.Fatal("replay claim accepted")
	}
	after, err := receipts.inspectExecution(bundle)
	if err != nil || after != before {
		t.Fatal("refusal changed immutable claim/result")
	}
	path := filepath.Join(root, key[7:]+".json")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, append(bytes[:len(bytes)-1], []byte(`,"status":"claimed"}`)...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = receipts.inspectExecution(bundle); err == nil {
		t.Fatal("ambiguous duplicate claim accepted")
	}
}
