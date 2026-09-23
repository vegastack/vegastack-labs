//go:build linux

package localbackup

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/backup"
)

func TestProtectedLocalTrustOnlyProvesCurrentPinnedDependencies(t *testing.T) {
	catalog := "sha256:" + strings.Repeat("a", 64)
	base := DependencyTrustRequest{PointID: "point-a", PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		ResticDigest: pinnedResticDigest(), CatalogDigest: catalog, StateRevision: 7, RecoveryEpoch: 2,
		Expected: []backup.ExpectedDependency{{DependencyID: "restic", Kind: "binary", Digest: pinnedResticDigest()},
			{DependencyID: "catalog", Kind: "schema", Digest: catalog}}}
	verifier := NewProtectedLocalDependencyTrust()
	evidence, err := verifier.VerifyCurrent(context.Background(), base)
	if err != nil || !exactDependencyTrust(base.Expected, evidence, 7, 2) {
		t.Fatalf("current protected pins rejected: evidence=%#v err=%v", evidence, err)
	}
	for _, kind := range []string{"config", "image", "signature"} {
		request := base
		request.Expected = append([]backup.ExpectedDependency(nil), base.Expected...)
		request.Expected = append(request.Expected, backup.ExpectedDependency{DependencyID: kind, Kind: kind, Digest: catalog})
		if _, err := verifier.VerifyCurrent(context.Background(), request); err == nil {
			t.Fatalf("%s historical digest became current trust", kind)
		}
	}
	wrong := base
	wrong.Expected = []backup.ExpectedDependency{{DependencyID: "restic", Kind: "binary", Digest: catalog}}
	if _, err := verifier.VerifyCurrent(context.Background(), wrong); err == nil {
		t.Fatal("wrong binary digest became current trust")
	}
	stale := append([]DependencyTrustEvidence(nil), evidence...)
	stale[0].RecoveryEpoch++
	if exactDependencyTrust(base.Expected, stale, 7, 2) {
		t.Fatal("stale epoch evidence satisfied current trust")
	}
	forged := append([]DependencyTrustEvidence(nil), evidence...)
	forged[0].SourceKind = "manifest-claim"
	if exactDependencyTrust(base.Expected, forged, 7, 2) {
		t.Fatal("manifest claim satisfied current trust")
	}
}
