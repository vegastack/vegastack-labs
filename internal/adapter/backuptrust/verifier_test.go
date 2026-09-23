package backuptrust

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter/localbackup"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type fixtureCatalog struct{ source store.BackupTrustSourceDraft }

func (catalog fixtureCatalog) GetCurrentBackupTrustSourceForDependency(_ context.Context, dependencyID, kind string, revision, epoch int64) (store.BackupTrustSourceDraft, error) {
	if catalog.source.DependencyID != dependencyID || catalog.source.DependencyKind != kind || revision != 7 || epoch != 2 {
		return store.BackupTrustSourceDraft{}, context.Canceled
	}
	return catalog.source, nil
}

type fixtureReader struct {
	artifact, bundle, root []byte
	observed               string
}

func (reader fixtureReader) OpenRegistered(_ context.Context, _, _ string, _ int64) (io.ReadCloser, []byte, []byte, string, error) {
	return io.NopCloser(bytes.NewReader(reader.artifact)), append([]byte(nil), reader.bundle...), append([]byte(nil), reader.root...), reader.observed, nil
}

func fixtureDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestBackupTrustRejectsWrongRootAndStaleArtifact(t *testing.T) {
	root := filepath.Join("..", "..", "release", "testdata")
	artifact, err := os.ReadFile(filepath.Join(root, "release-valid", "artifacts", "vsk-labs"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(filepath.Join(root, "release-valid", "artifacts", "vsk-labs.sigstore.json"))
	if err != nil {
		t.Fatal(err)
	}
	policyRaw, err := os.ReadFile(filepath.Join(root, "policy-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy generated.ReleaseTrustPolicy
	if err := json.Unmarshal(policyRaw, &policy); err != nil {
		t.Fatal(err)
	}
	source := store.BackupTrustSourceDraft{
		SourceID: "source-config-a", DependencyID: "config-a", DependencyKind: "config", ArtifactID: "artifact-config-a",
		ArtifactDigest: fixtureDigest(artifact), BundleDigest: fixtureDigest(bundle), TrustedRootReferenceID: "root-a",
		TrustRootDigest: fixtureDigest(policy.TrustedRoot), SignerIdentity: policy.CertificateIdentity, SignerIssuer: policy.OIDCIssuer,
		Revision: 1, RecoveryEpoch: 2, StateRevision: 7,
	}
	reader := fixtureReader{artifact: artifact, bundle: bundle, root: policy.TrustedRoot, observed: source.ArtifactDigest}
	request := localbackup.DependencyTrustRequest{PointID: "point-a", PolicyDigest: fixtureDigest([]byte("policy")), StateRevision: 7, RecoveryEpoch: 2,
		Expected: []backup.ExpectedDependency{{DependencyID: "config-a", Kind: "config", Digest: source.ArtifactDigest}}}
	verifier := NewVerifier(fixtureCatalog{source: source}, reader, nil)
	evidence, err := verifier.VerifyCurrent(context.Background(), request)
	if err != nil || len(evidence) != 1 || evidence[0].SourceID != source.SourceID || evidence[0].PointID != request.PointID {
		t.Fatalf("valid current signature rejected: evidence=%#v err=%v", evidence, err)
	}

	wrongRoot := reader
	wrongRoot.root = append([]byte(nil), reader.root...)
	wrongRoot.root[len(wrongRoot.root)/2] ^= 1
	if _, err := NewVerifier(fixtureCatalog{source: source}, wrongRoot, nil).VerifyCurrent(context.Background(), request); err == nil {
		t.Fatal("wrong root accepted")
	}
	changed := reader
	changed.artifact = append(append([]byte(nil), artifact...), 'x')
	if _, err := NewVerifier(fixtureCatalog{source: source}, changed, nil).VerifyCurrent(context.Background(), request); err == nil {
		t.Fatal("changed artifact accepted")
	}
}
