package release

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyOCIAuthenticatesManifestBytes(t *testing.T) {
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2},"layers":[]}`)
	f := newSyntheticFixture(t, syntheticFixtureOptions{artifact: manifest})
	dir := t.TempDir()
	m, b, p := filepath.Join(dir, "image.json"), filepath.Join(dir, "bundle.json"), filepath.Join(dir, "policy.json")
	policy, err := json.Marshal(f.policy)
	if err != nil {
		t.Fatal(err)
	}
	for path, raw := range map[string][]byte{m: manifest, b: f.bundleJSON, p: policy} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	proof, err := VerifyOCI(context.Background(), m, b, p, hashOCI(manifest))
	if err != nil {
		t.Fatal(err)
	}
	if proof.ManifestDigest != hashOCI(manifest) || proof.BundleDigest != hashOCI(f.bundleJSON) || proof.PolicyDigest != hashOCI(policy) {
		t.Fatal("proof does not bind verified bytes")
	}
	t.Run("digest-mismatch", func(t *testing.T) {
		if _, err := VerifyOCI(context.Background(), m, b, p, hashOCI([]byte("wrong"))); err == nil {
			t.Fatal("accepted wrong digest")
		}
	})
	t.Run("digest-text-signature-is-not-manifest-signature", func(t *testing.T) {
		other := newSyntheticFixture(t, syntheticFixtureOptions{artifact: []byte(hashOCI(manifest))})
		otherPolicy, _ := json.Marshal(other.policy)
		if err := os.WriteFile(b, other.bundleJSON, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, otherPolicy, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyOCI(context.Background(), m, b, p, hashOCI(manifest)); err == nil {
			t.Fatal("digest text accepted as image signature")
		}
	})
}
