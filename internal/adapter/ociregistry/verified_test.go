package ociregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/release"
)

func verifiedImage(t *testing.T) VerifiedPublishRequest {
	t.Helper()
	raw, err := os.ReadFile("testdata/verified-candidate/request.json")
	if err != nil {
		t.Fatal(err)
	}
	var evidence release.BuildEvidenceRequest
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	config := []byte("{}")
	return VerifiedPublishRequest{Evidence: evidence, Publication: PublishRequest{Repository: "team/app", Digest: evidence.Expected.ImageDigest, Manifest: bytes.Clone(evidence.Manifest), Blobs: []Blob{{Digest: sum(config), Size: 2, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(config)), nil }}}, Check: func() error { return nil }}}
}
func TestPublishVerifiedCandidate(t *testing.T) {
	c, f, v := fixture(t)
	q := verifiedImage(t)
	out, err := c.PublishVerified(context.Background(), q, v)
	if err != nil || !out.Publication.Verified || out.Evidence.ImageDigest != q.Publication.Digest || out.Evidence.PackageCount != 1 || !bytes.Equal(f.manifest, q.Publication.Manifest) {
		t.Fatal(out, err)
	}
}
func TestPublishVerifiedRejectsEvidenceBeforeNetwork(t *testing.T) {
	cases := map[string]func(*VerifiedPublishRequest){
		"source":         func(q *VerifiedPublishRequest) { q.Evidence.Expected.SourceRevision = strings.Repeat("b", 40) },
		"builder":        func(q *VerifiedPublishRequest) { q.Evidence.Expected.BuilderID = "https://wrong.invalid" },
		"manifest":       func(q *VerifiedPublishRequest) { q.Publication.Manifest = append(q.Publication.Manifest, ' ') },
		"missing-bundle": func(q *VerifiedPublishRequest) { q.Evidence.SBOMBundle = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, f, v := fixture(t)
			q := verifiedImage(t)
			change(&q)
			if _, err := c.PublishVerified(context.Background(), q, v); err == nil || len(f.calls) != 0 {
				t.Fatalf("unverified candidate reached network: %v %v", err, f.calls)
			}
		})
	}
}
func TestPublishVerifiedRetainsAuthorityAndUncertainStage(t *testing.T) {
	t.Run("revocation", func(t *testing.T) {
		c, f, v := fixture(t)
		q := verifiedImage(t)
		q.Publication.Check = func() error { return errors.New("synthetic revocation") }
		if _, err := c.PublishVerified(context.Background(), q, v); err == nil || len(f.calls) != 0 {
			t.Fatal("revoked publication reached registry")
		}
	})
	t.Run("lost-response", func(t *testing.T) {
		c, f, v := fixture(t)
		f.lost = true
		q := verifiedImage(t)
		out, err := c.PublishVerified(context.Background(), q, v)
		if err == nil || out.Publication.Stage != "blob_upload_attempted" || out.Publication.Verified || len(f.calls) != 3 || out.Evidence.ImageDigest != q.Publication.Digest {
			t.Fatal(out, err, f.calls)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		c, f, v := fixture(t)
		q := verifiedImage(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := c.PublishVerified(ctx, q, v); err == nil || len(f.calls) != 0 {
			t.Fatal("cancelled verification reached network")
		}
	})
}

func TestPublishVerifiedRejectsSignedWrongPackage(t *testing.T) {
	c, f, v := fixture(t)
	q := verifiedImage(t)
	raw, err := os.ReadFile("testdata/verified-candidate/request-wrong-package.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &q.Evidence); err != nil {
		t.Fatal(err)
	}
	out, err := c.PublishVerified(context.Background(), q, v)
	if err == nil || len(f.calls) != 0 || out.Publication.Verified {
		t.Fatal("valid signature with wrong package checksum reached registry", out, err, f.calls)
	}
}
