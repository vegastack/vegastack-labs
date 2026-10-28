package server

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/adapter/ociregistry"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/release"
	"github.com/vegastack/vegastack-labs/internal/store"
)

//go:embed testdata/ci-publication/request.json
var publicationEvidenceFixture []byte

func publicationCandidateFixture(t *testing.T, path string) ([]byte, release.BuildEvidenceRequest) {
	t.Helper()
	var evidence release.BuildEvidenceRequest
	if e := json.Unmarshal(publicationEvidenceFixture, &evidence); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(ciPublicationCandidate{Evidence: evidence, Blobs: []ciPublicationBlob{{Digest: hostaction.BytesDigest([]byte("{}")), Size: 2, Path: path}}})
	if e != nil {
		t.Fatal(e)
	}
	return raw, evidence
}
func TestCIPublicationCandidateUsesActualSignaturesAndExactSource(t *testing.T) {
	for _, fault := range []string{"none", "unsigned", "source", "invocation", "digest", "blob"} {
		t.Run(fault, func(t *testing.T) {
			raw, _ := publicationCandidateFixture(t, "/protected/config")
			var v ciPublicationCandidate
			json.Unmarshal(raw, &v)
			if fault == "unsigned" {
				v.Evidence.SBOMBundle = nil
			}
			if fault == "source" {
				v.Evidence.Expected.SourceRevision = strings.Repeat("b", 40)
			}
			if fault == "invocation" {
				v.Evidence.Expected.InvocationID = "https://wrong.invalid/jobs/70"
			}
			raw, _ = json.Marshal(v)
			x := store.CIPublicationExecution{Source: store.CIPublicationSource{Repository: "owner/repo", Revision: strings.Repeat("a", 40), RunID: "60", JobID: "70", Attempt: 2}}
			x.Binding.CandidatePath = "/protected/candidate"
			x.Binding.CandidateDigest = hostaction.BytesDigest(raw)
			x.Binding.Repository = "team/app"
			if fault == "digest" {
				x.Binding.CandidateDigest = hostaction.Digest("wrong")
			}
			c := &ciPublicationComposition{read: func(_ context.Context, path string, _ uint32, _ int64) ([]byte, error) {
				if path == "/protected/candidate" {
					return raw, nil
				}
				if fault == "blob" {
					return []byte("bad"), nil
				}
				return []byte("{}"), nil
			}}
			q, e := c.candidate(context.Background(), x)
			if fault == "none" {
				if e != nil || q.Publication.Digest != q.Evidence.Expected.ImageDigest {
					t.Fatal(q, e)
				}
			} else if e == nil {
				t.Fatal("unverified candidate accepted", fault)
			}
		})
	}
}
func publicationRegistryFixture(t *testing.T, before func(*http.Request)) (*ociregistry.Client, string, *atomic.Int32) {
	t.Helper()
	writes := &atomic.Int32{}
	var manifest []byte
	var blob []byte
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if before != nil {
			before(r)
		}
		if r.Header.Get("Authorization") != "Bearer publication-synthetic" {
			t.Error("publication-only credential missing")
			w.WriteHeader(401)
			return
		}
		prefix := "/v2/team/app/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			t.Error("publication escaped repository", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		tail := strings.TrimPrefix(r.URL.Path, prefix)
		switch {
		case r.Method == "HEAD" && strings.HasPrefix(tail, "blobs/"):
			if blob == nil {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Docker-Content-Digest", hostaction.BytesDigest(blob))
			w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
			w.WriteHeader(200)
		case r.Method == "POST" && tail == "blobs/uploads/":
			writes.Add(1)
			w.Header().Set("Location", prefix+"blobs/uploads/owned")
			w.WriteHeader(202)
		case r.Method == "PUT" && tail == "blobs/uploads/owned":
			writes.Add(1)
			blob, _ = io.ReadAll(r.Body)
			if r.URL.Query().Get("digest") != hostaction.BytesDigest(blob) {
				t.Error("blob digest")
			}
			w.Header().Set("Docker-Content-Digest", hostaction.BytesDigest(blob))
			w.WriteHeader(201)
		case r.Method == "PUT" && strings.HasPrefix(tail, "manifests/"):
			writes.Add(1)
			manifest, _ = io.ReadAll(r.Body)
			w.Header().Set("Docker-Content-Digest", hostaction.BytesDigest(manifest))
			w.WriteHeader(201)
		case r.Method == "GET" && strings.HasPrefix(tail, "manifests/"):
			w.Header().Set("Docker-Content-Digest", hostaction.BytesDigest(manifest))
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Content-Length", strconv.Itoa(len(manifest)))
			w.Write(manifest)
		default:
			t.Error("unexpected registry route", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(s.Close)
	c, e := ociregistry.NewClient(s.URL, s.Client().Transport)
	if e != nil {
		t.Fatal(e)
	}
	return c, s.URL, writes
}
func TestPublicationFixtureIsRealSignedOCI(t *testing.T) {
	raw, evidence := publicationCandidateFixture(t, "/protected/config")
	if !bytes.Contains(raw, []byte("Evidence")) {
		t.Fatal("missing protected evidence")
	}
	if _, e := release.VerifyBuildEvidenceBytes(context.Background(), evidence); e != nil {
		t.Fatal(e)
	}
}

func TestCIPublicationVerificationUsesSealedOperationAfterCredentialClose(t *testing.T) {
	op := adapter.Operation{OperationID: "publication", InputDigest: hostaction.Digest("manifest"), SecretReferences: []adapter.SecretReference{{ID: "publication-key", Consumer: store.CIPublicationAdapter}}}
	effect := adapter.Effect{Status: "succeeded", ResultDigest: hostaction.Digest("result"), EffectObserved: true, Changed: true}
	c := &ciPublicationComposition{results: map[string]ciPublicationEffect{ciPublicationVerificationKey(op, effect.ResultDigest): {effect: effect, receipt: ociregistry.VerifiedPublishReceipt{Publication: ociregistry.PublishReceipt{Verified: true}}, digest: effect.ResultDigest}}}
	op.SecretReferences = nil
	if v, e := c.Verify(context.Background(), op, effect); e != nil || !v.Verified {
		t.Fatal("JIT references changed verification identity", v, e)
	}
	if _, e := c.Verify(context.Background(), op, effect); e == nil {
		t.Fatal("verification receipt replayed")
	}
}
