package server

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/release"
	"github.com/vegastack/vegastack-labs/internal/store"
	"testing"
)

func manualPublicationFixture(t *testing.T, path string) ([]byte, release.BuildEvidenceRequest) {
	t.Helper()
	var e release.BuildEvidenceRequest
	if err := json.Unmarshal(publicationEvidenceFixture, &e); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(manualPublicationCandidate{Manifest: e.Manifest, Bundle: e.ProvenanceBundle, Blobs: []manualPublicationBlob{{Digest: hostaction.BytesDigest([]byte("{}")), Size: 2, Path: path}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw, e
}
func TestManualPublicationCandidateUsesIndependentTrustAndRealSignature(t *testing.T) {
	for _, fault := range []string{"none", "unsigned", "candidate-digest", "manifest-digest", "policy-digest", "wrong-identity", "blob", "candidate-trust"} {
		t.Run(fault, func(t *testing.T) {
			raw, e := manualPublicationFixture(t, "/protected/blob")
			policy := e.Policy
			var v manualPublicationCandidate
			json.Unmarshal(raw, &v)
			if fault == "unsigned" {
				v.Bundle = nil
				raw, _ = json.Marshal(v)
			}
			if fault == "wrong-identity" {
				var p map[string]any
				json.Unmarshal(policy, &p)
				p["certificateIdentity"] = "wrong@example.invalid"
				policy, _ = json.Marshal(p)
			}
			if fault == "candidate-trust" {
				var p map[string]any
				json.Unmarshal(raw, &p)
				p["Policy"] = e.Policy
				raw, _ = json.Marshal(p)
			}
			x := store.ManualPublicationExecution{}
			x.Binding.CandidatePath = "/protected/candidate"
			x.Binding.CandidateDigest = hostaction.BytesDigest(raw)
			x.Binding.TrustPolicyPath = "/protected/policy"
			x.Binding.TrustPolicyDigest = hostaction.BytesDigest(policy)
			x.Binding.ImageDigest = e.Expected.ImageDigest
			x.Binding.Repository = "team/app"
			if fault == "candidate-digest" {
				x.Binding.CandidateDigest = hostaction.Digest("wrong")
			}
			if fault == "manifest-digest" {
				x.Binding.ImageDigest = hostaction.Digest("wrong")
			}
			if fault == "policy-digest" {
				x.Binding.TrustPolicyDigest = hostaction.Digest("wrong")
			}
			c := &manualPublicationComposition{read: func(_ context.Context, path string, _ uint32, _ int64) ([]byte, error) {
				switch path {
				case x.Binding.CandidatePath:
					return raw, nil
				case x.Binding.TrustPolicyPath:
					return policy, nil
				default:
					if fault == "blob" {
						return []byte("bad"), nil
					}
					return []byte("{}"), nil
				}
			}}
			q, err := c.candidate(context.Background(), x)
			if fault == "none" {
				if err != nil || q.Digest != x.Binding.ImageDigest {
					t.Fatal(q, err)
				}
			} else if err == nil {
				t.Fatal("unverified manual candidate accepted", fault)
			}
		})
	}
}
