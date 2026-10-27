package release

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildStatements(t *testing.T) ([]byte, BuildExpectation, map[string]any, map[string]any) {
	t.Helper()
	manifest := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}`)
	expected := BuildExpectation{ImageDigest: hashOCI(manifest), SourceURI: "git+https://example.invalid/team/app@refs/heads/main", SourceRevision: strings.Repeat("a", 40), BuilderID: "https://builder.example.invalid/v1", BuildType: "https://build.example.invalid/oci/v1", InvocationID: "https://build.example.invalid/jobs/123/attempts/1", ExternalParameters: json.RawMessage(`{"ref":"refs/heads/main"}`)}
	statement := func(kind string, predicate any) map[string]any {
		return map[string]any{"_type": "https://in-toto.io/Statement/v1", "subject": []any{map[string]any{"name": "team/app", "digest": map[string]string{"sha256": strings.TrimPrefix(expected.ImageDigest, "sha256:")}}}, "predicateType": kind, "predicate": predicate}
	}
	provenance := statement("https://slsa.dev/provenance/v1", map[string]any{"buildDefinition": map[string]any{"buildType": expected.BuildType, "externalParameters": map[string]any{"ref": "refs/heads/main"}, "resolvedDependencies": []any{map[string]any{"uri": expected.SourceURI, "digest": map[string]string{"gitCommit": expected.SourceRevision}}}}, "runDetails": map[string]any{"builder": map[string]any{"id": expected.BuilderID}, "metadata": map[string]any{"invocationId": expected.InvocationID}}})
	sbom := statement("https://spdx.dev/Document/v2.3", map[string]any{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "image inventory", "documentNamespace": "https://sbom.example.invalid/doc/123", "creationInfo": map[string]any{"created": "2026-10-27T00:00:00Z", "creators": []string{"Tool: synthetic-fixture-1"}}, "packages": []any{map[string]any{"SPDXID": "SPDXRef-image", "name": "team/app", "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "checksums": []any{map[string]any{"algorithm": "SHA256", "checksumValue": strings.TrimPrefix(expected.ImageDigest, "sha256:")}}}}, "relationships": []any{map[string]any{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-image"}}})
	return manifest, expected, provenance, sbom
}
func signedBuild(t *testing.T, mutate func(map[string]any, map[string]any)) BuildEvidenceRequest {
	t.Helper()
	manifest, expected, provenance, sbom := buildStatements(t)
	if mutate != nil {
		mutate(provenance, sbom)
	}
	p, _ := json.Marshal(provenance)
	s, _ := json.Marshal(sbom)
	return signBuildStatements(t, manifest, expected, p, s)
}
func signBuildStatements(t *testing.T, manifest []byte, expected BuildExpectation, p, s []byte) BuildEvidenceRequest {
	t.Helper()
	pf := newSyntheticFixture(t, syntheticFixtureOptions{artifact: manifest, statement: p})
	sf := newSyntheticFixture(t, syntheticFixtureOptions{artifact: manifest, statement: s})
	var pr, sr map[string]json.RawMessage
	_ = json.Unmarshal(pf.policy.TrustedRoot, &pr)
	_ = json.Unmarshal(sf.policy.TrustedRoot, &sr)
	for key, value := range sr {
		var a, b []json.RawMessage
		if json.Unmarshal(value, &b) == nil && json.Unmarshal(pr[key], &a) == nil {
			pr[key], _ = json.Marshal(append(a, b...))
		}
	}
	pf.policy.TrustedRoot, _ = json.Marshal(pr)
	policy, _ := json.Marshal(pf.policy)
	return BuildEvidenceRequest{Manifest: manifest, ProvenanceBundle: pf.bundleJSON, SBOMBundle: sf.bundleJSON, Policy: policy, Expected: expected}
}
func TestBuildEvidenceAuthenticatesStandardClaims(t *testing.T) {
	q := signedBuild(t, nil)
	proof, err := VerifyBuildEvidenceBytes(context.Background(), q)
	if err != nil || proof.ImageDigest != q.Expected.ImageDigest || proof.PackageCount != 1 || proof.SourceRevision != q.Expected.SourceRevision {
		t.Fatal(proof, err)
	}
}
func TestBuildEvidenceRejectsValidlySignedWrongClaims(t *testing.T) {
	cases := map[string]func(map[string]any, map[string]any){
		"invocation": func(p, s map[string]any) {
			p["predicate"].(map[string]any)["runDetails"].(map[string]any)["metadata"].(map[string]any)["invocationId"] = "https://wrong.invalid/run"
		},
		"build-type": func(p, s map[string]any) {
			p["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["buildType"] = "https://wrong.invalid/type"
		},
		"duplicate-source": func(p, s map[string]any) {
			d := p["predicate"].(map[string]any)["buildDefinition"].(map[string]any)
			deps := d["resolvedDependencies"].([]any)
			d["resolvedDependencies"] = append(deps, deps[0])
		},
		"predicate-type": func(p, s map[string]any) { p["predicateType"] = "https://wrong.invalid/type" },
		"subject": func(p, s map[string]any) {
			s["subject"].([]any)[0].(map[string]any)["digest"] = map[string]string{"sha256": strings.Repeat("b", 64)}
		},
		"empty-packages": func(p, s map[string]any) { s["predicate"].(map[string]any)["packages"] = []any{} },
		"duplicate-package": func(p, s map[string]any) {
			d := s["predicate"].(map[string]any)
			pkgs := d["packages"].([]any)
			d["packages"] = append(pkgs, pkgs[0])
		},
		"missing-files-analyzed": func(p, s map[string]any) {
			delete(s["predicate"].(map[string]any)["packages"].([]any)[0].(map[string]any), "filesAnalyzed")
		},
		"file-inventory": func(p, s map[string]any) {
			s["predicate"].(map[string]any)["packages"].([]any)[0].(map[string]any)["filesAnalyzed"] = true
		},
		"license":   func(p, s map[string]any) { s["predicate"].(map[string]any)["dataLicense"] = "wrong" },
		"namespace": func(p, s map[string]any) { s["predicate"].(map[string]any)["documentNamespace"] = "not a URI" },
		"created": func(p, s map[string]any) {
			s["predicate"].(map[string]any)["creationInfo"].(map[string]any)["created"] = "yesterday"
		},
		"relationship-type": func(p, s map[string]any) {
			s["predicate"].(map[string]any)["relationships"].([]any)[0].(map[string]any)["relationshipType"] = "nonsense"
		},
		"case-alias-override": func(p, s map[string]any) {
			d := p["predicate"].(map[string]any)["buildDefinition"].(map[string]any)
			d["BuildType"] = d["buildType"]
			d["buildType"] = "https://wrong.invalid/type"
		},
		"builder": func(p, s map[string]any) {
			p["predicate"].(map[string]any)["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = "wrong"
		},
		"source": func(p, s map[string]any) {
			p["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["resolvedDependencies"].([]any)[0].(map[string]any)["digest"] = map[string]string{"gitCommit": strings.Repeat("b", 40)}
		},
		"parameters": func(p, s map[string]any) {
			p["predicate"].(map[string]any)["buildDefinition"].(map[string]any)["externalParameters"].(map[string]any)["extra"] = true
		},
		"empty-spdx": func(p, s map[string]any) { s["predicate"] = map[string]any{} },
		"dangling": func(p, s map[string]any) {
			s["predicate"].(map[string]any)["relationships"].([]any)[0].(map[string]any)["relatedSpdxElement"] = "SPDXRef-missing"
		},
		"root-checksum": func(p, s map[string]any) {
			s["predicate"].(map[string]any)["packages"].([]any)[0].(map[string]any)["checksums"].([]any)[0].(map[string]any)["checksumValue"] = strings.Repeat("b", 64)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			q := signedBuild(t, mutate)
			if _, err := VerifyBuildEvidenceBytes(context.Background(), q); err == nil {
				t.Fatal("valid signature bypassed claim check")
			}
		})
	}
}
func TestExportBuildEvidenceFixture(t *testing.T) {
	destination := os.Getenv("VSK_BUILD_EVIDENCE_FIXTURE_OUTPUT")
	if destination == "" {
		return
	}
	good := signedBuild(t, nil)
	if _, err := VerifyBuildEvidenceBytes(context.Background(), good); err != nil {
		t.Fatal(err)
	}
	wrong := signedBuild(t, func(p, s map[string]any) {
		s["predicate"].(map[string]any)["packages"].([]any)[0].(map[string]any)["checksums"].([]any)[0].(map[string]any)["checksumValue"] = strings.Repeat("b", 64)
	})
	if err := os.MkdirAll(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]BuildEvidenceRequest{"request.json": good, "request-wrong-package.json": wrong} {
		raw, err := json.MarshalIndent(q, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, name), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBuildEvidenceAllowsSLSAExtensions(t *testing.T) {
	q := signedBuild(t, func(p, s map[string]any) {
		p["predicate"].(map[string]any)["futureExtension"] = map[string]any{"data": "ignored"}
	})
	if _, err := VerifyBuildEvidenceBytes(context.Background(), q); err != nil {
		t.Fatal(err)
	}
}
func TestBuildEvidenceRejectsSignedDuplicateOrMissingPayload(t *testing.T) {
	manifest, expected, p, s := buildStatements(t)
	pr, _ := json.Marshal(p)
	sr, _ := json.Marshal(s)
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`{"predicate":`), []byte(strings.Replace(string(pr), `"predicateType":`, `"predicateType":"https://slsa.dev/provenance/v1","predicateType":`, 1))} {
		q := signBuildStatements(t, manifest, expected, raw, sr)
		if _, err := VerifyBuildEvidenceBytes(context.Background(), q); err == nil {
			t.Fatal("invalid signed statement accepted")
		}
	}
}
func TestBuildEvidenceBoundedInputAndExpectedClaims(t *testing.T) {
	good := signedBuild(t, nil)
	cases := map[string]func(*BuildEvidenceRequest){
		"oversize":  func(q *BuildEvidenceRequest) { q.SBOMBundle = make([]byte, maxBundleBytes+1) },
		"malformed": func(q *BuildEvidenceRequest) { q.SBOMBundle = []byte(`{"bad":`) },
		"missing":   func(q *BuildEvidenceRequest) { q.SBOMBundle = nil },
		"wrong-policy-identity": func(q *BuildEvidenceRequest) {
			var p map[string]any
			_ = json.Unmarshal(q.Policy, &p)
			p["certificateIdentity"] = "https://wrong.invalid"
			q.Policy, _ = json.Marshal(p)
		},
		"bad-revision": func(q *BuildEvidenceRequest) { q.Expected.SourceRevision = strings.Repeat("a", 41) },
		"duplicate-expected-parameters": func(q *BuildEvidenceRequest) {
			q.Expected.ExternalParameters = []byte(`{"ref":"x","ref":"refs/heads/main"}`)
		},
		"unexpected-parameters": func(q *BuildEvidenceRequest) { q.Expected.ExternalParameters = []byte(`{"ref":"refs/heads/other"}`) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			q := good
			mutate(&q)
			if _, err := VerifyBuildEvidenceBytes(context.Background(), q); err == nil {
				t.Fatal("bad input accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyBuildEvidenceBytes(ctx, good); err == nil {
		t.Fatal("cancelled input accepted")
	}
}
