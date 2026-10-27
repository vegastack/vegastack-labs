package release

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

// Expectations come from protected server composition, never from the claims
// being verified. This profile evaluates supplied evidence; it builds nothing.
type BuildExpectation struct {
	ImageDigest, SourceURI, SourceRevision, BuilderID, BuildType, InvocationID string
	ExternalParameters                                                         json.RawMessage
}
type BuildEvidenceRequest struct {
	Manifest, ProvenanceBundle, SBOMBundle, Policy []byte
	Expected                                       BuildExpectation
}
type BuildEvidenceProof struct {
	ImageDigest, PolicyDigest, ProvenanceBundleDigest, SBOMBundleDigest string
	ProvenancePayloadDigest, SBOMPayloadDigest                          string
	SourceURI, SourceRevision, BuilderID, BuildType, InvocationID       string
	PackageCount                                                        int
}

var spdxID = regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]{1,127}$`)
var exactRevision = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
var rawSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func evidenceError() error { return newError(generated.ErrorCodeEvidenceInvalid, "build-evidence") }

// FreezeBuildEvidence copies the bounded caller buffers so verification and
// publication cannot accidentally use different manifest/evidence slices.
func FreezeBuildEvidence(q BuildEvidenceRequest) (BuildEvidenceRequest, error) {
	if len(q.Manifest) == 0 || len(q.Manifest) > int(maxManifestBytes) || len(q.Policy) == 0 || len(q.Policy) > int(maxPolicyBytes) || len(q.ProvenanceBundle) == 0 || len(q.ProvenanceBundle) > int(maxBundleBytes) || len(q.SBOMBundle) == 0 || len(q.SBOMBundle) > int(maxBundleBytes) || len(q.Expected.ExternalParameters) > int(maxManifestBytes) || !utf8.Valid(q.Manifest) || !utf8.Valid(q.Policy) || !utf8.Valid(q.ProvenanceBundle) || !utf8.Valid(q.SBOMBundle) {
		return BuildEvidenceRequest{}, evidenceError()
	}
	q.Manifest = bytes.Clone(q.Manifest)
	q.Policy = bytes.Clone(q.Policy)
	q.ProvenanceBundle = bytes.Clone(q.ProvenanceBundle)
	q.SBOMBundle = bytes.Clone(q.SBOMBundle)
	q.Expected.ExternalParameters = bytes.Clone(q.Expected.ExternalParameters)
	return q, nil
}

// VerifyBuildEvidenceBytes authenticates both image-subject bundles with the
// existing offline Sigstore verifier before interpreting their exact payloads.
// Success means this bounded SLSA/SPDX profile matched, never a SLSA build level,
// complete dependency inventory, runner admission or permission to publish.
func VerifyBuildEvidenceBytes(ctx context.Context, q BuildEvidenceRequest) (BuildEvidenceProof, error) {
	if ctx == nil {
		return BuildEvidenceProof{}, evidenceError()
	}
	q, err := FreezeBuildEvidence(q)
	if err != nil {
		return BuildEvidenceProof{}, err
	}
	e := q.Expected
	if !digestPattern.MatchString(e.ImageDigest) || !exactRevision.MatchString(e.SourceRevision) || !evidenceURI(e.SourceURI) || !evidenceURI(e.BuilderID) || !evidenceURI(e.BuildType) || !evidenceURI(e.InvocationID) {
		return BuildEvidenceProof{}, evidenceError()
	}
	expectedParams, err := jsonObject(ctx, e.ExternalParameters)
	if err != nil {
		return BuildEvidenceProof{}, err
	}
	// No claims parsed before signature/identity/subject verification succeeds.
	if _, err = VerifyOCIBytes(ctx, q.Manifest, q.ProvenanceBundle, q.Policy, e.ImageDigest); err != nil {
		return BuildEvidenceProof{}, err
	}
	if _, err = VerifyOCIBytes(ctx, q.Manifest, q.SBOMBundle, q.Policy, e.ImageDigest); err != nil {
		return BuildEvidenceProof{}, err
	}
	provenance, err := attestationPayload(ctx, q.ProvenanceBundle)
	if err != nil {
		return BuildEvidenceProof{}, err
	}
	sbom, err := attestationPayload(ctx, q.SBOMBundle)
	if err != nil {
		return BuildEvidenceProof{}, err
	}
	p, err := statementPredicate(ctx, provenance, "https://slsa.dev/provenance/v1", e.ImageDigest)
	if err != nil {
		return BuildEvidenceProof{}, err
	}
	s, err := statementPredicate(ctx, sbom, "https://spdx.dev/Document/v2.3", e.ImageDigest)
	if err != nil {
		return BuildEvidenceProof{}, err
	}
	if err = checkProvenance(ctx, p, e, expectedParams); err != nil {
		return BuildEvidenceProof{}, err
	}
	count, err := checkSPDX(s, e.ImageDigest)
	if err != nil {
		return BuildEvidenceProof{}, err
	}
	if ctx.Err() != nil {
		return BuildEvidenceProof{}, interrupted()
	}
	return BuildEvidenceProof{ImageDigest: e.ImageDigest, PolicyDigest: hashOCI(q.Policy), ProvenanceBundleDigest: hashOCI(q.ProvenanceBundle), SBOMBundleDigest: hashOCI(q.SBOMBundle), ProvenancePayloadDigest: hashOCI(provenance), SBOMPayloadDigest: hashOCI(sbom), SourceURI: e.SourceURI, SourceRevision: e.SourceRevision, BuilderID: e.BuilderID, BuildType: e.BuildType, InvocationID: e.InvocationID, PackageCount: count}, nil
}
func attestationPayload(ctx context.Context, raw []byte) ([]byte, error) {
	if strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 32}) != nil {
		return nil, evidenceError()
	}
	b := &bundle.Bundle{}
	if b.UnmarshalJSON(raw) != nil {
		return nil, evidenceError()
	}
	env, err := b.Envelope()
	if err != nil || env == nil || env.RawEnvelope().PayloadType != "application/vnd.in-toto+json" {
		return nil, evidenceError()
	}
	payload, err := env.RawEnvelope().DecodeB64Payload()
	if err != nil || len(payload) == 0 || len(payload) > int(maxBundleBytes) || !utf8.Valid(payload) || strictjson.Scan(ctx, payload, strictjson.Limits{MaxDepth: 32}) != nil {
		return nil, evidenceError()
	}
	return payload, nil
}
func statementPredicate(ctx context.Context, raw []byte, kind, digest string) (json.RawMessage, error) {
	var s struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
		Subject       []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
		Predicate json.RawMessage `json:"predicate"`
	}
	if !criticalFieldNames(raw, statementFields) || json.Unmarshal(raw, &s) != nil || s.Type != "https://in-toto.io/Statement/v1" || s.PredicateType != kind || len(s.Subject) != 1 || !evidenceText(s.Subject[0].Name, 2048) || len(s.Subject[0].Digest) != 1 || s.Subject[0].Digest["sha256"] != strings.TrimPrefix(digest, "sha256:") {
		return nil, evidenceError()
	}
	if _, err := jsonObject(ctx, s.Predicate); err != nil {
		return nil, err
	}
	return s.Predicate, nil
}
func checkProvenance(ctx context.Context, raw []byte, e BuildExpectation, expected []byte) error {
	var p struct {
		BuildDefinition struct {
			BuildType            string          `json:"buildType"`
			ExternalParameters   json.RawMessage `json:"externalParameters"`
			ResolvedDependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
			Metadata struct {
				InvocationID string `json:"invocationId"`
			} `json:"metadata"`
		} `json:"runDetails"`
	}
	if !criticalFieldNames(raw, provenanceFields) || json.Unmarshal(raw, &p) != nil || p.BuildDefinition.BuildType != e.BuildType || p.RunDetails.Builder.ID != e.BuilderID || p.RunDetails.Metadata.InvocationID != e.InvocationID || len(p.BuildDefinition.ResolvedDependencies) > 4096 {
		return evidenceError()
	}
	params, err := jsonObject(ctx, p.BuildDefinition.ExternalParameters)
	if err != nil || !bytes.Equal(params, expected) {
		return evidenceError()
	}
	matches := 0
	for _, dependency := range p.BuildDefinition.ResolvedDependencies {
		if dependency.URI != "" && !evidenceURI(dependency.URI) {
			return evidenceError()
		}
		if dependency.URI == e.SourceURI {
			matches++
			if dependency.Digest["gitCommit"] != e.SourceRevision {
				return evidenceError()
			}
		}
	}
	if matches != 1 {
		return evidenceError()
	}
	return nil
}
func jsonObject(ctx context.Context, raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > int(maxBundleBytes) || !utf8.Valid(raw) || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 32}) != nil {
		return nil, evidenceError()
	}
	var object map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&object) != nil || object == nil {
		return nil, evidenceError()
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return nil, evidenceError()
	}
	return canonical, nil
}
func evidenceText(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for _, c := range value {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}
func evidenceURI(value string) bool {
	if !evidenceText(value, 2048) {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && u.IsAbs() && u.User == nil && u.Fragment == ""
}

func checkSPDX(raw []byte, image string) (int, error) {
	var s struct {
		Version   string `json:"spdxVersion"`
		License   string `json:"dataLicense"`
		ID        string `json:"SPDXID"`
		Name      string `json:"name"`
		Namespace string `json:"documentNamespace"`
		Creation  struct {
			Created  string   `json:"created"`
			Creators []string `json:"creators"`
		} `json:"creationInfo"`
		Packages []struct {
			ID            string          `json:"SPDXID"`
			Name          string          `json:"name"`
			Download      string          `json:"downloadLocation"`
			FilesAnalyzed *bool           `json:"filesAnalyzed"`
			Verification  json.RawMessage `json:"packageVerificationCode"`
			Checksums     []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"checksumValue"`
			} `json:"checksums"`
		} `json:"packages"`
		Relationships []struct {
			From string `json:"spdxElementId"`
			To   string `json:"relatedSpdxElement"`
			Type string `json:"relationshipType"`
		} `json:"relationships"`
		Files    []json.RawMessage `json:"files"`
		Snippets []json.RawMessage `json:"snippets"`
	}
	if !criticalFieldNames(raw, spdxFields) || json.Unmarshal(raw, &s) != nil || s.Version != "SPDX-2.3" || s.License != "CC0-1.0" || s.ID != "SPDXRef-DOCUMENT" || !evidenceText(s.Name, 256) || !evidenceURI(s.Namespace) || len(s.Packages) < 1 || len(s.Packages) > 4096 || len(s.Relationships) < 1 || len(s.Relationships) > 16384 || len(s.Files) > 0 || len(s.Snippets) > 0 || len(s.Creation.Creators) < 1 || len(s.Creation.Creators) > 32 {
		return 0, evidenceError()
	}
	if _, err := time.Parse(time.RFC3339, s.Creation.Created); err != nil || !strings.HasSuffix(s.Creation.Created, "Z") {
		return 0, evidenceError()
	}
	for _, creator := range s.Creation.Creators {
		if !evidenceText(creator, 256) || !(strings.HasPrefix(creator, "Tool: ") && len(creator) > 6 || strings.HasPrefix(creator, "Person: ") && len(creator) > 8 || strings.HasPrefix(creator, "Organization: ") && len(creator) > 14) {
			return 0, evidenceError()
		}
	}
	ids := map[string]bool{s.ID: true}
	imagePackages := map[string]bool{}
	for _, p := range s.Packages {
		if !spdxID.MatchString(p.ID) || ids[p.ID] || !evidenceText(p.Name, 256) || !evidenceText(p.Download, 2048) || p.FilesAnalyzed == nil || *p.FilesAnalyzed || len(p.Verification) > 0 || len(p.Checksums) > 32 {
			return 0, evidenceError()
		}
		if p.Download != "NOASSERTION" && p.Download != "NONE" && !evidenceURI(p.Download) {
			return 0, evidenceError()
		}
		ids[p.ID] = true
		seen := map[string]bool{}
		for _, checksum := range p.Checksums {
			if !spdxChecksumAlgorithm[checksum.Algorithm] || !checksumHex.MatchString(checksum.Value) || seen[checksum.Algorithm] {
				return 0, evidenceError()
			}
			seen[checksum.Algorithm] = true
			if checksum.Algorithm == "SHA256" {
				if !rawSHA256.MatchString(checksum.Value) {
					return 0, evidenceError()
				}
				if checksum.Value == strings.TrimPrefix(image, "sha256:") {
					imagePackages[p.ID] = true
				}
			}
		}
	}
	roots := map[string]bool{}
	for _, r := range s.Relationships {
		if !ids[r.From] || !ids[r.To] || !spdxRelationship[r.Type] {
			return 0, evidenceError()
		}
		if r.From == s.ID && r.Type == "DESCRIBES" {
			roots[r.To] = true
			if !imagePackages[r.To] {
				return 0, evidenceError()
			}
		}
	}
	if len(roots) != 1 {
		return 0, evidenceError()
	}
	return len(s.Packages), nil
}

// Accepted enumerations come from the pinned SPDX2.3 schema. This profile does
// not evaluate license expressions, external documents or file inventories.
var checksumHex = regexp.MustCompile(`^[0-9a-fA-F]{1,128}$`)
var spdxChecksumAlgorithm = wordSet("SHA1 BLAKE3 SHA3-384 SHA256 SHA384 BLAKE2b-512 BLAKE2b-256 SHA3-512 MD2 ADLER32 MD4 SHA3-256 BLAKE2b-384 SHA512 MD6 MD5 SHA224")
var spdxRelationship = wordSet("VARIANT_OF COPY_OF PATCH_FOR TEST_DEPENDENCY_OF CONTAINED_BY DATA_FILE_OF OPTIONAL_COMPONENT_OF ANCESTOR_OF GENERATES CONTAINS OPTIONAL_DEPENDENCY_OF FILE_ADDED REQUIREMENT_DESCRIPTION_FOR DEV_DEPENDENCY_OF DEPENDENCY_OF BUILD_DEPENDENCY_OF DESCRIBES PREREQUISITE_FOR HAS_PREREQUISITE PROVIDED_DEPENDENCY_OF DYNAMIC_LINK DESCRIBED_BY METAFILE_OF DEPENDENCY_MANIFEST_OF PATCH_APPLIED RUNTIME_DEPENDENCY_OF TEST_OF TEST_TOOL_OF DEPENDS_ON SPECIFICATION_FOR FILE_MODIFIED DISTRIBUTION_ARTIFACT AMENDS DOCUMENTATION_OF GENERATED_FROM STATIC_LINK OTHER BUILD_TOOL_OF TEST_CASE_OF PACKAGE_OF DESCENDANT_OF FILE_DELETED EXPANDED_FROM_ARCHIVE DEV_TOOL_OF EXAMPLE_OF")

func wordSet(words string) map[string]bool {
	m := map[string]bool{}
	for _, word := range strings.Fields(words) {
		m[word] = true
	}
	return m
}

// encoding/json accepts case-insensitive struct field aliases. Standard claims
// have exact names; aliases must not override a differently named signed claim.
// Only schema-critical objects are inspected; extension objects remain opaque.
type evidenceFields map[string]evidenceFields

var statementFields = evidenceFields{"_type": nil, "predicateType": nil, "subject": {"name": nil, "digest": nil}, "predicate": nil}
var provenanceFields = evidenceFields{"buildDefinition": {"buildType": nil, "externalParameters": nil, "resolvedDependencies": {"uri": nil, "digest": nil}}, "runDetails": {"builder": {"id": nil}, "metadata": {"invocationId": nil}}}
var spdxFields = evidenceFields{"spdxVersion": nil, "dataLicense": nil, "SPDXID": nil, "name": nil, "documentNamespace": nil, "creationInfo": {"created": nil, "creators": nil}, "packages": {"SPDXID": nil, "name": nil, "downloadLocation": nil, "filesAnalyzed": nil, "packageVerificationCode": nil, "checksums": {"algorithm": nil, "checksumValue": nil}}, "relationships": {"spdxElementId": nil, "relatedSpdxElement": nil, "relationshipType": nil}, "files": nil, "snippets": nil}

func criticalFieldNames(raw []byte, shape evidenceFields) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	return inspectFieldNames(value, shape)
}
func inspectFieldNames(value any, shape evidenceFields) bool {
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if !inspectFieldNames(item, shape) {
				return false
			}
		}
	case map[string]any:
		for key, child := range v {
			for known, nested := range shape {
				if strings.EqualFold(key, known) {
					if key != known {
						return false
					}
					if nested != nil && !inspectFieldNames(child, nested) {
						return false
					}
					break
				}
			}
		}
	}
	return true
}
