package release

import (
	"archive/tar"
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"encoding/json"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

const GoScratchBuildType = "https://vegastack.com/buildtypes/go-static-scratch-package/v1"
const MaxGoImageBinary = 128 << 20

// Source URI/builder/invocation are caller-supplied, unauthenticated metadata.
// The embedded clean revision is checked, not authenticated. This operation
// packages an existing binary; it does not claim to have compiled its source.
type GoImageRequest struct {
	Binary                                             []byte
	SourceURI, SourceRevision, BuilderID, InvocationID string
}
type GoImageOutput struct {
	Manifest, Config, Layer, ProvenanceStatement, SBOMStatement []byte
	Expected                                                    BuildExpectation
}

// BuildGoImage constructs actual scratch OCI bytes and unsigned in-toto
// statements. The SBOM is a compiled Go-module inventory, not a complete
// dependency/license/file inventory or an authenticated source claim.
func BuildGoImage(ctx context.Context, q GoImageRequest) (GoImageOutput, error) {
	empty := GoImageOutput{}
	if ctx == nil || len(q.Binary) == 0 || len(q.Binary) > MaxGoImageBinary || !exactRevision.MatchString(q.SourceRevision) || !evidenceURI(q.SourceURI) || !evidenceURI(q.BuilderID) || !evidenceURI(q.InvocationID) {
		return empty, evidenceError()
	}
	if ctx.Err() != nil {
		return empty, interrupted()
	}
	start := time.Now().UTC()
	binary := bytes.Clone(q.Binary)
	f, e := elf.NewFile(bytes.NewReader(binary))
	if e != nil {
		return empty, evidenceError()
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return empty, evidenceError()
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return empty, evidenceError()
		}
	}
	arch := ""
	switch f.Machine {
	case elf.EM_X86_64:
		arch = "amd64"
	case elf.EM_AARCH64:
		arch = "arm64"
	default:
		return empty, evidenceError()
	}
	info, e := buildinfo.Read(bytes.NewReader(binary))
	if e != nil || len(info.Deps) > 4090 || !evidenceText(info.GoVersion, 128) || !evidenceText(info.Main.Path, 256) {
		return empty, evidenceError()
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		if _, ok := settings[s.Key]; ok {
			return empty, evidenceError()
		}
		settings[s.Key] = s.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != arch || settings["CGO_ENABLED"] != "0" || settings["vcs"] != "git" || settings["vcs.revision"] != q.SourceRevision || settings["vcs.modified"] != "false" {
		return empty, evidenceError()
	}
	modules := []*debug.Module{&info.Main}
	modules = append(modules, info.Deps...)
	seen := map[string]bool{}
	for _, m := range modules {
		if m == nil || m.Replace != nil || !evidenceText(m.Path, 256) || seen[m.Path] || !evidenceText(m.Version, 256) {
			return empty, evidenceError()
		}
		seen[m.Path] = true
	}
	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	if tw.WriteHeader(&tar.Header{Name: "app", Mode: 0555, Size: int64(len(binary)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}) != nil {
		return empty, evidenceError()
	}
	if _, e = tw.Write(binary); e != nil {
		return empty, evidenceError()
	}
	if tw.Close() != nil {
		return empty, evidenceError()
	}
	marshal := func(v any) []byte { b, _ := json.Marshal(v); return b }
	config := marshal(map[string]any{"architecture": arch, "os": "linux", "config": map[string]any{"User": "65532:65532", "Entrypoint": []string{"/app"}, "WorkingDir": "/"}, "rootfs": map[string]any{"type": "layers", "diff_ids": []string{hashOCI(layer.Bytes())}}})
	descriptor := func(kind string, b []byte) map[string]any {
		return map[string]any{"mediaType": kind, "digest": hashOCI(b), "size": len(b)}
	}
	manifest := marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": descriptor("application/vnd.oci.image.config.v1+json", config), "layers": []any{descriptor("application/vnd.oci.image.layer.v1.tar", layer.Bytes())}})
	digest := hashOCI(manifest)
	binaryDigest := hashOCI(binary)
	params := marshal(map[string]any{"binaryDigest": binaryDigest, "sourceURI": q.SourceURI, "sourceRevision": q.SourceRevision, "architecture": arch, "inventoryScope": "compiled-go-modules-only", "metadataTrust": "caller-and-compiler-reported-unverified", "entrypoint": "/app"})
	expected := BuildExpectation{ImageDigest: digest, SourceURI: q.SourceURI, SourceRevision: q.SourceRevision, BuilderID: q.BuilderID, BuildType: GoScratchBuildType, InvocationID: q.InvocationID, ExternalParameters: params}
	provenance := marshal(map[string]any{"buildDefinition": map[string]any{"buildType": GoScratchBuildType, "externalParameters": json.RawMessage(params), "resolvedDependencies": []any{map[string]any{"uri": q.SourceURI, "digest": map[string]string{"gitCommit": q.SourceRevision}}, map[string]any{"uri": "urn:sha256:" + strings.TrimPrefix(binaryDigest, "sha256:"), "digest": map[string]string{"sha256": strings.TrimPrefix(binaryDigest, "sha256:")}}}}, "runDetails": map[string]any{"builder": map[string]string{"id": q.BuilderID}, "metadata": map[string]any{"invocationId": q.InvocationID, "startedOn": start.Format(time.RFC3339Nano), "finishedOn": time.Now().UTC().Format(time.RFC3339Nano)}}})
	pkg := func(id, name string) map[string]any {
		return map[string]any{"SPDXID": id, "name": name, "downloadLocation": "NOASSERTION", "filesAnalyzed": false, "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION"}
	}
	image := pkg("SPDXRef-Image", "Go scratch image")
	image["checksums"] = []any{map[string]string{"algorithm": "SHA256", "checksumValue": strings.TrimPrefix(digest, "sha256:")}}
	app := pkg("SPDXRef-Binary", info.Path)
	app["checksums"] = []any{map[string]string{"algorithm": "SHA256", "checksumValue": strings.TrimPrefix(binaryDigest, "sha256:")}}
	toolchain := pkg("SPDXRef-GoStandardLibrary", "Go standard library")
	toolchain["versionInfo"] = info.GoVersion
	toolchain["comment"] = "Toolchain version only; standard-library packages/files and licenses were not individually scanned."
	packages := []any{image, app, toolchain}
	relationship := func(from, kind, to string) map[string]string {
		return map[string]string{"spdxElementId": from, "relationshipType": kind, "relatedSpdxElement": to}
	}
	relationships := []any{relationship("SPDXRef-DOCUMENT", "DESCRIBES", "SPDXRef-Image"), relationship("SPDXRef-Image", "CONTAINS", "SPDXRef-Binary"), relationship("SPDXRef-Binary", "DEPENDS_ON", "SPDXRef-GoStandardLibrary")}
	for i, m := range modules {
		id := "SPDXRef-Module-" + strconv.Itoa(i)
		p := pkg(id, m.Path)
		p["versionInfo"] = m.Version
		packages = append(packages, p)
		relationships = append(relationships, relationship("SPDXRef-Binary", "DEPENDS_ON", id))
	}
	sbomDocument := map[string]any{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "Go scratch image compiled-module inventory", "creationInfo": map[string]any{"created": start.Format(time.RFC3339), "creators": []string{"Tool: vsk-labs-go-scratch-packager-v1"}}, "documentComment": "Unsigned compiled Go-module inventory from compiler metadata; not a complete dependency, source, license or file SBOM. Supplied source/builder identities are not authenticated.", "packages": packages, "relationships": relationships}
	sbomDocument["documentNamespace"] = "urn:sha256:" + strings.TrimPrefix(hashOCI(marshal(sbomDocument)), "sha256:")
	sbom := marshal(sbomDocument)
	statement := func(kind string, p []byte) []byte {
		return marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": kind, "subject": []any{map[string]any{"name": "go-scratch-image", "digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}}, "predicate": json.RawMessage(p)})
	}
	if _, e = checkSPDX(sbom, digest); e != nil {
		return empty, e
	}
	canonical, e := jsonObject(ctx, params)
	if e != nil {
		return empty, e
	}
	if e = checkProvenance(ctx, provenance, expected, canonical); e != nil {
		return empty, e
	}
	if ctx.Err() != nil {
		return empty, interrupted()
	}
	return GoImageOutput{Manifest: manifest, Config: config, Layer: layer.Bytes(), ProvenanceStatement: statement("https://slsa.dev/provenance/v1", provenance), SBOMStatement: statement("https://spdx.dev/Document/v2.3", sbom), Expected: expected}, nil
}

// BuildGoImageFile snapshots one explicit regular local binary with the existing
// protected bounded release file reader before generating its image.
func BuildGoImageFile(ctx context.Context, path string, q GoImageRequest) (GoImageOutput, error) {
	if ctx == nil {
		return GoImageOutput{}, evidenceError()
	}
	binary, err := readOCIFile(ctx, path, MaxGoImageBinary)
	if err != nil {
		return GoImageOutput{}, err
	}
	q.Binary = binary
	return BuildGoImage(ctx, q)
}

// WriteGoImage writes a new local OCI layout, unsigned statement payloads and
// expectations for a separately configured signer. Existing output is refused.
// On I/O failure a partial directory may remain; it is never reported complete.
func WriteGoImage(ctx context.Context, directory string, out GoImageOutput) error {
	if ctx == nil || ctx.Err() != nil {
		return interrupted()
	}
	if len(out.Manifest) == 0 || hashOCI(out.Manifest) != out.Expected.ImageDigest || len(out.Layer) == 0 || len(out.Config) == 0 {
		return evidenceError()
	}
	if os.Mkdir(directory, 0700) != nil {
		return evidenceError()
	}
	root, e := os.OpenRoot(directory)
	if e != nil {
		return evidenceError()
	}
	defer root.Close()
	if root.Mkdir("blobs", 0700) != nil || root.Mkdir("blobs/sha256", 0700) != nil {
		return evidenceError()
	}
	expected, _ := json.Marshal(out.Expected)
	index, _ := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": out.Expected.ImageDigest, "size": len(out.Manifest)}}})
	files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": index, "provenance.statement.json": out.ProvenanceStatement, "sbom.statement.json": out.SBOMStatement, "expectations.json": expected}
	for _, b := range [][]byte{out.Manifest, out.Config, out.Layer} {
		files["blobs/sha256/"+strings.TrimPrefix(hashOCI(b), "sha256:")] = b
	}
	for name, b := range files {
		if ctx.Err() != nil {
			return interrupted()
		}
		f, e := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return evidenceError()
		}
		_, writeErr := f.Write(b)
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			return evidenceError()
		}
	}
	return nil
}
