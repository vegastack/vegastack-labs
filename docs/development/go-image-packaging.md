# Local Go image packaging

`vsk-labs release build-go-image` creates actual scratch OCI image bytes from an existing static Linux Go executable. It does not compile source, sign, publish, contact a provider or grant deployment authority. Linux amd64 and arm64 are supported. The image has only `/app`, an executable entrypoint running as UID/GID65532, with no shell, CA bundle, timezone data or other base-image files. Applications requiring these must use a separate appropriately approved build path.

Compile from clean, committed Git source using Go's VCS stamping, with CGO disabled and the output outside the source worktree. For example, using an application repository that has `./cmd/app`:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=true -o /tmp/application ./cmd/app
vsk-labs release build-go-image \
  --binary /tmp/application \
  --source-uri https://example.org/application \
  --source-revision 0123456789abcdef0123456789abcdef01234567 \
  --builder-id https://example.org/packager \
  --invocation-id https://example.org/runs/one \
  --directory /tmp/application-image \
  --output json
```

Replace the example identities with the actual protected build inputs. The command requires the exact expected revision in clean embedded Git build metadata and rejects replacement modules, dynamic interpreters, missing metadata or the wrong target architecture. Compiler metadata can be forged by an untrusted build; source URI, builder and invocation arguments are supplied metadata, not authenticated identities. Neither this command nor its `expectations.json` can establish the signer's trust policy or authorization.

The new output directory contains an OCI layout (`oci-layout`, `index.json` and content-addressed blobs), `provenance.statement.json`, `sbom.statement.json` and `expectations.json`. Existing output is refused. On an I/O failure a partial directory may remain; failure is never reported as a completed artifact. Human and JSON output explicitly report unsigned, binary-packaging-only provenance and compiled-go-modules-only inventory.

The SPDX2.3 statement describes the exact image manifest digest and includes the binary checksum, the actual main/linked modules from Go buildinfo and the reported Go standard-library version. It does not scan every standard-library package, vendored file, native dependency, license or source file. Names and versions are compiler-reported. NOASSERTION records unknown license/download details; no full dependency or license completeness claim is made.

The SLSA provenance/v1 statement describes the actual packaging operation under build type `https://vegastack.com/buildtypes/go-static-scratch-package/v1`. It binds the binary checksum, image manifest, embedded source revision, supplied source URI/builder/invocation, packaging parameters and actual packaging start/end. It does not claim that the packager compiled the binary or attained a SLSA build level.

For publication, the existing configured signing system must sign each unchanged statement as an in-toto Statement/v1 Sigstore bundle for the real configured identity. The controller obtains its expected source/builder/invocation and trust policy independently from protected composition; it must not trust this directory as authority. Supply the resulting bundles and exact manifest to `release.VerifyBuildEvidenceBytes` or `ociregistry.Client.PublishVerified`. Config and layer blobs come from the OCI layout. Unsigned statement JSON is not an acceptable substitute for either bundle: the existing verifier rejects it. No signing identity, OIDC credential, bundle, registry publication or live acceptance is established by local packaging tests.

Manual fallback uses the same command and constraints. Preserve a failed partial directory for diagnosis; use a new destination for a new attempt. Local artifact generation has no remote rollback or infrastructure effects.

Contracts checked28-10-2026: [Go buildinfo](https://pkg.go.dev/debug/buildinfo), [OCI image specification1.1.1](https://github.com/opencontainers/image-spec/tree/v1.1.1), [SLSA provenance/v1](https://slsa.dev/provenance/v1). The producer matches the existing bounded SPDX/SLSA verifier profile; it does not weaken signature verification.
