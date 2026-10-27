# Public synthetic build-evidence fixtures

Generated for Issue #306 on 27-10-2026 using
`internal/release/build_evidence_test.go:TestExportBuildEvidenceFixture` and the
existing `newSyntheticFixture` helper. First-party MIT test material; these are
not real build outputs, releases or qualified builder identities.

The fixtures contain actual Sigstore v0.3 DSSE signatures with ephemeral ECDSA
keys, synthetic Fulcio/CT/Rekor roots and an observer timestamp, produced using
already pinned sigstore-go v1.3.0 test APIs. No private key is written or retained.
Issuer/certificate, builder, source and invocation use reserved example.invalid
identities. Both bundled standard predicates describe the SHA256 subject of the
same synthetic OCI image. Its only config blob is the two bytes `{}`; it has no
layers. This is a protocol fixture, not a useful container or generated SBOM.

`request.json` satisfies the bounded SLSA-v1/SPDX2.3 package profile.
`request-wrong-package.json` has valid signatures and matching image subjects but
intentionally lies about the root package checksum; verification must reject it
before any registry request. Each JSON file serializes BuildEvidenceRequest;
Go byte fields use normal JSON base64 encoding. Public trust roots are combined
so both independent synthetic signing hierarchies can be verified offline.

SHA256:

- request.json: bd683e1222bc179d297696d023f58e42b1bb9fc7824812baae7a333fca6fba1d
- request-wrong-package.json: 27cfaa3791c7c2d26360a7e5822bdc13ae3212e51924e8f8cf895e2db353c25a

Regeneration is explicit and replaces these random public fixtures:

    VSK_BUILD_EVIDENCE_FIXTURE_OUTPUT=../adapter/ociregistry/testdata/verified-candidate go test ./internal/release -run '^TestExportBuildEvidenceFixture$'

Update the inventory after intentional regeneration. Ordinary tests never write
fixtures, fetch a schema, contact Sigstore or select a real signing identity.
