# Synthetic release-verification fixture provenance

These files are first-party, public test material generated for Issue #28 on
08-09-2026. They do not represent a VegaStack release and do not satisfy
`G-017`. As first-party repository content, they are covered by the repository's
MIT license.

The fixture generator used the exported APIs in
`github.com/sigstore/sigstore-go` v1.3.0 (Apache-2.0), including
`pkg/testing/ca.VirtualSigstore`, plus its pinned Sigstore/Certificate
Transparency dependencies. It generated ephemeral ECDSA keys in memory, made
synthetic Fulcio and CT hierarchies, embedded one SCT, created one Rekor
inclusion proof and promise, and created one RFC 3161 timestamp for each v0.3
bundle. The two public trust hierarchies were combined in the checked-in local
trusted root. No private key, token, credential, or real service identity was
written to disk or retained.

The deliberately non-routable policy values are:

- certificate identity: `https://example.invalid/vegastack/synthetic-release`
- OIDC issuer: `https://issuer.example.invalid`

Because ECDSA key and signature generation uses cryptographic randomness, the
public fixture bytes are stable after check-in but are not expected to be
reproducible byte-for-byte. Equivalent evidence is generated from fresh
ephemeral keys at test runtime in `signature_test.go`; the tests also derive
all negative cases in memory so no private signing material is needed.

SHA-256 inventory:

- `policy-valid.json`: `854cff09a2017f320788859438edf493fcdd56d243329681b4174b582f28c8b9`
- `release-valid/manifest.json`: `e096144f3a3f046927e82a9e0e1a0af2c8721475080d519b78e0423edd61e3c7`
- `release-valid/manifest.sigstore.json`: `b1f776796df123319dffd23669f744e544b831932748e6e4c75617576f0bb25f`
- `release-valid/artifacts/vsk-labs`: `3c1e79825287ad56cf4dc687c4838d401014a0c8e911e8c039779c8e7b2baf49`
- `release-valid/artifacts/vsk-labs.sigstore.json`: `6ae8786935e5fe52b3b2cca12637c2e16449e41b9ea12fd8082ad084ff23bfac`

The three-byte SBOM and provenance placeholders predate this cryptographic
fixture and are referenced only to exercise safe optional paths; they are not
claims about the synthetic artifact.
