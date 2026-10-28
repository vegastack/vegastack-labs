# Public synthetic publication fixture

Generated on 28-10-2026 by `TestExportCIPublicationFixture` in
`internal/release/build_evidence_test.go`, using the existing ephemeral Sigstore
synthetic signing hierarchy. No signing key is retained. Source `owner/repo`,
numeric run60/attempt2/job70 and revision a*40 match the public native controller
fixture only. The signature/trust roots, builder, source, SLSA/SPDX predicates
and two-byte OCI config `{}` are synthetic; this is not a useful image or real
GitHub/build/signing evidence. First-party MIT material. The invocation URI is a
canonical comparison identifier, never a provider route or URL to follow.

Regenerate explicitly with:

    VSK_CI_PUBLICATION_FIXTURE_OUTPUT=../server/testdata/ci-publication go test ./internal/release -run '^TestExportCIPublicationFixture$'
