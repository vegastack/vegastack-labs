package release

import (
	"context"
	"io"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const targetBundleSignature = "bundle-signature"

// SigstoreBundleVerifier verifies a supplied Sigstore bundle and trust policy
// entirely from local bytes. It deliberately does not use TUF, a network
// client, or either of sigstore-go's unsafe policy bypasses.
type SigstoreBundleVerifier struct{}

func (SigstoreBundleVerifier) Verify(ctx context.Context, artifact io.Reader, bundleJSON []byte, policy generated.ReleaseTrustPolicy) error {
	if err := ctx.Err(); err != nil {
		return interrupted()
	}
	if artifact == nil || len(bundleJSON) == 0 {
		return newError(generated.ErrorCodeEvidenceInvalid, targetBundleSignature)
	}
	if int64(len(bundleJSON)) > maxBundleBytes {
		return newError(generated.ErrorCodeInputInvalid, targetBundleSignature)
	}
	if int64(len(policy.TrustedRoot)) > maxPolicyBytes {
		return newError(generated.ErrorCodeInputInvalid, targetBundleSignature)
	}
	if err := validatePolicy(policy); err != nil {
		return newError(generated.ErrorCodeEvidenceInvalid, targetBundleSignature)
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(policy.TrustedRoot)
	if err != nil {
		return newError(generated.ErrorCodeEvidenceInvalid, targetBundleSignature)
	}
	entity := &bundle.Bundle{}
	if err := entity.UnmarshalJSON(bundleJSON); err != nil {
		return newError(generated.ErrorCodeEvidenceInvalid, targetBundleSignature)
	}
	version, err := entity.Version()
	if err != nil || version != "v0.3" {
		return newError(generated.ErrorCodeEvidenceInvalid, targetBundleSignature)
	}

	certificateIdentity, err := verify.NewShortCertificateIdentity(
		policy.OIDCIssuer, "", policy.CertificateIdentity, "",
	)
	if err != nil {
		return newError(generated.ErrorCodeEvidenceInvalid, targetBundleSignature)
	}
	verifier, err := verify.NewVerifier(
		trustedRoot,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1),
	)
	if err != nil {
		return newError(generated.ErrorCodeEvidenceInvalid, targetBundleSignature)
	}
	_, err = verifier.Verify(
		entity,
		verify.NewPolicy(
			verify.WithArtifact(&contextReader{ctx: ctx, reader: artifact}),
			verify.WithCertificateIdentity(certificateIdentity),
		),
	)
	if ctx.Err() != nil {
		return interrupted()
	}
	if err != nil {
		return newError(generated.ErrorCodeEvidenceInvalid, targetBundleSignature)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	count, err := reader.reader.Read(buffer)
	if reader.ctx.Err() != nil {
		return count, reader.ctx.Err()
	}
	return count, err
}
