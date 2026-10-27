package ociregistry

import (
	"bytes"
	"context"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/release"
)

type VerifiedPublishRequest struct {
	Publication PublishRequest
	Evidence    release.BuildEvidenceRequest
}
type VerifiedPublishReceipt struct {
	Evidence    release.BuildEvidenceProof
	Publication PublishReceipt
}

// PublishVerified authenticates and checks the standard evidence profile before
// handing the same frozen image to Publish. It grants no authority: Check must
// still enforce current server plan/lease/policy and journal each write intent.
// The supplied credential is publication-scoped; no deploy path is invoked.
// Preserve Publication.Stage even on error, including an uncertain remote write.
func (c *Client) PublishVerified(ctx context.Context, q VerifiedPublishRequest, v *credentialref.Value) (out VerifiedPublishReceipt, err error) {
	if ctx == nil || q.Publication.Check == nil || len(q.Publication.Manifest) > maxManifest || len(q.Publication.Blobs) > 128 {
		return out, ErrInput
	}
	if ctx.Err() != nil {
		return out, ErrInterrupted
	}
	q.Evidence, err = release.FreezeBuildEvidence(q.Evidence)
	if err != nil {
		return out, err
	}
	q.Publication.Manifest = bytes.Clone(q.Publication.Manifest)
	q.Publication.Blobs = append([]Blob(nil), q.Publication.Blobs...)
	if q.Publication.Digest != q.Evidence.Expected.ImageDigest || !bytes.Equal(q.Publication.Manifest, q.Evidence.Manifest) {
		return out, ErrIdentity
	}
	out.Evidence, err = release.VerifyBuildEvidenceBytes(ctx, q.Evidence)
	if err != nil {
		return out, err
	}
	out.Publication, err = c.Publish(ctx, q.Publication, v)
	return out, err
}
