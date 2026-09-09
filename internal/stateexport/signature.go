package stateexport

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

const (
	SigningPurpose     = "vsk-labs:inventory-draft-export:v1"
	SignatureAlgorithm = "ed25519"
)

type SignRequest struct {
	Purpose string
	Digest  [32]byte
}

type Signer interface {
	Sign(context.Context, SignRequest) (DetachedSignature, error)
}

type Verifier interface {
	Verify(context.Context, SignRequest, DetachedSignature) error
}

func SigningInput(request SignRequest) ([]byte, error) {
	if request.Purpose != SigningPurpose {
		return nil, exportError(generated.ErrorCodeInputInvalid, "inventory-export-signing-purpose")
	}
	return []byte(request.Purpose + "\nsha256:" + hex.EncodeToString(request.Digest[:]) + "\n"), nil
}

func VerifySignedExport(ctx context.Context, verifier Verifier, value SignedExport) error {
	if err := ctx.Err(); err != nil {
		return exportError(generated.ErrorCodeInterrupted, "inventory-export-signature")
	}
	if verifier == nil {
		return exportError(generated.ErrorCodePrerequisiteBlocked, "inventory-export-verifier")
	}
	if value.Schema != SignedExportSchema || value.SchemaVersion != SchemaVersion || value.VerificationStatus != VerificationVerified ||
		value.Signature.Algorithm != SignatureAlgorithm || !tokenPattern.MatchString(value.Signature.KeyID) ||
		!digestPattern.MatchString(value.Signature.KeyFingerprint) {
		return exportError(generated.ErrorCodeIntegrityFailure, "inventory-export-signature")
	}
	_, digest, err := CanonicalPayload(value.Payload)
	if err != nil {
		return exportError(generated.ErrorCodeIntegrityFailure, "inventory-export-payload")
	}
	wantDigest := digestString(digest)
	if len(value.ContentDigest) != len(wantDigest) || subtle.ConstantTimeCompare([]byte(value.ContentDigest), []byte(wantDigest)) != 1 {
		return exportError(generated.ErrorCodeIntegrityFailure, "inventory-export-content-digest")
	}
	signature, err := base64.RawURLEncoding.DecodeString(value.Signature.Value)
	if err != nil || len(signature) != 64 || base64.RawURLEncoding.EncodeToString(signature) != value.Signature.Value {
		return exportError(generated.ErrorCodeIntegrityFailure, "inventory-export-signature")
	}
	request := SignRequest{Purpose: SigningPurpose, Digest: digest}
	if _, err := SigningInput(request); err != nil {
		return err
	}
	if err := verifier.Verify(ctx, request, value.Signature); err != nil {
		return exportError(generated.ErrorCodeIntegrityFailure, "inventory-export-signature")
	}
	if err := ctx.Err(); err != nil {
		return exportError(generated.ErrorCodeInterrupted, "inventory-export-signature")
	}
	return nil
}
