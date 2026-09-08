package inventory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestNormalizeAndValidateRejectsSecretsWithoutEchoAndAllowsOpaqueSerial(t *testing.T) {
	t.Parallel()
	candidate := minimalCandidate()
	candidate.Assets[0].Identities[0].Value = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="
	if _, err := NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: candidate}); err != nil {
		t.Fatalf("base64-like serial rejected: %v", err)
	}
	canary := "-----BEGIN PRIVATE KEY----- public-test-canary"
	candidate.Assets[0].Identities[0].Value = canary
	_, err := NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: candidate})
	var domainErr *Error
	if !errors.As(err, &domainErr) || domainErr.Code != generated.ErrorCodeInputInvalid || strings.Contains(err.Error(), canary) {
		t.Fatalf("secret rejection = %v", err)
	}
}

func TestNormalizeRejectsSecretSemanticLocationsAndTokenPrefixes(t *testing.T) {
	t.Parallel()
	for _, mutate := range []func(*DraftCandidate){
		func(candidate *DraftCandidate) { candidate.Provenance[0].FieldPath = "password" },
		func(candidate *DraftCandidate) { candidate.Observations[0].Value = "github_pat_public-test-canary" },
		func(candidate *DraftCandidate) {
			candidate.Observations[0].Value = "https://user:pass@example.invalid/"
		},
	} {
		candidate := minimalCandidate()
		mutate(&candidate)
		_, err := NormalizeAndValidate(context.Background(), DecodedCandidate{Candidate: candidate})
		assertInventoryCode(t, err, generated.ErrorCodeInputInvalid)
	}
}
