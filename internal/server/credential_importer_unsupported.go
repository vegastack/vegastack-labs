//go:build !linux

package server

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type credentialImportService interface {
	Preflight(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error)
	Import(context.Context, generated.CredentialImportRequest, []byte, identity.Principal) (generated.CredentialImportSubmission, error)
}

type unsupportedCredentialImporter struct{}

func (unsupportedCredentialImporter) Preflight(context.Context, generated.CredentialImportRequest, identity.Principal) (*generated.CredentialImportSubmission, error) {
	return nil, failure.New(generated.ErrorCodeUnsupportedPlatform, "credential-import", false)
}

func (unsupportedCredentialImporter) Import(context.Context, generated.CredentialImportRequest, []byte, identity.Principal) (generated.CredentialImportSubmission, error) {
	return generated.CredentialImportSubmission{}, failure.New(generated.ErrorCodeUnsupportedPlatform, "credential-import", false)
}

func newProductionCredentialImporter(*store.CredentialRepository, *store.PlanRepository, string, uint32) credentialImportService {
	return unsupportedCredentialImporter{}
}
