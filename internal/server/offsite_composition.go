package server

import (
	"context"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// QualifiedOffsiteRunnerSource is the deployment-profile boundary for G-008.
// It may return qualified=false without failing server startup; this keeps all
// local capabilities available while off-site execution remains unregistered.
type QualifiedOffsiteRunnerSource interface {
	Runner(context.Context, *serverconfig.OffsiteBackup, *store.Store) (runengine.OffsiteCopyRunner, bool, error)
}

// NewProductionOffsiteEffectFactory composes the shipped adapter from one
// qualified runner and the server-owned append-only catalog. Neither a profile
// nor a runner alone is enough to register provider authority.
func NewProductionOffsiteEffectFactory(source QualifiedOffsiteRunnerSource) OffsiteEffectFactory {
	return func(ctx context.Context, profile *serverconfig.OffsiteBackup, authority *store.Store) (adapter.Adapter, error) {
		if profile == nil || authority == nil || source == nil {
			return nil, nil
		}
		runner, qualified, err := source.Runner(ctx, profile, authority)
		if err != nil || !qualified || runner == nil {
			return nil, err
		}
		catalog := backup.NewSQLCatalog(authority)
		execution, err := runengine.NewCatalogOffsiteExecution(runner, catalog)
		if err != nil {
			return nil, err
		}
		return runengine.NewOffsiteEffect(execution)
	}
}

// ProfileOffsiteRunnerSource is the shipped qualification registry. G-008
// activation installs a typed factory for its exact evidence digest; unknown,
// absent, or fixture-only evidence remains unavailable without affecting local
// backup operation.
type ProfileOffsiteRunnerSource struct {
	factories map[string]func(context.Context, *serverconfig.OffsiteBackup, *store.Store) (runengine.OffsiteCopyRunner, error)
}

type QualifiedOffsiteRunnerRegistration struct {
	EvidenceDigest string
	ProofClass     string
	Factory        func(context.Context, *serverconfig.OffsiteBackup, *store.Store) (runengine.OffsiteCopyRunner, error)
}

func NewProfileOffsiteRunnerSource() *ProfileOffsiteRunnerSource {
	return &ProfileOffsiteRunnerSource{factories: map[string]func(context.Context, *serverconfig.OffsiteBackup, *store.Store) (runengine.OffsiteCopyRunner, error){}}
}

func (source *ProfileOffsiteRunnerSource) Register(registration QualifiedOffsiteRunnerRegistration) error {
	if source == nil || registration.Factory == nil || registration.ProofClass != backup.OffsiteProofQualified || len(registration.EvidenceDigest) != 71 || registration.EvidenceDigest[:7] != "sha256:" {
		return errors.New("offsite runtime qualification rejected")
	}
	source.factories[registration.EvidenceDigest] = registration.Factory
	return nil
}

func (source *ProfileOffsiteRunnerSource) Runner(ctx context.Context, profile *serverconfig.OffsiteBackup, authority *store.Store) (runengine.OffsiteCopyRunner, bool, error) {
	if source == nil || profile == nil || authority == nil {
		return nil, false, nil
	}
	factory := source.factories[profile.G008EvidenceDigest]
	if factory == nil {
		return nil, false, nil
	}
	runner, err := factory(ctx, profile, authority)
	return runner, err == nil && runner != nil, err
}

var _ QualifiedOffsiteRunnerSource = (*ProfileOffsiteRunnerSource)(nil)
