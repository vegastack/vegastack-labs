package server

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// QualifiedOffsiteRunnerSource is the deployment-profile boundary for G-008.
// It may return qualified=false without failing server startup; this keeps all
// local capabilities available while off-site execution remains unregistered.
type QualifiedOffsiteRunnerSource interface {
	Runner(context.Context, serverconfig.Profile, *store.Store) (runengine.OffsiteCopyRunner, bool, error)
}

// NewProductionOffsiteEffectFactory composes the shipped adapter from one
// qualified runner and the server-owned append-only catalog. Neither a profile
// nor a runner alone is enough to register provider authority.
func NewProductionOffsiteEffectFactory(source QualifiedOffsiteRunnerSource) OffsiteEffectFactory {
	return func(ctx context.Context, profile serverconfig.Profile, authority *store.Store) (adapter.Adapter, error) {
		if profile.OffsiteBackup == nil || authority == nil || source == nil {
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

// ProfileOffsiteRunnerSource is the shipped qualification resolver. It does
// not accept imperative registrations: every process start re-derives
// authority from current append-only G-008 evidence before invoking the
// compiled provider factory.
type ProfileOffsiteRunnerSource struct {
	factory func(context.Context, serverconfig.Profile, *store.Store, generated.GateEvidence) (runengine.OffsiteCopyRunner, error)
	clock   func() time.Time
	resolve func(context.Context, *store.Store, *serverconfig.OffsiteBackup, time.Time) (generated.GateEvidence, error)
}

func NewProfileOffsiteRunnerSource(factory func(context.Context, serverconfig.Profile, *store.Store, generated.GateEvidence) (runengine.OffsiteCopyRunner, error)) *ProfileOffsiteRunnerSource {
	return &ProfileOffsiteRunnerSource{factory: factory, clock: time.Now, resolve: func(ctx context.Context, authority *store.Store, profile *serverconfig.OffsiteBackup, at time.Time) (generated.GateEvidence, error) {
		return store.NewGateRepository(authority).ResolveCurrentLiveGateEvidence(ctx, "G-008", profile.G008EvidenceDigest, profile.QualificationDigest, profile.PutCutoffDigest, profile.MultipartCutoffDigest, at)
	}}
}

func (source *ProfileOffsiteRunnerSource) Runner(ctx context.Context, complete serverconfig.Profile, authority *store.Store) (runengine.OffsiteCopyRunner, bool, error) {
	profile := complete.OffsiteBackup
	if source == nil || profile == nil || authority == nil {
		return nil, false, nil
	}
	if source.factory == nil {
		return nil, false, nil
	}
	clock := source.clock
	if clock == nil {
		clock = time.Now
	}
	if source.resolve == nil {
		return nil, false, nil
	}
	evidence, err := source.resolve(ctx, authority, profile, clock())
	if err != nil {
		return nil, false, nil
	}
	runner, err := source.factory(ctx, complete, authority, evidence)
	return runner, err == nil && runner != nil, err
}

var _ QualifiedOffsiteRunnerSource = (*ProfileOffsiteRunnerSource)(nil)
