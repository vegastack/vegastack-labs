package server

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type QualifiedOffsiteRetirementSource interface {
	Execution(context.Context, serverconfig.Profile, *store.Store) (runengine.OffsiteRetirementExecution, bool, error)
}

type OffsiteRetirementEffectFactory func(context.Context, serverconfig.Profile, *store.Store) (adapter.Adapter, error)

func NewProductionOffsiteRetirementEffectFactory(source QualifiedOffsiteRetirementSource) OffsiteRetirementEffectFactory {
	return func(ctx context.Context, profile serverconfig.Profile, authority *store.Store) (adapter.Adapter, error) {
		if profile.OffsiteBackup == nil || authority == nil || source == nil {
			return nil, nil
		}
		execution, qualified, err := source.Execution(ctx, profile, authority)
		if err != nil || !qualified || execution == nil {
			return nil, err
		}
		return runengine.NewOffsiteRetirementEffect(execution)
	}
}

type ProfileOffsiteRetirementSource struct {
	factory func(context.Context, serverconfig.Profile, *store.Store, generated.GateEvidence) (runengine.OffsiteRetirementExecution, error)
	clock   func() time.Time
	resolve func(context.Context, *store.Store, *serverconfig.OffsiteBackup, time.Time) (generated.GateEvidence, error)
}

func NewProfileOffsiteRetirementSource(factory func(context.Context, serverconfig.Profile, *store.Store, generated.GateEvidence) (runengine.OffsiteRetirementExecution, error)) *ProfileOffsiteRetirementSource {
	return &ProfileOffsiteRetirementSource{factory: factory, clock: time.Now, resolve: func(ctx context.Context, authority *store.Store, profile *serverconfig.OffsiteBackup, at time.Time) (generated.GateEvidence, error) {
		return store.NewGateRepository(authority).ResolveCurrentLiveGateEvidence(ctx, "G-008", profile.G008EvidenceDigest, profile.QualificationDigest, profile.PutCutoffDigest, profile.MultipartCutoffDigest, at)
	}}
}

func (source *ProfileOffsiteRetirementSource) Execution(ctx context.Context, profile serverconfig.Profile, authority *store.Store) (runengine.OffsiteRetirementExecution, bool, error) {
	if source == nil || profile.OffsiteBackup == nil || authority == nil || source.factory == nil || source.resolve == nil {
		return nil, false, nil
	}
	clock := source.clock
	if clock == nil {
		clock = time.Now
	}
	evidence, err := source.resolve(ctx, authority, profile.OffsiteBackup, clock())
	if err != nil {
		return nil, false, nil
	}
	execution, err := source.factory(ctx, profile, authority, evidence)
	return execution, err == nil && execution != nil, err
}

var _ QualifiedOffsiteRetirementSource = (*ProfileOffsiteRetirementSource)(nil)
