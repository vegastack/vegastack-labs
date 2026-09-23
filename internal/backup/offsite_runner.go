package backup

import (
	"context"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

// OffsiteRunSpec is the complete typed, secret-borrowing execution input for
// one already-authorized generation. The resolver must derive it from the
// immutable plan/declaration and qualified site adapters; digests alone are
// never interpreted as values by the runner.
type OffsiteRunSpec struct {
	PointID              string
	Policy               OffsitePolicy
	Retention            adapter.RetentionObservation
	Copy                 CopyConfig
	Verifier             OffsiteVerifierConfig
	Cutoff               OffsiteCutoffProbe
	WriterSealObservedAt time.Time
}

type OffsiteRunSpecSource interface {
	ResolveOffsiteRun(context.Context, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (OffsiteRunSpec, error)
}

// OffsiteWorkflowRunner is the production orchestration of the already
// separated admission, forecast, custody, catalog, seal and verification
// boundaries. It has no provider fallback and cannot run from digest-only
// inputs: a qualified typed resolver is mandatory.
type OffsiteWorkflowRunner struct {
	source  OffsiteSource
	specs   OffsiteRunSpecSource
	catalog OffsiteCatalog
}

func NewOffsiteWorkflowRunner(source OffsiteSource, specs OffsiteRunSpecSource, catalog OffsiteCatalog) (*OffsiteWorkflowRunner, error) {
	if source == nil || specs == nil || catalog == nil {
		return nil, errors.New("offsite workflow unavailable")
	}
	return &OffsiteWorkflowRunner{source: source, specs: specs, catalog: catalog}, nil
}

func (runner *OffsiteWorkflowRunner) CopyAndVerify(ctx context.Context, operation adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (OffsiteProof, error) {
	if runner == nil || runner.source == nil || runner.specs == nil || runner.catalog == nil || len(values) != 3 || values[0] == nil || values[1] == nil || values[2] == nil || len(values[0].Bytes()) == 0 || len(values[1].Bytes()) == 0 || len(values[2].Bytes()) == 0 {
		return OffsiteProof{}, errors.New("offsite workflow unavailable")
	}
	spec, err := runner.specs.ResolveOffsiteRun(ctx, operation, binding, values)
	if err != nil {
		return OffsiteProof{}, err
	}
	if spec.Policy.GenerationID != operation.TargetID || spec.PointID == "" || spec.Copy.Endpoint == nil || spec.Cutoff == nil || spec.WriterSealObservedAt.IsZero() ||
		spec.Copy.Binding.RunID != binding.RunID || spec.Copy.Binding.StepID != binding.StepID || spec.Copy.Binding.GenerationID != operation.TargetID ||
		spec.Copy.Binding.RecoveryEpoch != binding.RecoveryEpoch {
		return OffsiteProof{}, errors.New("offsite workflow binding mismatch")
	}
	defer spec.Copy.Endpoint.Close()
	point, err := AdmitOffsitePoint(ctx, runner.source, spec.Policy, spec.PointID, binding.RecoveryEpoch)
	if err != nil {
		return OffsiteProof{}, err
	}
	if point.StateRevision != binding.StateRevision {
		return OffsiteProof{}, errors.New("offsite source revision is stale")
	}
	admission, err := ForecastGeneration(spec.Policy, point, spec.Retention)
	if err != nil {
		return OffsiteProof{}, err
	}
	pending, err := CopyOffsitePoint(ctx, spec.Copy, point, admission)
	if err != nil {
		return OffsiteProof{}, err
	}
	if err := runner.catalog.AppendPending(ctx, pending); err != nil {
		return OffsiteProof{}, err
	}
	seal, err := SealWriter(ctx, pending, OffsiteProofQualified, spec.WriterSealObservedAt, spec.Cutoff)
	if err != nil {
		return OffsiteProof{}, err
	}
	proof, err := VerifyOffsitePoint(ctx, spec.Verifier, pending, seal)
	if err != nil {
		return OffsiteProof{}, err
	}
	if err := runner.catalog.AppendProof(ctx, proof); err != nil {
		return OffsiteProof{}, err
	}
	if err := runner.catalog.AdvanceLastGood(ctx, proof, binding.StateRevision); err != nil {
		return OffsiteProof{}, err
	}
	return proof, nil
}

var _ interface {
	CopyAndVerify(context.Context, adapter.Operation, adapter.ExactExecutionBinding, []*credentialref.Value) (OffsiteProof, error)
} = (*OffsiteWorkflowRunner)(nil)
