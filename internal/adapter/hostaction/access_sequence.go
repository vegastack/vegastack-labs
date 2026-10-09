package hostaction

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
)

type AccessSequenceSource interface {
	ResolveLocalProbe(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (generated.HostActionRequest, generated.AccessProbeInput, error)
}
type AccessLocalProbe interface {
	Execute(context.Context, generated.AccessProbeInput, []*credentialref.Value) ([]generated.AccessMeasurement, error)
}
type ControlResultRecorder interface {
	RecordVerifiedControlResults(context.Context, adapter.Operation, adapter.ExactExecutionBinding, adapter.Effect, generated.HostActionResult) error
}
type completedAccess struct {
	Effect  adapter.Effect
	Binding adapter.ExactExecutionBinding
	Result  generated.HostActionResult
}

// NewWithAccess extends the same exact executor; dependencies are explicit and
// no global transport, result registry or arbitrary result upload is installed.
func NewWithAccess(targets TargetSource, bundles BundleSource, authority Authority, sequences AccessSequenceSource, probe AccessLocalProbe, recorder ControlResultRecorder, nativeSelectors ...NativeProbeSelector) (*Adapter, error) {
	a, err := New(targets, bundles, authority)
	if err != nil {
		return nil, err
	}
	if sequences == nil || probe == nil || recorder == nil || len(nativeSelectors) > 1 {
		return nil, denied()
	}
	a.sequences = sequences
	a.probe = probe
	a.recorder = recorder
	if len(nativeSelectors) == 1 {
		a.nativeProbe = nativeSelectors[0]
	}
	return a, nil
}
func (a *Adapter) executeLocalProbe(ctx context.Context, op adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	if a.sequences == nil || a.probe == nil || a.recorder == nil || len(op.SecretReferences) != 1 || len(values) != 1 || values[0] == nil {
		return adapter.Effect{}, denied()
	}
	request, input, err := a.sequences.ResolveLocalProbe(ctx, op, binding)
	if err != nil || request.HostID != op.TargetID || request.ActionID != "debian.access.probe.local" || request.CredentialReferenceID != op.SecretReferences[0].ID || request.ActionInputDigest != protocol.BytesDigest([]byte(request.ActionInput)) {
		return adapter.Effect{}, denied()
	}
	raw, err := json.Marshal(input)
	if err != nil || string(raw) != request.ActionInput {
		return adapter.Effect{}, denied()
	}
	measurements, err := a.probe.Execute(ctx, input, values)
	if err != nil {
		return adapter.Effect{}, denied()
	}
	// Bind local observations to this exact execution rather than inventing a
	// target envelope/signature for an operation performed in the controller.
	digest := LocalProbeResultBinding(op, binding, input)
	for i := range measurements {
		measurements[i].BundleDigest = digest
		measurements[i].MeasurementDigest = protocol.MeasurementDigest(measurements[i])
	}
	result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: digest, Status: "succeeded", Reason: "measured", EffectObserved: true, ControlMeasurements: measurements}
	result.ResultDigest = protocol.ResultDigest(result)
	if len(measurements) == 0 || protocol.ValidateResult(result) != nil {
		return adapter.Effect{}, denied()
	}
	effect := adapter.Effect{Status: result.Status, ResultDigest: result.ResultDigest, EffectObserved: true}
	if err = a.remember(op, binding, effect, result); err != nil {
		return adapter.Effect{}, err
	}
	return effect, nil
}
func (a *Adapter) remember(op adapter.Operation, binding adapter.ExactExecutionBinding, effect adapter.Effect, result generated.HostActionResult) error {
	if protocol.ValidateResult(result) != nil || result.ResultDigest != effect.ResultDigest {
		return denied()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.completed) >= 1024 {
		return denied()
	}
	// Detach backing arrays/pointers from producer-owned data before persistence.
	raw, err := json.Marshal(result)
	if err != nil {
		return denied()
	}
	var copied generated.HostActionResult
	if json.Unmarshal(raw, &copied) != nil {
		return denied()
	}
	a.completed[verificationKey(op, effect.ResultDigest)] = completedAccess{Effect: effect, Binding: binding, Result: copied}
	return nil
}

// LocalProbeResultBinding is the exact receipt-bound identity for controller observations.
func LocalProbeResultBinding(op adapter.Operation, binding adapter.ExactExecutionBinding, input generated.AccessProbeInput) string {
	op.SecretReferences = nil // InputDigest seals the exact credential manifest.
	return protocol.Digest(struct {
		Operation adapter.Operation
		Binding   adapter.ExactExecutionBinding
		Input     generated.AccessProbeInput
	}{op, binding, input})
}
