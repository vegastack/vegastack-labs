package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/run"
	"slices"
)

type hostActionConsoleSource interface {
	VerifyHostActionConsole(context.Context, string, generated.HostActionCredentialConfirmation, int64) error
}
type hostActionLifecycleSource interface {
	GetLifecycleBinding(context.Context, generated.Plan, string) (credentialref.LifecycleBinding, error)
	GetCredentialVersion(context.Context, string, string) (generated.CredentialReference, error)
}

// This routes only exact host-action use and its native credential activation.
// Existing unrelated prerequisite checks retain their original fallback.
type hostActionGate struct {
	targets     hostActionConsoleSource
	credentials hostActionLifecycleSource
	allowed     []string
	fallback    run.GateVerifier
}

func (g hostActionGate) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	action := op.AdapterID == hostaction.AdapterID && (op.OperationType == hostaction.OperationType || op.OperationType == debianaccess.LocalProbeOperation)
	lifecycle := p.HostActionConsole != nil && (op.OperationType == string(credentialref.ActionActivate) || op.OperationType == string(credentialref.ActionRotate))
	if !action && !lifecycle {
		if g.fallback == nil {
			return actionFailure()
		}
		return g.fallback.VerifySecretStep(ctx, p, op)
	}
	if g.targets == nil || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || (p.HostAccessSequence == nil && (len(p.Operations) != 1 || p.Operations[0] != op)) {
		return actionFailure()
	}
	var c generated.HostActionCredentialConfirmation
	if action {
		if scope := p.HostBaselineScope; scope != nil && (!slices.Contains(g.allowed, scope.SubjectIdentityDigest) || !slices.Contains(g.allowed, scope.ExecutionIdentityDigest)) {
			return actionFailure()
		}
		r := p.HostAction
		if p.HostAccessSequence != nil {
			source, ok := g.targets.(interface {
				ResolveAccessSequenceStep(context.Context, generated.Plan, string) (generated.HostActionRequest, error)
				ResolveAccessLocalProbe(context.Context, generated.Plan, string) (generated.HostActionRequest, generated.AccessProbeInput, error)
			})
			if !ok || p.HostAction != nil {
				return actionFailure()
			}
			var selected generated.HostActionRequest
			var err error
			if op.OperationType == debianaccess.LocalProbeOperation {
				selected, _, err = source.ResolveAccessLocalProbe(ctx, p, op.OperationID)
			} else {
				selected, err = source.ResolveAccessSequenceStep(ctx, p, op.OperationID)
			}
			if err != nil {
				return err
			}
			r = &selected
			for _, target := range p.HostAccessSequence.AuxiliaryTargets {
				if !slices.Contains(g.allowed, target.IdentityDigest) {
					return actionFailure()
				}
			}
		}
		if r == nil || hostaction.ValidateRequest(*r) != nil || r.HostID != op.TargetID || hostaction.Digest(*r) != op.ArtifactDigest || r.RecoveryEpoch != p.Binding.RecoveryEpoch {
			return actionFailure()
		}
		c = generated.HostActionCredentialConfirmation{Method: r.ConsoleConfirmation.Method, TargetDigest: r.TargetDigest, HostIdentityDigest: r.ConsoleConfirmation.HostIdentityDigest, TargetRevision: r.TargetRevision}
	} else {
		if g.credentials == nil {
			return actionFailure()
		}
		b, err := g.credentials.GetLifecycleBinding(ctx, p, op.OperationID)
		if err != nil || !credentialref.ValidLifecycleBinding(b) || b.HostActionConsole == nil || b.ResolverID != "native-systemd" || len(b.ConsumerIDs) != 1 || b.ConsumerIDs[0] != hostaction.AdapterID || b.TargetID != op.TargetID || b.RecoveryEpoch != p.Binding.RecoveryEpoch || string(b.Action) != op.OperationType {
			return actionFailure()
		}
		if b.Action == credentialref.ActionRotate {
			if b.ImportDraftConsumerID == nil || b.ImportDraftPurposeID == nil || *b.ImportDraftConsumerID != hostaction.AdapterID || *b.ImportDraftPurposeID != hostaction.PurposeID {
				return actionFailure()
			}
		} else {
			ref, err := g.credentials.GetCredentialVersion(ctx, b.ReferenceID, b.MaterialVersion)
			if err != nil || ref.ConsumerID != hostaction.AdapterID || ref.PurposeID != hostaction.PurposeID || ref.TargetID != b.TargetID || ref.ResolverID != "native-systemd" || ref.MaterialVersion != b.MaterialVersion || ref.RecoveryEpoch != b.RecoveryEpoch {
				return actionFailure()
			}
		}
		c = *p.HostActionConsole
		if c.Method != b.HostActionConsole.Method || c.TargetDigest != b.HostActionConsole.TargetDigest || c.HostIdentityDigest != b.HostActionConsole.HostIdentityDigest || c.TargetRevision != b.HostActionConsole.TargetRevision || c.NativeConsumerMachineID != b.HostActionConsole.NativeConsumerMachineID || len(b.NativeConsumers) != 1 || c.NativeConsumerMachineID != b.NativeConsumers[0].HostMachineID || p.HostActionNativeUnit != b.NativeConsumers[0].UnitName {
			return actionFailure()
		}
	}
	if !slices.Contains(g.allowed, c.HostIdentityDigest) {
		return actionFailure()
	}
	return g.targets.VerifyHostActionConsole(ctx, op.TargetID, c, p.Binding.RecoveryEpoch)
}
