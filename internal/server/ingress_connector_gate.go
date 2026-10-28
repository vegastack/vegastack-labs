package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/ingressconnector"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type connectorSelection struct {
	HostID, IdentityDigest, AccountID, TunnelID, OriginCAPool string
	RecoveryEpoch                                             int64
}
type connectorPilot func(context.Context, generated.Plan) (generated.ControllerSetupPilotEligibility, error)

type connectorBaseline func(context.Context, string) (store.HostAdmissionSnapshot, error)

// Setup eligibility comes only from the ordinary actual baseline evaluator or
// the explicitly selected shared controller-pilot verifier. Neither a marker
// nor a connector service observation becomes host admission/G-012 evidence.
func verifyIngressConnector(ctx context.Context, p generated.Plan, selected connectorSelection, baseline connectorBaseline, pilot connectorPilot) error {
	r := p.HostAction
	if r == nil || r.ActionID != ingressconnector.Action || r.ActionVersion != "1.0.0" || p.HostAccessSequence != nil || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || len(p.Operations) != 1 || p.Operations[0].AdapterID != hostaction.AdapterID || p.Operations[0].OperationType != hostaction.OperationType || p.Operations[0].Idempotent || selected.TunnelID == "" || selected.RecoveryEpoch != p.Binding.RecoveryEpoch {
		return actionFailure()
	}
	in, e := ingressconnector.Decode([]byte(r.ActionInput))
	if e != nil || in.HostID != r.HostID || in.HostID != selected.HostID || in.HostIdentityDigest != r.ConsoleConfirmation.HostIdentityDigest || in.HostIdentityDigest != selected.IdentityDigest || in.AccountID != selected.AccountID || in.TunnelID != selected.TunnelID || (selected.OriginCAPool != "" && selected.OriginCAPool != ingressconnector.CAPath) || (in.OriginCADigest != "") != (selected.OriginCAPool != "") {
		return actionFailure()
	}
	var s store.HostAdmissionSnapshot
	if in.ControllerSetupPilotDigest != "" {
		if pilot == nil {
			return actionFailure()
		}
		eligibility, err := pilot(ctx, p)
		if err != nil || eligibility.HostID != in.HostID || eligibility.HostIdentityDigest != in.HostIdentityDigest || eligibility.RecoveryEpoch != p.Binding.RecoveryEpoch || eligibility.StateRevision != p.Binding.StateRevision || eligibility.PolicyDigest != in.ControllerSetupPilotDigest {
			return actionFailure()
		}
		return nil
	} else {
		if baseline == nil {
			return actionFailure()
		}
		s, e = baseline(ctx, in.HostID)
	}
	if e != nil || s.Host.HostID != in.HostID || s.IdentityDigest != in.HostIdentityDigest || s.Revision.RecoveryEpoch != p.Binding.RecoveryEpoch || s.Revision.StateRevision != p.Binding.StateRevision {
		return actionFailure()
	}
	return nil
}
