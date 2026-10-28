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
type connectorBaseline func(context.Context, string) (store.HostAdmissionSnapshot, error)

// Only the existing actual baseline evaluator may supply production readiness.
// No connector service observation becomes host admission or G-012 evidence.
func verifyIngressConnector(ctx context.Context, p generated.Plan, selected connectorSelection, baseline connectorBaseline) error {
	r := p.HostAction
	if r == nil || r.ActionID != ingressconnector.Action || r.ActionVersion != "1.0.0" || p.HostAccessSequence != nil || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || len(p.Operations) != 1 || p.Operations[0].AdapterID != hostaction.AdapterID || p.Operations[0].OperationType != hostaction.OperationType || p.Operations[0].Idempotent || selected.TunnelID == "" || baseline == nil || selected.RecoveryEpoch != p.Binding.RecoveryEpoch {
		return actionFailure()
	}
	in, e := ingressconnector.Decode([]byte(r.ActionInput))
	if e != nil || in.HostID != r.HostID || in.HostID != selected.HostID || in.HostIdentityDigest != r.ConsoleConfirmation.HostIdentityDigest || in.HostIdentityDigest != selected.IdentityDigest || in.AccountID != selected.AccountID || in.TunnelID != selected.TunnelID || (selected.OriginCAPool != "" && selected.OriginCAPool != ingressconnector.CAPath) || (in.OriginCADigest != "") != (selected.OriginCAPool != "") {
		return actionFailure()
	}
	s, e := baseline(ctx, in.HostID)
	if e != nil || s.Host.HostID != in.HostID || s.IdentityDigest != in.HostIdentityDigest || s.Revision.RecoveryEpoch != p.Binding.RecoveryEpoch || s.Revision.StateRevision != p.Binding.StateRevision {
		return actionFailure()
	}
	return nil
}
