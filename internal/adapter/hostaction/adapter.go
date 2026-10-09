// Package hostaction transports one server-authorized action to a pinned SSH peer.
package hostaction

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
)

type Target struct {
	HostID, HostIdentityDigest, Address, User, HostKey, AutomationPrincipalID string
	Port                                                                      uint16
	CallerUID                                                                 uint32
	Revision                                                                  int64
}

// TargetSource must resolve current, independently bound identity and apply the
// site's physical-host exclusions before returning. Aliases alone are not identity.
type TargetSource interface {
	Resolve(context.Context, generated.HostActionBundle) (Target, error)
}
type BundleSource interface {
	Issue(context.Context, adapter.Operation, adapter.ExactExecutionBinding) (generated.HostActionEnvelope, error)
}
type Authority interface {
	Authorize(context.Context, generated.HostActionEnvelope, generated.HostActionChallenge) (generated.HostActionAuthorization, error)
}
type Adapter struct {
	targets   TargetSource
	bundles   BundleSource
	authority Authority
	mu        sync.Mutex
	completed map[string]adapter.Effect
}

var _ adapter.Adapter = (*Adapter)(nil)
var _ adapter.BoundCredentialExecutor = (*Adapter)(nil)

func denied() error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, "host-action-transport", false)
}
func New(targets TargetSource, bundles BundleSource, authority Authority) (*Adapter, error) {
	if targets == nil || bundles == nil || authority == nil {
		return nil, denied()
	}
	return &Adapter{targets: targets, bundles: bundles, authority: authority, completed: map[string]adapter.Effect{}}, nil
}
func (*Adapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	return adapter.Effect{}, denied()
}
func (*Adapter) ExecuteWithCredentials(context.Context, adapter.Operation, []*credentialref.Value) (adapter.Effect, error) {
	return adapter.Effect{}, denied()
}
func (a *Adapter) Verify(ctx context.Context, op adapter.Operation, e adapter.Effect) (adapter.Verification, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || adapter.ValidateOperation(op) != nil || adapter.ValidateEffect(e) != nil {
		return adapter.Verification{}, denied()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	key := protocol.Digest(op) + "/" + e.ResultDigest
	got, ok := a.completed[key]
	if !ok || got != e {
		return adapter.Verification{}, denied()
	}
	delete(a.completed, key)
	return adapter.Verification{Verified: true, Digest: e.ResultDigest}, nil
}
func validTarget(t Target, b generated.HostActionBundle) bool {
	return t.HostID == b.HostID && t.HostIdentityDigest == b.HostIdentityDigest && t.AutomationPrincipalID == b.AutomationPrincipalID && int64(t.CallerUID) == b.CallerUID && t.CallerUID > 0 && t.Revision > 0 && net.ParseIP(t.Address) != nil && t.Port > 0 && t.User != "" && t.User != "root" && !strings.ContainsAny(t.User, " \t\r\n\x00") && len(t.User) <= 64
}
func (a *Adapter) ExecuteBoundWithCredentials(ctx context.Context, op adapter.Operation, binding adapter.ExactExecutionBinding, values []*credentialref.Value) (adapter.Effect, error) {
	if a == nil || a.targets == nil || a.bundles == nil || a.authority == nil || ctx == nil || ctx.Err() != nil || adapter.ValidateOperation(op) != nil || op.AdapterID != "host-action" || op.OperationType != "host.action.execute" || len(op.SecretReferences) != 1 || len(values) != 1 || values[0] == nil || len(values[0].Bytes()) == 0 {
		return adapter.Effect{}, denied()
	}
	deadline, err := time.Parse(time.RFC3339, binding.MaximumExpiresAt)
	if err != nil || !time.Now().Before(deadline) {
		return adapter.Effect{}, denied()
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	envelope, err := a.bundles.Issue(ctx, op, binding)
	if err != nil {
		return adapter.Effect{}, denied()
	}
	b := envelope.Bundle
	raw, err := json.Marshal(envelope)
	digest, digestErr := protocol.BundleDigest(b)
	expiry, expiryErr := time.Parse(time.RFC3339, b.ExpiresAt)
	if err != nil || digestErr != nil || len(raw) > protocol.MaximumEnvelope || generated.ValidateContractJSON(generated.SchemaIDHostActionEnvelope, raw, generated.ContractExact) != nil || b.PlanID != binding.PlanID || b.PlanDigest != binding.PlanDigest || b.RunID != binding.RunID || b.StepID != binding.StepID || b.LeaseID != binding.LeaseID || b.StateRevision != binding.StateRevision || b.RecoveryEpoch != binding.RecoveryEpoch || b.HostID != op.TargetID || b.CredentialReferenceID != op.SecretReferences[0].ID || expiryErr != nil || !time.Now().Before(expiry) || expiry.After(deadline) {
		return adapter.Effect{}, denied()
	}
	target, err := a.targets.Resolve(ctx, b)
	if err != nil || !validTarget(target, b) {
		return adapter.Effect{}, denied()
	}
	result, observed, err := a.exchange(ctx, target, envelope, digest, values[0])
	if err != nil {
		return adapter.Effect{EffectObserved: observed}, denied()
	}
	e := adapter.Effect{Status: result.Status, ResultDigest: result.ResultDigest, Changed: result.Changed, EffectObserved: result.EffectObserved}
	if adapter.ValidateEffect(e) != nil || e.Status != "succeeded" {
		return adapter.Effect{EffectObserved: true}, denied()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// Verification is immediate in the engine. Bound memory if a caller abandons
	// verification; never accept another effect by evicting an existing receipt.
	if len(a.completed) >= 1024 {
		return adapter.Effect{EffectObserved: true}, denied()
	}
	a.completed[protocol.Digest(op)+"/"+e.ResultDigest] = e
	return e, nil
}
