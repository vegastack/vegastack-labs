//go:build linux

package linuxrole

import (
	"context"
	"time"
)

// InspectNativeControlHandoff reads only the fixed protected production receipt
// and reuses the production handoff observer. It starts/stops no process and
// does not open the control database as another writer.
func InspectNativeControlHandoff(ctx context.Context) (NativeControlHandoffObservation, error) {
	n := &nativeRuntime{root: "/", version: "1.0.0", run: roleCommand, now: time.Now}
	return n.inspectNativeControlHandoff(ctx)
}
func (n *nativeRuntime) inspectNativeControlHandoff(ctx context.Context) (NativeControlHandoffObservation, error) {
	var out NativeControlHandoffObservation
	r, err := n.readHandoff()
	if err != nil || r.Status != "completed" || r.Input.Handoff == nil || !r.State.ServiceActive || ValidateControlHandoff(r.Input, r.State) != nil {
		return out, errNative
	}
	s, err := n.handoffState(ctx, r.Input)
	if err != nil || !s.ServiceActive || ValidateControlHandoff(r.Input, s) != nil {
		return out, errNative
	}
	out = NativeControlHandoffObservation{Bundle: r.Bundle, Input: r.Input, ReceiptDigest: r.Digest, RecordedState: r.State, CurrentState: s, ObservedAt: n.now().UTC().Format(time.RFC3339Nano)}
	return out, nil
}
