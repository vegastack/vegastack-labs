//go:build linux

package qualification

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// rebootSelectedGuest preserves the exact mutable disk and firmware inodes.
// A graceful shutdown and fresh launch are needed because the pinned template
// deliberately exits on guest reboot. No reset or additional guest is touched.
func (d *ownedGuestLifecycle) rebootSelectedGuest(ctx context.Context, in generated.NativeStepRequest) (generated.NativeStepResult, error) {
	out := generated.NativeStepResult{Schema: generated.SchemaIDNativeStepResult, SchemaVersion: "1.0.0", Binding: in, Status: "failed", ObservationDigests: []string{}, ReceiptDigests: []string{}, ProducerRunIDs: []string{}}
	if in.Operation != "reboot-native" || validateStep(d.scope, in, time.Now().UTC()) != nil || !nativeRebootAllowed(d.scope, in) {
		return out, ErrUnavailable
	}
	deadline, _ := time.Parse(time.RFC3339, in.Deadline)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	before, err := d.consoleBootID(ctx, in.GuestID)
	if err != nil {
		return out, err
	}
	if d.beginReplacementRestart(in, before) != nil {
		return out, ErrUnavailable
	}
	out.Changed = true
	if err = d.StopOwned(ctx, in.GuestID); err != nil {
		return out, err
	}
	// Invalidate cached boot freshness before the replacement process exists.
	d.mu.Lock()
	delete(d.bootIDs, in.GuestID)
	delete(d.bootAt, in.GuestID)
	d.mu.Unlock()
	if err = d.RestartOwned(ctx, in.GuestID); err != nil {
		return out, err
	}
	after, err := waitChangedBoot(ctx, before, func(ctx context.Context) (string, error) { return d.consoleBootID(ctx, in.GuestID) })
	if err != nil {
		return out, err
	}
	d.mu.Lock()
	d.bootIDs[in.GuestID], d.bootAt[in.GuestID] = after, time.Now()
	d.mu.Unlock()
	if d.finishReplacementRestart(in, after) != nil {
		return out, ErrUnavailable
	}
	out.Status = "completed"
	// Diagnostic only; authoritative rollback proof still reads the actual
	// protected rollback record and compares its original/new boot identities.
	out.ObservationDigests = []string{hostaction.Digest(struct{ Guest, Before, After string }{in.GuestID, before, after})}
	return out, nil
}

func waitChangedBoot(ctx context.Context, before string, read func(context.Context) (string, error)) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		boot, err := read(ctx)
		if err == nil {
			if !bootIDPattern.MatchString(boot) || boot == before {
				return "", ErrUnavailable
			}
			return boot, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
