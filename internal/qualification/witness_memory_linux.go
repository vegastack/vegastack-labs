//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strconv"
	"time"
)

type nativeWitnessMemory struct {
	guest                     string
	before, after             *generated.NativeRollbackWitness
	fail                      *generated.NativeFail2banWitness
	phase                     int
	banAt                     time.Time
	volumeCase                *generated.NativeVolumeCaseWitness
	volume                    *generated.NativeVolumeSealWitness
	handoff                   *generated.NativeControlHandoffWitness
	setup                     *generated.NativeControlSetupWitness
	actionBefore, actionAfter *generated.NativeActionReceiptWitness
}

func witnessKey(in generated.NativeStepRequest) string {
	return in.ScopeDigest + ":" + in.ControllerInstanceID + ":" + strconv.FormatInt(in.RecoveryEpoch, 10) + ":" + in.PlanDigest + ":" + in.ScenarioID + ":" + in.PlanID + ":" + in.RunID + ":" + in.StepID + ":" + in.LeaseID
}
func (d *ownedGuestLifecycle) waitWitnessWindow(ctx context.Context, in generated.NativeStepRequest) error {
	d.mu.Lock()
	w := d.witnesses[witnessKey(in)]
	var wait time.Duration
	if in.Operation == "witness" && w != nil && in.ScenarioID == "fail2ban-window" && w.phase == 5 {
		wait = 600*time.Second - time.Since(w.banAt)
	}
	d.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (d *ownedGuestLifecycle) captureWitness(in generated.NativeStepRequest, out generated.NativeStepResult) error {
	if in.Operation != "witness" {
		return nil
	}
	if out.Status != "completed" || hostaction.Digest(out.Binding) != hostaction.Digest(in) {
		return ErrUnavailable
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	key := witnessKey(in)
	w := d.witnesses[key]
	if w == nil {
		if len(d.witnesses) >= 48 {
			return ErrUnavailable
		}
		w = &nativeWitnessMemory{guest: in.GuestID}
		d.witnesses[key] = w
	}
	if out.Rollback != nil {
		if w.guest != in.GuestID {
			return ErrUnavailable
		}
		if w.before == nil {
			if out.Rollback.State != "armed" {
				return ErrUnavailable
			}
			w.before = out.Rollback
			return nil
		}
		if w.after != nil {
			return ErrUnavailable
		}
		var before, after debianaccess.NativeRollbackObservation
		a, _ := json.Marshal(w.before)
		b, _ := json.Marshal(out.Rollback)
		if json.Unmarshal(a, &before) != nil || json.Unmarshal(b, &after) != nil || ValidateRollbackWitness(in.ScenarioID, before, after) != nil {
			return ErrUnavailable
		}
		w.after = out.Rollback
		return nil
	}
	if in.ScenarioID == "fail2ban-window" {
		if w.fail == nil {
			w.fail = &generated.NativeFail2banWitness{Schema: generated.SchemaIDNativeFail2banWitness, SchemaVersion: "1.0.0"}
		}
		switch w.phase {
		case 0:
			if out.Fail2banState == nil || len(out.Fail2banState.Banned) != 0 {
				return ErrUnavailable
			}
			w.fail.Before = *out.Fail2banState
		case 1:
			if out.SSH == nil || len(out.SSH.Outcomes) != 1 || out.SSH.Outcomes[0] != "allowed" {
				return ErrUnavailable
			}
			w.fail.AdminBefore = *out.SSH
		case 2:
			if out.SSH == nil || len(out.SSH.Outcomes) != 5 {
				return ErrUnavailable
			}
			for _, v := range out.SSH.Outcomes {
				if v != "denied" {
					return ErrUnavailable
				}
			}
			w.fail.Failures = *out.SSH
		case 3:
			if out.Fail2banState == nil || w.guest != in.GuestID || len(out.Fail2banState.Banned) != 1 || out.Fail2banState.Banned[0] != w.fail.Failures.SourceAddress || out.Fail2banState.FailedTotal-w.fail.Before.FailedTotal != 5 {
				return ErrUnavailable
			}
			w.fail.Banned = *out.Fail2banState
			w.banAt = time.Now()
		case 4:
			if out.SSH == nil || len(out.SSH.Outcomes) != 1 || out.SSH.Outcomes[0] != "allowed" {
				return ErrUnavailable
			}
			w.fail.AdminDuring = *out.SSH
		case 5:
			if out.Fail2banState == nil || w.guest != in.GuestID || time.Since(w.banAt) < 600*time.Second {
				return ErrUnavailable
			}
			w.fail.After = *out.Fail2banState
			w.fail.ElapsedNanoseconds = int64(time.Since(w.banAt))
		case 6:
			if out.SSH == nil {
				return ErrUnavailable
			}
			w.fail.AdminAfter = *out.SSH
			raw, _ := json.Marshal(w.fail)
			var measured NativeFail2banWitness
			if json.Unmarshal(raw, &measured) != nil || ValidateFail2banWitness(measured) != nil {
				return ErrUnavailable
			}
		default:
			return ErrUnavailable
		}
		w.phase++
		return nil
	}
	if out.ControlSetup != nil {
		if w.setup != nil || w.guest != in.GuestID {
			return ErrUnavailable
		}
		w.setup = out.ControlSetup
		return nil
	}
	if out.ActionReceipt != nil {
		if w.guest != in.GuestID {
			return ErrUnavailable
		}
		if w.actionBefore == nil {
			w.actionBefore = out.ActionReceipt
			return nil
		}
		if w.actionAfter != nil || w.actionBefore.ClaimDigest != out.ActionReceipt.ClaimDigest || w.actionBefore.ResultDigest != out.ActionReceipt.ResultDigest || hostaction.Digest(w.actionBefore.Bundle) != hostaction.Digest(out.ActionReceipt.Bundle) {
			return ErrUnavailable
		}
		w.actionAfter = out.ActionReceipt
		return nil
	}
	if out.VolumeCase != nil {
		if w.volumeCase != nil || w.guest != in.GuestID || out.VolumeCase.ScenarioID != in.ScenarioID {
			return ErrUnavailable
		}
		w.volumeCase = out.VolumeCase
		return nil
	}
	if out.VolumeSeal != nil {
		if w.volume != nil || w.guest != in.GuestID {
			return ErrUnavailable
		}
		w.volume = out.VolumeSeal
		return nil
	}
	if out.ControlHandoff != nil {
		if w.handoff != nil || w.guest != in.GuestID {
			return ErrUnavailable
		}
		w.handoff = out.ControlHandoff
		return nil
	}
	return ErrUnavailable
}
func (d *ownedGuestLifecycle) attachWitness(b generated.NativeObservationBinding, out *generated.NativeObservation) {
	if b.ScopeDigest != d.scope.digest || b.ControllerInstanceID != d.scope.value.ControllerInstanceID {
		return
	}
	key := witnessKey(generated.NativeStepRequest{ScopeDigest: b.ScopeDigest, ControllerInstanceID: b.ControllerInstanceID, RecoveryEpoch: b.RecoveryEpoch, PlanDigest: b.PlanDigest, ScenarioID: b.ScenarioID, PlanID: b.PlanID, RunID: b.RunID, StepID: b.StepID, LeaseID: b.LeaseID})
	w := d.witnesses[key]
	if w == nil || w.guest != b.GuestID {
		return
	}
	out.RollbackBefore = w.before
	out.RollbackAfter = w.after
	out.VolumeSeal = w.volume
	out.VolumeCase = w.volumeCase
	out.ControlHandoff = w.handoff
	out.ControlSetup = w.setup
	out.ActionReceiptBefore = w.actionBefore
	out.ActionReceiptAfter = w.actionAfter
	if w.phase == 7 {
		out.Fail2banCycle = w.fail
	}
}
