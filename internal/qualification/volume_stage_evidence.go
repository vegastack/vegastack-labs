package qualification

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func validateVolumeCaseExecutions(scenario string, executions []ProducerExecution, observations []generated.NativeObservation) error {
	count := 1
	if scenario == "volume-revoked-binding" {
		count = 2
	}
	if len(executions) != count || len(observations) != count {
		return ErrUnavailable
	}
	var w *generated.NativeVolumeCaseWitness
	for _, o := range observations {
		if o.VolumeCase != nil {
			if w != nil {
				return ErrUnavailable
			}
			w = o.VolumeCase
		}
	}
	if w == nil || !exactNativeJSON(generated.SchemaIDNativeVolumeCaseWitness, *w) || w.ScenarioID != scenario || w.HeaderBeforeDigest != w.HeaderAfterDigest || w.OriginalPolicyDigest != w.OriginalPolicyAfterDigest || w.TestedCopyBeforeDigest != w.TestedCopyAfterDigest {
		return ErrUnavailable
	}
	seenCurrent, seenPrior := false, false
	for i, e := range executions {
		o := observations[i]
		r, err := producerAction(e)
		if err != nil {
			return err
		}
		var b generated.HostVolumeBinding
		var kind string
		priorExecution := false
		switch scenario {
		case "volume-effective-mapping", "volume-wrong-mapping", "volume-status-no-original-repair":
			if r.ActionID != "debian.volume.observe" || w.BaselineInput == nil || w.RecoveryInput != nil || w.PriorRecoveryInput != nil || len(w.BaselineInput.Volumes) != 1 || hostaction.Digest(*w.BaselineInput) != w.InputDigest {
				return ErrUnavailable
			}
			var in generated.DebianBaselineInput
			if json.Unmarshal([]byte(r.ActionInput), &in) != nil || hostaction.Digest(in) != w.InputDigest {
				return ErrUnavailable
			}
			b = in.Volumes[0]
			kind = "mapping"
			seenCurrent = true
		default:
			if r.ActionID != "debian.volume-recovery.verify" || w.RecoveryInput == nil || w.BaselineInput != nil || hostaction.Digest(*w.RecoveryInput) != w.InputDigest {
				return ErrUnavailable
			}
			var in generated.VolumeRecoveryInput
			if json.Unmarshal([]byte(r.ActionInput), &in) != nil {
				return ErrUnavailable
			}
			if hostaction.Digest(in) == w.InputDigest {
				if seenCurrent {
					return ErrUnavailable
				}
				seenCurrent = true
			} else if scenario == "volume-revoked-binding" && w.PriorRecoveryInput != nil && hostaction.Digest(in) == hostaction.Digest(*w.PriorRecoveryInput) {
				if seenPrior {
					return ErrUnavailable
				}
				seenPrior = true
				priorExecution = true
			} else {
				return ErrUnavailable
			}
			b = in.Binding
			kind = "recovery"
		}
		if priorExecution {
			// The prior successful action supplies its immutable input and receipt;
			// the postrotation physical test belongs only to the current action.
			if o.VolumeCase != nil {
				return ErrUnavailable
			}
		} else {
			if o.VolumeCase == nil || hostaction.Digest(*o.VolumeCase) != hostaction.Digest(*w) {
				return ErrUnavailable
			}
			at, err := time.Parse(time.RFC3339, o.ObservedAt)
			measured, me := time.Parse(time.RFC3339, w.ObservedAt)
			if err != nil || me != nil || at.Before(measured) || at.Sub(measured) > 30*time.Second {
				return ErrUnavailable
			}
		}
		currentBinding := b
		if scenario == "volume-revoked-binding" {
			currentBinding = w.RecoveryInput.Binding
		}
		if hostaction.Digest(currentBinding) != w.BindingDigest || b.HeaderDigest != w.HeaderBeforeDigest {
			return ErrUnavailable
		}
		matched := false
		for _, m := range e.Result.ControlMeasurements {
			if m.Volume != nil && m.Status == "passed" && m.Volume.Kind == kind && hostaction.Digest(m.Volume.Binding) == hostaction.Digest(b) {
				matched = true
			}
		}
		if !matched {
			return ErrUnavailable
		}
	}
	if !seenCurrent {
		return ErrUnavailable
	}
	switch scenario {
	case "volume-wrong-key", "volume-wrong-header", "volume-wrong-slot", "volume-wrong-mapping", "volume-revoked-binding":
		if w.ObservedOutcome != "refused" {
			return ErrUnavailable
		}
	case "volume-inconsistent-redundant-header", "volume-status-no-original-repair":
		// An intact primary may remain readable. Qualification concerns preservation
		// of the original and sealed damaged copy, not a fabricated tool refusal.
	default:
		if w.ObservedOutcome != "accepted" {
			return ErrUnavailable
		}
	}
	if scenario == "volume-wrong-header" || scenario == "volume-inconsistent-redundant-header" || scenario == "volume-status-no-original-repair" {
		if w.TestedCopyBeforeDigest == w.HeaderBeforeDigest {
			return ErrUnavailable
		}
	} else if w.TestedCopyBeforeDigest != w.HeaderBeforeDigest {
		return ErrUnavailable
	}
	if w.RecoveryInput != nil {
		slot := w.RecoveryInput.Binding.KeySlot
		if scenario == "volume-wrong-slot" {
			if w.TestedKeySlot == slot {
				return ErrUnavailable
			}
		} else if w.TestedKeySlot != slot {
			return ErrUnavailable
		}
	}
	if scenario == "volume-revoked-binding" {
		if !seenPrior || w.PriorRecoveryInput == nil {
			return ErrUnavailable
		}
		if !debianbaseline.VolumeRecoveryRotationMatches(*w.RecoveryInput, *w.PriorRecoveryInput) || w.OriginalPolicyDigest != w.RecoveryInput.Binding.RecoveryReferenceDigest {
			return ErrUnavailable
		}
	} else if w.PriorRecoveryInput != nil {
		return ErrUnavailable
	}
	return nil
}

func isVolumeCaseScenario(s string) bool {
	return strings.HasPrefix(s, "volume-") && s != "volume-sealed-copy-write-refused"
}
