package qualification

import (
	"encoding/json"
	"net/netip"
	"slices"

	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/crypto/ssh"
)

func producerAction(e ProducerExecution) (generated.HostActionRequest, error) {
	var r *generated.HostActionRequest
	for i, op := range e.Plan.Operations {
		if op.OperationID != e.Receipt.OperationID {
			continue
		}
		if r != nil {
			return generated.HostActionRequest{}, ErrUnavailable
		}
		if e.Plan.HostAction != nil {
			r = e.Plan.HostAction
		} else if e.Plan.HostAccessSequence != nil && i < len(e.Plan.HostAccessSequence.Actions) {
			r = &e.Plan.HostAccessSequence.Actions[i]
		}
		if r == nil || op.AdapterID != hostaction.AdapterID || op.ArtifactDigest != hostaction.Digest(*r) || e.Receipt.ArtifactDigest != op.ArtifactDigest || e.Receipt.TargetID != r.HostID || r.HostID != e.Reference.HostID {
			return generated.HostActionRequest{}, ErrUnavailable
		}
	}
	if r == nil || r.ActionInputDigest != hostaction.BytesDigest([]byte(r.ActionInput)) || e.Result == nil || hostaction.ValidateResult(*e.Result) != nil || e.Result.ResultDigest != hostaction.ResultDigest(*e.Result) || e.Result.ResultDigest != e.Receipt.ResultDigest || e.Receipt.Status != "succeeded" || e.Result.Status != "succeeded" || !e.Result.EffectObserved {
		return generated.HostActionRequest{}, ErrUnavailable
	}
	return *r, nil
}

func validateFail2banExecutions(executions []ProducerExecution, observations []generated.NativeObservation) error {
	if len(executions) != 1 || len(observations) != 1 || observations[0].Fail2banCycle == nil {
		return ErrUnavailable
	}
	r, err := producerAction(executions[0])
	if err != nil || r.ActionID != "debian.access.collect" {
		return ErrUnavailable
	}
	input, err := debianaccess.DecodeInput([]byte(r.ActionInput))
	if err != nil {
		return ErrUnavailable
	}
	var w NativeFail2banWitness
	raw, _ := json.Marshal(observations[0].Fail2banCycle)
	if json.Unmarshal(raw, &w) != nil || ValidateFail2banWitness(w) != nil {
		return ErrUnavailable
	}
	allowed := func(address string, prefixes []string) bool {
		a, err := netip.ParseAddr(address)
		if err != nil {
			return false
		}
		for _, text := range prefixes {
			if p, err := netip.ParsePrefix(text); err == nil && p.Contains(a) {
				return true
			}
		}
		return false
	}
	if allowed(w.Failures.SourceAddress, input.RecoverySourcePrefixes) || !allowed(w.Failures.SourceAddress, input.SSHSourcePrefixes) || !allowed(w.AdminBefore.SourceAddress, input.RecoverySourcePrefixes) {
		return ErrUnavailable
	}
	for _, ob := range []NativeSSHObservation{w.Failures, w.AdminBefore, w.AdminDuring, w.AdminAfter} {
		if ob.DestinationHostID != input.HostID || ob.DestinationIdentityDigest != input.HostIdentityDigest || ob.DestinationPort != 22 || ob.DestinationAddress != w.AdminBefore.DestinationAddress || ob.User != w.AdminBefore.User || !slices.Contains(input.SSHUsers, ob.User) {
			return ErrUnavailable
		}
	}
	admin := false
	for _, account := range input.Accounts {
		if account.Role != "human" || account.Name != w.AdminBefore.User {
			continue
		}
		for _, text := range account.PublicKeys {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(text))
			if err == nil && hostaction.BytesDigest(key.Marshal()) == w.AdminBefore.PublicKeyDigest {
				admin = true
			}
		}
	}
	if !admin || w.AdminDuring.PublicKeyDigest != w.AdminBefore.PublicKeyDigest || w.AdminAfter.PublicKeyDigest != w.AdminBefore.PublicKeyDigest {
		return ErrUnavailable
	}
	return nil
}

func validateRollbackExecutions(scenario string, executions []ProducerExecution, observations []generated.NativeObservation) error {
	if len(executions) != 1 || len(observations) != 1 {
		return ErrUnavailable
	}
	e, o := executions[0], observations[0]
	r, err := producerAction(e)
	if err != nil || r.ActionID != "debian.access.apply" || o.RollbackBefore == nil || o.RollbackAfter == nil {
		return ErrUnavailable
	}
	input, err := debianaccess.DecodeInput([]byte(r.ActionInput))
	if err != nil {
		return ErrUnavailable
	}
	var before, after debianaccess.NativeRollbackObservation
	raw, _ := json.Marshal(o.RollbackBefore)
	if json.Unmarshal(raw, &before) != nil {
		return ErrUnavailable
	}
	raw, _ = json.Marshal(o.RollbackAfter)
	if json.Unmarshal(raw, &after) != nil {
		return ErrUnavailable
	}
	if before.RunID != e.Reference.RunID || before.PlanID != e.Reference.PlanID || before.InputDigest != r.ActionInputDigest || before.AuthorizationDigest != input.RollbackDigest || before.BundleDigest != e.Result.BundleDigest || before.HostID != input.HostID || before.HostIdentityDigest != input.HostIdentityDigest || after.CurrentBootID != o.BootID {
		return ErrUnavailable
	}
	return ValidateRollbackWitness(scenario, before, after)
}

func validateVolumeSealExecutions(executions []ProducerExecution, observations []generated.NativeObservation) error {
	if len(executions) != 1 || len(observations) != 1 {
		return ErrUnavailable
	}
	e, o := executions[0], observations[0]
	r, err := producerAction(e)
	if err != nil || r.ActionID != "debian.volume-recovery.verify" || o.VolumeSeal == nil {
		return ErrUnavailable
	}
	var input generated.VolumeRecoveryInput
	if json.Unmarshal([]byte(r.ActionInput), &input) != nil || !exactNativeJSON(generated.SchemaIDVolumeRecoveryInput, input) {
		return ErrUnavailable
	}
	w := o.VolumeSeal
	// Linux's EPERM is 1; the four required memfd seals are 1|2|4|8.
	if w.WriteErrno != 1 || w.ResizeErrno != 1 || w.ReopenWriteErrno != 1 || w.Seals&15 != 15 || w.HeaderBeforeDigest != input.Binding.HeaderDigest || w.HeaderAfterDigest != w.HeaderBeforeDigest || w.CopyBeforeDigest != w.HeaderBeforeDigest || w.CopyAfterDigest != w.CopyBeforeDigest {
		return ErrUnavailable
	}
	matched := false
	for _, m := range e.Result.ControlMeasurements {
		if m.Volume != nil && m.Status == "passed" && hostaction.Digest(m.Volume.Binding) == hostaction.Digest(input.Binding) {
			matched = true
		}
	}
	if !matched {
		return ErrUnavailable
	}
	return nil
}
