//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/debianbaseline"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func executeWitness(ctx context.Context, scope validatedNativeScope, in generated.NativeStepRequest, out generated.NativeStepResult) (generated.NativeStepResult, error) {
	path := filepath.Join("/run/vsk-labs-native", in.ScenarioID+"-"+strconv.FormatInt(in.Ordinal, 10)+".witness.json")
	raw, err := ownedFile(path, 0, 65536)
	var request generated.NativeWitnessRequest
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeWitnessRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &request) != nil || hostaction.Digest(request.Binding) != hostaction.Digest(in) {
		return out, ErrUnavailable
	}
	if (in.Operation == "select-controller") != (request.Kind == "controller-selection") || (request.Kind != "controller-selection" && request.RestoreBinding != nil) || (request.Kind != "replacement-negative" && request.ReplacementRequest != nil) {
		return out, ErrUnavailable
	}
	guest := scope.guests[in.GuestID]
	if request.Kind != "action-receipt" && request.ActionBundle != nil {
		return out, ErrUnavailable
	}
	if request.Kind != "volume-case" && (request.BaselineInput != nil || request.PriorVolumeInput != nil) {
		return out, ErrUnavailable
	}
	switch request.Kind {
	case "controller-selection":
		selected := generated.NativeWitnessRequest{Schema: request.Schema, SchemaVersion: request.SchemaVersion, Binding: request.Binding, Kind: request.Kind, RestoreBinding: request.RestoreBinding}
		if hostaction.Digest(selected) != hostaction.Digest(request) {
			return out, ErrUnavailable
		}
		if request.RestoreBinding == nil || request.ReplacementRequest != nil || in.ScenarioID != "replacement-recovery" || guest.Role != "replacement" {
			return out, ErrUnavailable
		}
		reply, e := callNativeAPI(ctx, scope, nativeAPIPacket{Step: in, Kind: "status"})
		status := reply.Status
		if e != nil || status == nil || !status.ReadAvailable || status.InstanceID != request.RestoreBinding.NewInstanceID || status.RecoveryEpoch != request.RestoreBinding.NextRecoveryEpoch {
			return out, ErrUnavailable
		}
		identity, e := MeasureControllerIdentity(ctx, scope.value, status.InstanceID)
		if e != nil || validateControllerSelection(scope, in, identity, *request.RestoreBinding) != nil {
			return out, ErrUnavailable
		}
		out.ControllerIdentity = &identity
		out.RestoreBinding = request.RestoreBinding
	case "replacement-negative":
		selected := generated.NativeWitnessRequest{Schema: request.Schema, SchemaVersion: request.SchemaVersion, Binding: request.Binding, Kind: request.Kind, ReplacementRequest: request.ReplacementRequest}
		if hostaction.Digest(selected) != hostaction.Digest(request) {
			return out, ErrUnavailable
		}
		if request.ReplacementRequest == nil || in.ScenarioID != "replacement-recovery" || (guest.Role != "controller" && guest.Role != "replacement") {
			return out, ErrUnavailable
		}
		reply, e := callNativeAPI(ctx, scope, nativeAPIPacket{Step: in, Kind: "replacement-negative", Replacement: request.ReplacementRequest})
		if e != nil || reply.Attempt == nil {
			return out, ErrUnavailable
		}
		out.ReplacementRecovery = &generated.NativeReplacementRecoveryWitness{Schema: generated.SchemaIDNativeReplacementRecoveryWitness, SchemaVersion: "1.0.0", ReplacementID: request.ReplacementRequest.ReplacementID, BindingDigest: request.ReplacementRequest.BindingDigest, Attempts: []generated.NativeReplacementRecoveryAttempt{*reply.Attempt}}

	case "rollback":
		if !strings.HasPrefix(in.ScenarioID, "access-rollback-") || request.Fail2banInput != nil || request.VolumeInput != nil || request.RollbackRecordDigest == "" {
			return out, ErrUnavailable
		}
		measured, e := debianaccess.ObserveNativeRollback(ctx, request.RollbackRecordDigest)
		if e != nil {
			return out, e
		}
		if measured.PlanID != in.PlanID || measured.RunID != in.RunID || measured.HostID != guest.HostID || measured.HostIdentityDigest != guest.HostIdentityDigest {
			return out, ErrUnavailable
		}
		encoded, _ := json.Marshal(measured)
		var value generated.NativeRollbackWitness
		if json.Unmarshal(encoded, &value) != nil {
			return out, ErrUnavailable
		}
		value.Schema = generated.SchemaIDNativeRollbackWitness
		value.SchemaVersion = "1.0.0"
		out.Rollback = &value
	case "fail2ban-state":
		if in.ScenarioID != "fail2ban-window" || request.Fail2banInput != nil || request.VolumeInput != nil || request.RollbackRecordDigest != "" {
			return out, ErrUnavailable
		}
		measured, e := ObserveNativeFail2ban(ctx)
		if e != nil {
			return out, e
		}
		encoded, _ := json.Marshal(measured)
		var value generated.NativeFail2banState
		if json.Unmarshal(encoded, &value) != nil {
			return out, ErrUnavailable
		}
		value.Schema = generated.SchemaIDNativeFail2banState
		value.SchemaVersion = "1.0.0"
		out.Fail2banState = &value
	case "ssh-failures", "ssh-admin", "ssh-previous-key", "ssh-current-key":
		credentialSSH := request.Kind == "ssh-previous-key" || request.Kind == "ssh-current-key"
		if (credentialSSH && in.ScenarioID != "native-credential-lifecycle" || !credentialSSH && in.ScenarioID != "fail2ban-window") || request.Fail2banInput == nil || request.VolumeInput != nil || request.RollbackRecordDigest != "" || request.Fail2banInput.Source.HostID != guest.HostID || request.Fail2banInput.Source.IdentityDigest != guest.HostIdentityDigest {
			return out, ErrUnavailable
		}
		input := NativeFail2banInput{request.Fail2banInput.Target, request.Fail2banInput.Source, request.Fail2banInput.Destination}
		var measured NativeSSHObservation
		var e error
		if credentialSSH {
			keyName := "previous-ssh.key"
			if request.Kind == "ssh-current-key" {
				keyName = "current-ssh.key"
			}
			measured, e = observeNativeSSH(ctx, scope.value, input, keyName)
		} else if request.Kind == "ssh-admin" {
			measured, e = ObserveNativeSSHAdmin(ctx, scope.value, input)
		} else {
			measured, e = ObserveNativeSSHFailures(ctx, scope.value, input)
		}
		if e != nil {
			return out, e
		}
		encoded, _ := json.Marshal(measured)
		var value generated.NativeSshObservation
		if json.Unmarshal(encoded, &value) != nil {
			return out, ErrUnavailable
		}
		value.Schema = generated.SchemaIDNativeSshObservation
		value.SchemaVersion = "1.0.0"
		out.SSH = &value
	case "volume-case":
		if request.Fail2banInput != nil || request.RollbackRecordDigest != "" {
			return out, ErrUnavailable
		}
		var measured debianbaseline.NativeVolumeCaseObservation
		var e error
		switch in.ScenarioID {
		case "volume-effective-mapping", "volume-wrong-mapping", "volume-status-no-original-repair":
			if request.BaselineInput == nil || request.VolumeInput != nil || request.PriorVolumeInput != nil || request.BaselineInput.HostID != guest.HostID || request.BaselineInput.HostIdentityDigest != guest.HostIdentityDigest || request.BaselineInput.ProfileLockDigest != scope.value.ProfileLockDigest {
				return out, ErrUnavailable
			}
			measured, e = debianbaseline.ObserveNativeVolumeMappingCase(ctx, in.ScenarioID, *request.BaselineInput)
		case "volume-revoked-binding":
			if request.BaselineInput != nil || request.VolumeInput == nil || request.PriorVolumeInput == nil {
				return out, ErrUnavailable
			}
			for _, v := range []*generated.VolumeRecoveryInput{request.VolumeInput, request.PriorVolumeInput} {
				if v.HostID != guest.HostID || v.HostIdentityDigest != guest.HostIdentityDigest || v.ProfileLockDigest != scope.value.ProfileLockDigest {
					return out, ErrUnavailable
				}
			}
			measured, e = debianbaseline.ObserveNativeVolumeRevokedBinding(ctx, *request.VolumeInput, *request.PriorVolumeInput)
		case "volume-recovery-positive", "volume-wrong-key", "volume-wrong-header", "volume-wrong-slot", "volume-unchanged-after-verification", "volume-inconsistent-redundant-header":
			if request.BaselineInput != nil || request.VolumeInput == nil || request.PriorVolumeInput != nil || request.VolumeInput.HostID != guest.HostID || request.VolumeInput.HostIdentityDigest != guest.HostIdentityDigest || request.VolumeInput.ProfileLockDigest != scope.value.ProfileLockDigest {
				return out, ErrUnavailable
			}
			measured, e = debianbaseline.ObserveNativeVolumeRecoveryCase(ctx, in.ScenarioID, *request.VolumeInput)
		default:
			return out, ErrUnavailable
		}
		if e != nil {
			return out, e
		}
		raw, _ := json.Marshal(measured)
		var value generated.NativeVolumeCaseWitness
		if json.Unmarshal(raw, &value) != nil {
			return out, ErrUnavailable
		}
		value.Schema = generated.SchemaIDNativeVolumeCaseWitness
		value.SchemaVersion = "1.0.0"
		value.BaselineInput = request.BaselineInput
		value.RecoveryInput = request.VolumeInput
		value.PriorRecoveryInput = request.PriorVolumeInput
		out.VolumeCase = &value
	case "volume-seal":
		if in.ScenarioID != "volume-sealed-copy-write-refused" || request.VolumeInput == nil || request.Fail2banInput != nil || request.RollbackRecordDigest != "" || request.VolumeInput.HostID != guest.HostID || request.VolumeInput.HostIdentityDigest != guest.HostIdentityDigest || request.VolumeInput.ProfileLockDigest != scope.value.ProfileLockDigest {
			return out, ErrUnavailable
		}
		measured, _, e := debianbaseline.ObserveNativeVolumeSeal(ctx, *request.VolumeInput)
		if e != nil {
			return out, e
		}
		encoded, _ := json.Marshal(measured)
		var value generated.NativeVolumeSealWitness
		if json.Unmarshal(encoded, &value) != nil {
			return out, ErrUnavailable
		}
		value.Schema = generated.SchemaIDNativeVolumeSealWitness
		value.SchemaVersion = "1.0.0"
		out.VolumeSeal = &value
	case "action-receipt":
		if (in.ScenarioID != "action-replay" && in.ScenarioID != "action-concurrency") || request.ActionBundle == nil || request.VolumeInput != nil || request.Fail2banInput != nil || request.RollbackRecordDigest != "" {
			return out, ErrUnavailable
		}
		b := *request.ActionBundle
		if b.HostID != guest.HostID || b.HostIdentityDigest != guest.HostIdentityDigest || b.PlanID != in.PlanID || b.PlanDigest != in.PlanDigest || b.RunID != in.RunID || b.StepID != in.StepID || b.LeaseID != in.LeaseID || b.RecoveryEpoch != in.RecoveryEpoch {
			return out, ErrUnavailable
		}
		measured, e := hostaction.InspectNativeExecution(ctx, b)
		if e != nil {
			return out, e
		}
		out.ActionReceipt = &generated.NativeActionReceiptWitness{Schema: generated.SchemaIDNativeActionReceiptWitness, SchemaVersion: "1.0.0", Bundle: b, ExecutionDigest: measured.ExecutionDigest, BundleDigest: measured.BundleDigest, ClaimDigest: measured.ClaimDigest, ResultDigest: measured.ResultDigest, Status: measured.Status, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	case "control-setup":
		if in.ScenarioID != "control-setup" || request.VolumeInput != nil || request.Fail2banInput != nil || request.RollbackRecordDigest != "" || request.ActionBundle != nil {
			return out, ErrUnavailable
		}
		measured, e := InspectNativeControlSetup(ctx)
		if e != nil {
			return out, e
		}
		out.ControlSetup = &measured
	case "control-handoff":
		if in.ScenarioID != "control-handoff" || request.VolumeInput != nil || request.Fail2banInput != nil || request.RollbackRecordDigest != "" {
			return out, ErrUnavailable
		}
		measured, e := linuxrole.InspectNativeControlHandoff(ctx)
		if e != nil {
			return out, e
		}
		if measured.Bundle.HostID != guest.HostID || measured.Bundle.HostIdentityDigest != guest.HostIdentityDigest {
			return out, ErrUnavailable
		}
		value := ControlHandoffWitness(measured)
		out.ControlHandoff = &value
	default:
		return out, ErrUnavailable
	}
	out.Status = "completed"
	raw, err = json.Marshal(out)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDNativeStepResult, raw, generated.ContractExact) != nil {
		return out, ErrUnavailable
	}
	return out, nil
}
