//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/server"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

// This finite local administrator entry has no target, path or command flags.
// Every effect follows a current server-owned acknowledged claim. Root never
// opens SQLite or acts as the human API principal.
func runControllerSetupMode(ctx context.Context, args []string) (bool, int) {
	if len(args) == 0 || args[0] != controllerSetupMode && args[0] != controllerSetupAPIMode && args[0] != controllerPilotHealthMode && args[0] != controllerSetupRecoveryMode {
		return false, 0
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if args[0] == controllerSetupAPIMode {
		if len(args) != 2 || os.Getuid() == 0 || os.Geteuid() != os.Getuid() || controllerSetupAPIChild(ctx, args[1]) != nil {
			return true, 1
		}
		return true, 0
	}
	if len(args) != 1 {
		return true, 1
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, controllerSetupMaximumInput+1))
	if e != nil || len(raw) > controllerSetupMaximumInput {
		return true, 1
	}
	if args[0] == controllerSetupRecoveryMode {
		var q generated.ControllerSetupRecoveryRequest
		if os.Getuid() == 0 || os.Geteuid() != os.Getuid() || generated.ValidateContractJSON(generated.SchemaIDControllerSetupRecoveryRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &q) != nil {
			return true, 1
		}
		operations := server.NewOperations(result.BuildInfo{ToolVersion: toolVersion, ReleaseBuildID: releaseBuildID}, newRequestID)
		response, e := operations.PrepareControllerSetupRecovery(ctx, controllerSetupConfig, q)
		if e != nil || response.ExitCode != 0 {
			return true, 1
		}
		if _, e = os.Stdout.Write(response.Raw); e != nil {
			return true, 1
		}
		return true, 0
	}
	if args[0] == controllerPilotHealthMode {
		in, e := linuxrole.DecodeControllerInstallInput(raw)
		if e != nil || os.Getuid() == 0 || os.Geteuid() != os.Getuid() || os.Getuid() != int(in.AdministratorUID) || os.Getgid() != int(in.AdministratorGID) || linuxrole.WriteControllerPilotHealth(ctx, in, os.Stdout) != nil {
			return true, 1
		}
		return true, 0
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 || executeControllerSetup(ctx, raw, os.Stdout) != nil {
		// No OS/provider error text or credential content is projected.
		_, _ = io.WriteString(os.Stderr, errControllerSetup.Error()+"\n")
		return true, 1
	}
	return true, 0
}

func controllerSetupProtectedPolicy(ctx context.Context, in linuxrole.ControllerInstallInput) (generated.ControllerSetupPilotPolicy, error) {
	for _, uid := range []int64{in.AdministratorUID, in.ServiceUID} {
		p, e := serverconfig.NewLoader(uint32(uid)).Load(ctx, controllerSetupConfig)
		if e != nil || p.ControllerSetupPilot == nil {
			continue
		}
		v := *p.ControllerSetupPilot
		if hostaction.Digest(v) != in.ControllerSetupPilotDigest || v.AdministratorUID != in.AdministratorUID || v.AdministratorGID != in.AdministratorGID || v.ServiceUID != in.ServiceUID || v.ServiceGID != in.ServiceGID || v.ControllerInstanceID != in.ControllerInstanceID || v.ControllerMachineIDDigest != in.ControllerMachineIDDigest || v.RecoveryEpoch != in.RecoveryEpoch || v.RecoveryImageDigest != in.RecoveryImageDigest || v.ExecutableDigest != in.ExecutableDigest {
			return generated.ControllerSetupPilotPolicy{}, errControllerSetup
		}
		return v, nil
	}
	return generated.ControllerSetupPilotPolicy{}, errControllerSetup
}

func controllerSetupAdminCall(ctx context.Context, action string, policy generated.ControllerSetupPilotPolicy, q any) ([]byte, error) {
	if action != "claim" && action != "receipt" || !serverconfig.ValidControllerSetupPilot(policy) {
		return nil, errControllerSetup
	}
	b, e := json.Marshal(q)
	if e != nil || len(b) > controllerSetupMaximumInput {
		return nil, errControllerSetup
	}
	executable, e := os.Executable()
	if e != nil {
		return nil, errControllerSetup
	}
	c := exec.CommandContext(ctx, executable, controllerSetupAPIMode, action)
	c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	c.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(policy.AdministratorUID), Gid: uint32(policy.AdministratorGID), Groups: []uint32{}}}
	c.Stdin = bytes.NewReader(b)
	// The generated claim/run envelopes are bounded separately from requests.
	var out controllerSetupOutput
	c.Stdout = &out
	if c.Run() != nil || out.overflow {
		return nil, errControllerSetup
	}
	return out.Bytes(), nil
}

type controllerSetupOutput struct {
	bytes.Buffer
	overflow bool
}

func (o *controllerSetupOutput) Write(b []byte) (int, error) {
	if o.Len()+len(b) > 4<<20 {
		o.overflow = true
		return 0, errControllerSetup
	}
	return o.Buffer.Write(b)
}

func executeControllerSetup(ctx context.Context, raw []byte, out io.Writer) error {
	q, in, e := decodeControllerSetupRequest(raw)
	if e != nil {
		return e
	}
	policy, e := controllerSetupProtectedPolicy(ctx, in)
	if e != nil {
		return e
	}
	claimRaw, e := controllerSetupAdminCall(ctx, "claim", policy, q)
	var claim localapi.TypedResponse[generated.ControllerSetupClaim]
	if e != nil || json.Unmarshal(claimRaw, &claim) != nil || claim.ExitCode != 0 || validateControllerSetupClaim(q, in, policy, claim.Data, time.Now().UTC()) != nil {
		return errControllerSetup
	}
	deadline, _ := time.Parse(time.RFC3339, claim.Data.ExpiresAt)
	effectCtx, cancel := context.WithDeadline(ctx, deadline.Add(-2*time.Second))
	changed, status, digest, effectErr := linuxrole.RunControllerInstall(effectCtx, in, toolVersion)
	cancel()
	if effectErr != nil || digest == "" {
		status = "failed"
		if changed {
			status = "partial"
		}
		digest = hostaction.Digest([]string{"controller-setup-incomplete", claim.Data.ClaimDigest, status})
	}
	receipt := generated.ControllerSetupReceiptRequest{Schema: generated.SchemaIDControllerSetupReceiptRequest, SchemaVersion: "1.0.0", ClaimDigest: claim.Data.ClaimDigest, RunID: claim.Data.Run.RunID, LeaseID: claim.Data.Lease.LeaseID, RecoveryEpoch: in.RecoveryEpoch, ResultDigest: digest, InputJSON: q.InputJSON, Status: status}
	response, e := controllerSetupAdminCall(ctx, "receipt", policy, receipt)
	var recorded localapi.TypedResponse[generated.Run]
	if e != nil || json.Unmarshal(response, &recorded) != nil || recorded.ExitCode != 0 {
		return errControllerSetup
	}
	if _, e = out.Write(recorded.Raw); e != nil {
		return errControllerSetup
	}
	if effectErr != nil || recorded.Data.Status != "succeeded" {
		return errControllerSetup
	}
	return nil
}

func controllerSetupAPIChild(ctx context.Context, action string) error {
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, controllerSetupMaximumInput+1))
	if e != nil || len(raw) > controllerSetupMaximumInput {
		return errControllerSetup
	}
	operations := server.NewOperations(result.BuildInfo{ToolVersion: toolVersion, ReleaseBuildID: releaseBuildID}, newRequestID)
	switch action {
	case "claim":
		q, _, e := decodeControllerSetupRequest(raw)
		if e != nil {
			return e
		}
		response, e := operations.ClaimControllerSetup(ctx, controllerSetupConfig, q)
		if e != nil || response.ExitCode != 0 {
			return errControllerSetup
		}
		return json.NewEncoder(os.Stdout).Encode(response)
	case "receipt":
		var q generated.ControllerSetupReceiptRequest
		if generated.ValidateContractJSON(generated.SchemaIDControllerSetupReceiptRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &q) != nil {
			return errControllerSetup
		}
		response, e := operations.SubmitControllerSetupReceipt(ctx, controllerSetupConfig, q)
		if e != nil || response.ExitCode != 0 {
			return errControllerSetup
		}
		return json.NewEncoder(os.Stdout).Encode(response)
	}
	return errControllerSetup
}
