package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const controllerSetupMode = "__controller-setup-once"
const controllerSetupAPIMode = "__controller-setup-api"
const controllerPilotHealthMode = "controller-pilot-health"
const controllerSetupRecoveryMode = "__controller-setup-recovery"
const controllerSetupConfig = "/etc/vsk-labs/control/server.json"
const controllerSetupMaximumInput = 65536

var errControllerSetup = errors.New("controller setup did not complete; inspect the recorded run before retrying")

func decodeControllerSetupRequest(raw []byte) (generated.ControllerSetupClaimRequest, linuxrole.ControllerInstallInput, error) {
	var q generated.ControllerSetupClaimRequest
	var in linuxrole.ControllerInstallInput
	if len(raw) == 0 || len(raw) > controllerSetupMaximumInput || strictjson.Scan(context.Background(), raw, strictjson.Limits{MaxDepth: 32}) != nil || generated.ValidateContractJSON(generated.SchemaIDControllerSetupClaimRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &q) != nil {
		return q, in, errControllerSetup
	}
	in, e := linuxrole.DecodeControllerInstallInput([]byte(q.InputJSON))
	if e != nil {
		return q, in, errControllerSetup
	}
	canonical, e := json.Marshal(in)
	if e != nil || string(canonical) != q.InputJSON {
		return q, in, errControllerSetup
	}
	return q, in, nil
}

func validateControllerSetupClaim(q generated.ControllerSetupClaimRequest, in linuxrole.ControllerInstallInput, expected generated.ControllerSetupPilotPolicy, claim generated.ControllerSetupClaim, now time.Time) error {
	b, e := json.Marshal(claim)
	if e != nil || generated.ValidateContractJSON(generated.SchemaIDControllerSetupClaim, b, generated.ContractExact) != nil || hostaction.Digest(claim.Policy) != hostaction.Digest(expected) || claim.InputJSON != q.InputJSON || hostaction.Digest(expected) != in.ControllerSetupPilotDigest {
		return errControllerSetup
	}
	p, r, l := claim.Plan, claim.Run, claim.Lease
	if p.PlanID != q.Reference.PlanID || p.PlanDigest != q.Reference.PlanDigest || p.Binding.RecoveryEpoch != q.Reference.RecoveryEpoch || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.HostAction != nil || p.HostRoleScope != nil || p.HostAccessSequence != nil || len(p.Operations) != 1 || r.Status != "running" || len(r.Steps) != 1 || generated.ValidateExecutorLeaseBinding(p, r, l) != nil {
		return errControllerSetup
	}
	op := p.Operations[0]
	if op.AdapterID != "core.controller-setup" || op.OperationType != "controller.setup.bootstrap" || op.TargetID != expected.HostID || op.ArtifactDigest != hostaction.Digest(expected) || op.InputDigest != hostaction.BytesDigest([]byte(q.InputJSON)) || op.Idempotent || l.Status != "active" {
		return errControllerSetup
	}
	deadline, e := time.Parse(time.RFC3339, claim.ExpiresAt)
	if e != nil || claim.ExpiresAt != l.MaximumExpiresAt || !now.Before(deadline) || deadline.Sub(now) > time.Duration(generated.ExecutorLeaseSeconds)*time.Second {
		return errControllerSetup
	}
	if in.Handoff != nil {
		handoffDeadline, e := time.Parse(time.RFC3339, in.Handoff.ExpiresAt)
		if e != nil || !now.Before(handoffDeadline) || handoffDeadline.After(deadline) {
			return errControllerSetup
		}
	}
	expectedClaim := hostaction.Digest([]string{p.PlanID, p.PlanDigest, r.RunID, l.LeaseID, hostaction.Digest(expected), op.InputDigest, expected.AdministratorPrincipalID, l.MaximumExpiresAt})
	if expectedClaim != claim.ClaimDigest {
		return errControllerSetup
	}
	return nil
}
