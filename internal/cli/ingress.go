package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

type IngressControlOperations interface {
	SubmitIngressRolloutEvidence(context.Context, string, generated.IngressRolloutEvidenceRequest) (localapi.TypedResponse[generated.IngressStatusData], error)
	ObserveIngress(context.Context, string, generated.IngressDraftRequest) (localapi.TypedResponse[generated.IngressStatusData], error)
	DraftIngress(context.Context, string, generated.IngressDraftRequest) (localapi.TypedResponse[generated.IngressDraftSubmission], error)
	IngressStatus(context.Context, string, string) (localapi.TypedResponse[generated.IngressStatusData], error)
}

func (a *App) runIngressCommand(ctx context.Context, mode outputMode, p parsedArguments) int {
	c, ok := a.control.(IngressControlOperations)
	if !ok {
		return a.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "ingress-control", generated.RunStatusFailed, false)
	}
	if p.commandName() == generated.CommandNameNetworkIngressStatus {
		r, e := c.IngressStatus(ctx, p.Value(generated.FlagConfig), p.Value(generated.FlagProfileID))
		if e != nil {
			return a.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
		}
		observedAt := r.Data.ObservedAt
		if observedAt == "" {
			observedAt = "none"
		}
		_, e = fmt.Fprintf(a.stdout, "Ingress %s: %s (%s)\nLast observation: %s\nRecorded ownership revision: %d\n", r.Data.ProfileID, r.Data.Status, r.Data.Reason, observedAt, r.Data.OwnershipRevision)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if a.files == nil {
		return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ingress-file", generated.RunStatusFailed, false)
	}
	raw, e := a.files.Read(ctx, p.Value(generated.FlagFile), 65536)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	if p.commandName() == generated.CommandNameNetworkIngressRolloutEvidence {
		var q generated.IngressRolloutEvidenceRequest
		if len(raw) > 16384 || generated.ValidateContractJSON(generated.SchemaIDIngressRolloutEvidenceRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &q) != nil {
			return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ingress-rollout", generated.RunStatusFailed, false)
		}
		r, e := c.SubmitIngressRolloutEvidence(ctx, p.Value(generated.FlagConfig), q)
		if e != nil {
			return a.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
		}
		_, e = fmt.Fprintf(a.stdout, "Tunnel rotation: %s (%s)\nExisting sessions and credential generation require independent proof.\n", r.Data.RotationStage, r.Data.Reason)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if p.commandName() == generated.CommandNameNetworkIngressPilotEvidence {
		var q generated.IngressPilotEvidenceRequest
		if len(raw) > 65536 || generated.ValidateContractJSON(generated.SchemaIDIngressPilotEvidenceRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &q) != nil {
			return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "pilot-evidence", generated.RunStatusFailed, false)
		}
		pilot, ok := a.control.(interface {
			DraftIngressPilotEvidence(context.Context, string, generated.IngressPilotEvidenceRequest) (localapi.TypedResponse[generated.GateEvidenceSubmission], error)
		})
		if !ok {
			return a.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "pilot-evidence", generated.RunStatusFailed, false)
		}
		r, e := pilot.DraftIngressPilotEvidence(ctx, p.Value(generated.FlagConfig), q)
		if e != nil {
			return a.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
		}
		_, e = fmt.Fprintf(a.stdout, "Pilot evidence draft %s\nDeclaration: %s\nPlan and human acknowledgement required. No HA or host qualification.\n", r.Data.EvidenceID, r.Data.ChangeID)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	var q generated.IngressDraftRequest
	if len(raw) > 65536 || generated.ValidateContractJSON(generated.SchemaIDIngressDraftRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &q) != nil {
		return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ingress-request", generated.RunStatusFailed, false)
	}
	if p.commandName() == generated.CommandNameNetworkIngressObserve {
		r, e := c.ObserveIngress(ctx, p.Value(generated.FlagConfig), q)
		if e != nil {
			return a.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
		}
		_, e = fmt.Fprintf(a.stdout, "Ingress observation: %s\nBefore digest: %s\nNo ownership or provider change.\n", r.Data.Reason, r.Data.ObservationDigest)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	r, e := c.DraftIngress(ctx, p.Value(generated.FlagConfig), q)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	if r.ExitCode != 0 {
		return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
	}
	_, e = fmt.Fprintf(a.stdout, "Ingress draft %s\nDeclaration: %s\nPlan and human acknowledgement are required before apply.\n", r.Data.DraftID, r.Data.DeclarationID)
	if e != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
