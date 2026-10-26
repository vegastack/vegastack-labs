package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

type MeshControlOperations interface {
	ObserveMesh(context.Context, string, generated.MeshDraftRequest) (localapi.TypedResponse[generated.MeshStatusData], error)
	DraftMesh(context.Context, string, generated.MeshDraftRequest) (localapi.TypedResponse[generated.MeshDraftSubmission], error)
	MeshStatus(context.Context, string, string) (localapi.TypedResponse[generated.MeshStatusData], error)
}

func (a *App) runMeshCommand(ctx context.Context, mode outputMode, p parsedArguments) int {
	c, ok := a.control.(MeshControlOperations)
	if !ok {
		return a.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "mesh-control", generated.RunStatusFailed, false)
	}
	if p.commandName() == generated.CommandNameNetworkMeshStatus {
		r, e := c.MeshStatus(ctx, p.Value(generated.FlagConfig), p.Value(generated.FlagProfileID))
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
		_, e = fmt.Fprintf(a.stdout, "Mesh %s: %s (%s)\nLast observation: %s\nRecorded ownership revision: %d\n", r.Data.ProfileID, r.Data.Status, r.Data.Reason, observedAt, r.Data.OwnershipRevision)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if a.files == nil {
		return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "mesh-file", generated.RunStatusFailed, false)
	}
	raw, e := a.files.Read(ctx, p.Value(generated.FlagFile), 65536)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	var q generated.MeshDraftRequest
	if len(raw) > 65536 || generated.ValidateContractJSON(generated.SchemaIDMeshDraftRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &q) != nil {
		return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "mesh-request", generated.RunStatusFailed, false)
	}
	if p.commandName() == generated.CommandNameNetworkMeshObserve {
		r, e := c.ObserveMesh(ctx, p.Value(generated.FlagConfig), q)
		if e != nil {
			return a.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
		}
		_, e = fmt.Fprintf(a.stdout, "Mesh observation: %s\nBefore digest: %s\nNo ownership or provider change.\n", r.Data.Reason, r.Data.ObservationDigest)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	r, e := c.DraftMesh(ctx, p.Value(generated.FlagConfig), q)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	if r.ExitCode != 0 {
		return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
	}
	_, e = fmt.Fprintf(a.stdout, "Mesh draft %s\nDeclaration: %s\nPlan and human acknowledgement are required before apply.\n", r.Data.DraftID, r.Data.DeclarationID)
	if e != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
