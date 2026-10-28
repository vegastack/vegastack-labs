package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/principal"
)

type MaintenanceControlOperations interface {
	DiagnoseMaintenance(context.Context, string, string) (localapi.TypedResponse[generated.MaintenanceDiagnosis], error)
	DraftMaintenance(context.Context, string, generated.MaintenanceDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error)
}

func (a *App) runMaintenance(ctx context.Context, mode outputMode, p parsedArguments) int {
	c, ok := a.control.(MaintenanceControlOperations)
	if !ok {
		return a.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "maintenance-control", generated.RunStatusBlocked, false)
	}
	if p.commandName() == generated.CommandNameMaintenanceRepair {
		return a.runMaintenanceRepair(ctx, mode, p, c)
	}
	if p.commandName() == generated.CommandNameMaintenanceDiagnose {
		id := p.Value(generated.FlagHostID)
		if !principal.ValidID(id) {
			return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "host-id", generated.RunStatusFailed, false)
		}
		r, e := c.DiagnoseMaintenance(ctx, p.Value(generated.FlagConfig), id)
		if e != nil {
			return a.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
		}
		d := r.Data
		_, e = fmt.Fprintf(a.stdout, "Host: %s\nBaseline: %s\nNew admission blocked: %t\nExisting workloads: unchanged\n", d.HostID, d.Status, d.NewAdmissionBlocked)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		for _, f := range d.Findings {
			if _, e = fmt.Fprintf(a.stdout, "%s: %s (%s)\n", f.ControlID, f.Status, f.ReasonCode); e != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
		return 0
	}
	if a.files == nil {
		return a.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "maintenance-request", generated.RunStatusFailed, false)
	}
	raw, e := a.files.Read(ctx, p.Value(generated.FlagFile), 32768)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	var q generated.MaintenanceDraftRequest
	if len(raw) > 32768 || generated.ValidateContractJSON(generated.SchemaIDMaintenanceDraftRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &q) != nil {
		return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "maintenance-request", generated.RunStatusFailed, false)
	}
	r, e := c.DraftMaintenance(ctx, p.Value(generated.FlagConfig), q)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	if r.ExitCode != 0 {
		return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
	}
	_, e = fmt.Fprintf(a.stdout, "Inert maintenance record: %s revision %d\nExecution: unsupported; no maintenance action ran.\n", r.Data.DeclarationID, r.Data.Revision)
	if e != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

// The existing host-action API is the sole preparation/authorization boundary.
// Diagnosis adds context; it cannot grant mutation or synthesize policy inputs.
func (a *App) runMaintenanceRepair(ctx context.Context, mode outputMode, p parsedArguments, c MaintenanceControlOperations) int {
	submit, ok := a.control.(interface {
		SubmitHostAction(context.Context, string, generated.HostActionRequest) (localapi.TypedResponse[generated.HostActionSubmission], error)
	})
	if !ok || a.files == nil {
		return a.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "host-action-control", generated.RunStatusBlocked, false)
	}
	raw, e := a.files.Read(ctx, p.Value(generated.FlagFile), 131072)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	var q generated.HostActionRequest
	id := p.Value(generated.FlagHostID)
	if !principal.ValidID(id) || len(raw) > 131072 || generated.ValidateContractJSON(generated.SchemaIDHostActionRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &q) != nil || q.HostID != id || q.ActionID != "debian.baseline.apply" {
		return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "maintenance-repair", generated.RunStatusFailed, false)
	}
	d, e := c.DiagnoseMaintenance(ctx, p.Value(generated.FlagConfig), id)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	if d.ExitCode != 0 {
		return a.remoteFailure(mode, d.Raw, d.Result, d.ExitCode)
	}
	if d.Data.HostID != id || d.Data.StateRevision != q.ExpectedStateRevision || d.Data.RecoveryEpoch != q.RecoveryEpoch {
		return a.fail(mode, p.commandName(), generated.ErrorCodePlanStale, "maintenance-repair", generated.RunStatusBlocked, false)
	}
	r, e := submit.SubmitHostAction(ctx, p.Value(generated.FlagConfig), q)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	if r.ExitCode != 0 {
		return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
	}
	if _, e = fmt.Fprintln(a.stdout, "Single-host baseline repair prepared through the existing host-action API. No host action ran.\nReview the exact plan, obtain its human acknowledgement and apply separately. Stop before another host until actual canary health, drain and recovery checks pass."); e != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return a.printHostDraft(r.Data.DraftID, r.Data.DeclarationID, r.Data.ContentDigest, r.Data.StateRevision, r.Data.RecoveryEpoch)
}
