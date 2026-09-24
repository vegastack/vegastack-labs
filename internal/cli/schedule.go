package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

type ScheduleControlOperations interface {
	SubmitScheduledPolicyDraft(context.Context, string, generated.ScheduledJobPolicy) (localapi.TypedResponse[generated.ScheduledPolicyDraftSubmission], error)
	DispatchSchedule(context.Context, string, string) (localapi.TypedResponse[generated.ScheduledJob], error)
	CancelSchedule(context.Context, string, string) (localapi.TypedResponse[generated.ScheduledJob], error)
}

type ScheduleReadOperations interface {
	ListScheduledPolicies(context.Context, string) (localapi.TypedResponse[generated.BrowserScheduledJobPolicyListData], error)
	InspectScheduledPolicy(context.Context, string, string) (localapi.TypedResponse[generated.BrowserScheduledJobPolicy], error)
}

func (app *App) runScheduleCommand(ctx context.Context, mode outputMode, parsed parsedArguments) int {
	if parsed.commandName() == generated.CommandNameScheduleList {
		reads, ok := app.control.(ScheduleReadOperations)
		if !ok {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "schedule-read-control", generated.RunStatusFailed, false)
		}
		response, err := reads.ListScheduledPolicies(ctx, parsed.Value(generated.FlagConfig))
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		for _, policy := range response.Data.Items {
			if _, err := fmt.Fprintf(app.stdout, "%s revision %d: %s (%s)\n", policy.PolicyID, policy.Revision, policy.Status, policy.ReasonCode); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
		return 0
	}
	if parsed.commandName() == generated.CommandNameScheduleInspect {
		reads, ok := app.control.(ScheduleReadOperations)
		if !ok {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "schedule-read-control", generated.RunStatusFailed, false)
		}
		response, err := reads.InspectScheduledPolicy(ctx, parsed.Value(generated.FlagConfig), parsed.Value(generated.FlagPolicyID))
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "%s revision %d: %s (%s), action %s\n", response.Data.PolicyID, response.Data.Revision, response.Data.Status, response.Data.ReasonCode, response.Data.ActionKind)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	control, ok := app.control.(ScheduleControlOperations)
	if !ok {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "schedule-control", generated.RunStatusFailed, false)
	}
	if parsed.commandName() == generated.CommandNameSchedulePolicyDraft {
		if app.files == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "schedule-file", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 65536)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		var policy generated.ScheduledJobPolicy
		if json.Unmarshal(raw, &policy) != nil || generated.ValidateContractJSON(generated.SchemaIDScheduledJobPolicy, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "scheduled-policy-contract", generated.RunStatusFailed, false)
		}
		response, err := control.SubmitScheduledPolicyDraft(ctx, parsed.Value(generated.FlagConfig), policy)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Stored inert scheduled policy draft %s for policy %s revision %d (digest %s); activation still requires its exact human-approved plan.\n", response.Data.DraftID, response.Data.PolicyID, response.Data.PolicyRevision, response.Data.PolicyDigest)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if parsed.commandName() == generated.CommandNameScheduleCancel {
		response, err := control.CancelSchedule(ctx, parsed.Value(generated.FlagConfig), parsed.Value(generated.FlagJobID))
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		_, err = fmt.Fprintf(app.stdout, "Scheduled job %s is %s (%s).\n", response.Data.JobID, response.Data.Status, response.Data.ReasonCode)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	response, err := control.DispatchSchedule(ctx, parsed.Value(generated.FlagConfig), parsed.Value(generated.FlagPolicyID))
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	if response.ExitCode != 0 {
		return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
	}
	_, err = fmt.Fprintf(app.stdout, "Scheduled job %s is %s (%s).\n", response.Data.JobID, response.Data.Status, response.Data.ReasonCode)
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
