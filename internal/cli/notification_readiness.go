package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

type NotificationReadinessControl interface {
	NotificationReadiness(context.Context, string, generated.NotificationReadinessRequest) (localapi.TypedResponse[generated.DeclarationRevision], error)
}

func (a *App) runNotificationReadiness(ctx context.Context, mode outputMode, p parsedArguments) int {
	c, ok := a.control.(NotificationReadinessControl)
	if !ok {
		return a.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "notification-readiness-control", generated.RunStatusFailed, false)
	}
	raw, e := a.files.Read(ctx, p.Value(generated.FlagFile), 8192)
	if e != nil || len(raw) > 8192 || generated.ValidateContractJSON(generated.SchemaIDNotificationReadinessRequest, raw, generated.ContractExact) != nil {
		return a.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "notification-readiness-request", generated.RunStatusFailed, false)
	}
	var q generated.NotificationReadinessRequest
	if json.Unmarshal(raw, &q) != nil {
		return exitCodeFor(generated.ErrorCodeInputInvalid)
	}
	r, e := c.NotificationReadiness(ctx, p.Value(generated.FlagConfig), q)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	if r.ExitCode != 0 {
		return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
	}
	_, e = fmt.Fprintf(a.stdout, "Prepared %s declaration %s. Plan and acknowledge its exact operation before apply; preparation sends nothing.\n", q.Action, r.Data.DeclarationID)
	if e != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
