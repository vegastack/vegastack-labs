package cli

import (
	"context"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

type OperationsMonitoringControl interface {
	OperationsStatus(context.Context, string, bool) (localapi.TypedResponse[generated.OperationsStatusData], error)
}

func (a *App) runOperationsMonitoring(ctx context.Context, mode outputMode, p parsedArguments) int {
	c, ok := a.control.(OperationsMonitoringControl)
	if !ok {
		return a.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "operations-control", generated.RunStatusFailed, false)
	}
	r, e := c.OperationsStatus(ctx, p.Value(generated.FlagConfig), p.commandName() == generated.CommandNameOperationsObserve)
	if e != nil {
		return a.failServer(mode, p.commandName(), e)
	}
	if r.ExitCode != 0 {
		return a.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(a.stdout, r.Raw, r.ExitCode)
	}
	_, e = fmt.Fprintf(a.stdout, "Operational observations: %d; notifications: %s; recent deliveries: %d\n", len(r.Data.Alerts), r.Data.Notifications, len(r.Data.Deliveries))
	for _, alert := range r.Data.Alerts {
		if e == nil {
			_, e = fmt.Fprintf(a.stdout, "%s %s %s occurrences=%d\n", alert.Key, alert.ObservationState, alert.Status, alert.Occurrences)
		}
	}
	if e != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
