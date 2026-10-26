package cli

import (
	"context"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/principal"
)

type ServiceConfigurationControlOperations interface {
	GetServiceConfiguration(context.Context, string, string) (localapi.TypedResponse[generated.ServiceConfigurationStatus], error)
}

func (app *App) runServiceConfiguration(ctx context.Context, mode outputMode, p parsedArguments) int {
	control, ok := app.control.(ServiceConfigurationControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "service-configuration-control", generated.RunStatusBlocked, false)
	}
	id := p.Value(generated.FlagServiceID)
	if !principal.ValidID(id) {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "service-id", generated.RunStatusFailed, false)
	}
	response, e := control.GetServiceConfiguration(ctx, p.Value(generated.FlagConfig), id)
	if e != nil {
		return app.failServer(mode, p.commandName(), e)
	}
	if response.ExitCode != 0 {
		return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
	}
	d := response.Data
	_, e = fmt.Fprintf(app.stdout, "Service: %s\nDesired settings: %s\nPlacement: %s (%s)\nObserved: %s\n", d.ServiceID, d.ConfigurationDigest, d.PlacementState, d.PlacementReason, serviceObservationTime(d.ObservedAt))
	if e == nil && d.Configuration != nil {
		c := d.Configuration
		_, e = fmt.Fprintf(app.stdout, "Environment: %s\nCPU: %d%%\nMemory: %d bytes\nStorage reservation: %d bytes\nPort: %d\nExposure: %s\nHealth: %s (expected %d)\nData: %s\nMigration: %s\nRollback: %s\nBackup policy: %s\n", c.EnvironmentClass, c.CPUQuotaPercent, c.MemoryBytes, c.StorageBytes, c.Port, c.Exposure, c.HealthPath, c.HealthExpectedStatus, c.DataClass, c.Migration, c.Rollback, c.BackupPolicyID)
	}
	if e != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
