package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

type ciJobControl interface {
	DraftCIJob(context.Context, string, generated.CiJobDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error)
}

func (app *App) runCIJob(ctx context.Context, mode outputMode, p parsedArguments) int {
	c, ok := app.control.(ciJobControl)
	if !ok || c == nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "ci-job-control", generated.RunStatusFailed, false)
	}
	if app.files == nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "ci-job-request", generated.RunStatusFailed, false)
	}
	raw, e := app.files.Read(ctx, p.Value(generated.FlagFile), 16384)
	var in generated.CiJobDraftRequest
	if e != nil || len(raw) > 16384 || json.Unmarshal(raw, &in) != nil || generated.ValidateContractJSON(generated.SchemaIDCiJobDraftRequest, raw, generated.ContractExact) != nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ci-job-request", generated.RunStatusFailed, false)
	}
	r, e := c.DraftCIJob(ctx, p.Value(generated.FlagConfig), in)
	if e != nil {
		return app.failServer(mode, p.commandName(), e)
	}
	if r.ExitCode != 0 {
		return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
	}
	if _, e = fmt.Fprintf(app.stdout, "Draft declaration: %s (revision %d)\nCommit, plan and acknowledge before apply.\n", r.Data.DeclarationID, r.Data.Revision); e != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
