package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"strconv"
)

type CIEnrollmentControlOperations interface {
	ListCIEnrollments(context.Context, string, string, int) (localapi.TypedResponse[generated.CiEnrollmentList], error)
	GetCIEnrollment(context.Context, string, string) (localapi.TypedResponse[generated.CiEnrollmentRecord], error)
	DraftCIEnrollment(context.Context, string, generated.CiEnrollmentDraftRequest) (localapi.TypedResponse[generated.DeclarationRevision], error)
}

func (app *App) runCIEnrollment(ctx context.Context, mode outputMode, p parsedArguments) int {
	c, ok := app.control.(CIEnrollmentControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodePrerequisiteBlocked, "ci-enrollment-control", generated.RunStatusBlocked, false)
	}
	config := p.Value(generated.FlagConfig)
	switch p.commandName() {
	case generated.CommandNameCiEnrollmentList:
		after, n := p.Value(generated.FlagAfter), 50
		if v := p.Value(generated.FlagLimit); v != "" {
			var e error
			n, e = strconv.Atoi(v)
			if e != nil || n < 1 || n > 100 || strconv.Itoa(n) != v {
				return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ci-enrollment-query", generated.RunStatusFailed, false)
			}
		}
		if after != "" && !principal.ValidID(after) {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ci-enrollment-query", generated.RunStatusFailed, false)
		}
		r, e := c.ListCIEnrollments(ctx, config, after, n)
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		for _, v := range r.Data.Enrollments {
			if _, e = fmt.Fprintf(app.stdout, "%s\t%s\tJob admission: %s\n", v.Definition.EnrollmentID, v.RegistrationStatus, v.AdmissionStatus); e != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
		if len(r.Data.Enrollments) == 0 {
			_, e = fmt.Fprintln(app.stdout, "No CI registrations in current scope.")
		}
		if r.Data.NextAfter != "" {
			_, e = fmt.Fprintf(app.stdout, "Continue after: %s\n", r.Data.NextAfter)
		}
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	case generated.CommandNameCiEnrollmentShow:
		id := p.Value(generated.FlagEnrollmentID)
		if !principal.ValidID(id) {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ci-enrollment-id", generated.RunStatusFailed, false)
		}
		r, e := c.GetCIEnrollment(ctx, config, id)
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		_, e = fmt.Fprintf(app.stdout, "CI enrollment: %s\nRegistration: %s\nJob admission: %s\n", r.Data.Definition.EnrollmentID, r.Data.RegistrationStatus, r.Data.AdmissionStatus)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	case generated.CommandNameCiEnrollmentDraft:
		var input generated.CiEnrollmentDraftRequest
		if app.files == nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "ci-enrollment-request", generated.RunStatusFailed, false)
		}
		raw, e := app.files.Read(ctx, p.Value(generated.FlagFile), 16384)
		if e != nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ci-enrollment-request", generated.RunStatusFailed, false)
		}
		if len(raw) > 16384 || json.Unmarshal(raw, &input) != nil || generated.ValidateContractJSON(generated.SchemaIDCiEnrollmentDraftRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ci-enrollment-request", generated.RunStatusFailed, false)
		}
		r, e := c.DraftCIEnrollment(ctx, config, input)
		if e != nil {
			return app.failServer(mode, p.commandName(), e)
		}
		if r.ExitCode != 0 {
			return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
		}
		_, e = fmt.Fprintf(app.stdout, "Draft declaration: %s (revision %d)\nCommit, plan and acknowledge before apply; job admission remains not-qualified.\n", r.Data.DeclarationID, r.Data.Revision)
		if e != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "ci-enrollment-request", generated.RunStatusFailed, false)
}
