package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type CredentialDescriptorOpener func(int) (io.ReadCloser, error)

func openCredentialDescriptor(descriptor int) (io.ReadCloser, error) {
	file := os.NewFile(uintptr(descriptor), "credential-import")
	if file == nil {
		return nil, errors.New("credential descriptor unavailable")
	}
	return file, nil
}

func (app *App) runCredentialImport(ctx context.Context, parsed parsedArguments) int {
	if app.credentials == nil || app.stdin == nil || app.openCredentialDescriptor == nil {
		return app.fail(parsed.output, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "control-operations", generated.RunStatusFailed, false)
	}
	expectedRevision, _ := strconv.ParseInt(parsed.Value(generated.FlagExpectedStateRevision), 10, 64)
	recoveryEpoch, _ := strconv.ParseInt(parsed.Value(generated.FlagRecoveryEpoch), 10, 64)
	input := generated.CredentialImportRequest{
		Schema: generated.SchemaIDCredentialImportRequest, SchemaVersion: generated.RegistrySchemaVersion,
		ExpectedStateRevision: expectedRevision, RecoveryEpoch: recoveryEpoch,
		IdempotencyKey: parsed.Value(generated.FlagIdempotencyKey),
		ReferenceID:    parsed.Value(generated.FlagReferenceID), ConsumerID: parsed.Value(generated.FlagConsumerID),
		PurposeID: parsed.Value(generated.FlagPurposeID), TargetID: parsed.Value(generated.FlagTargetID),
		ResolverID: parsed.Value(generated.FlagResolverID), MaterialVersion: parsed.Value(generated.FlagMaterialVersion),
	}
	input.TargetDigest = credentialref.ImportTargetDigest(input)

	source := app.stdin
	var descriptor io.ReadCloser
	if value := parsed.Value(generated.FlagInputFd); value != "" {
		fd, _ := strconv.Atoi(value)
		var err error
		descriptor, err = app.openCredentialDescriptor(fd)
		if err != nil || descriptor == nil {
			return app.fail(parsed.output, parsed.commandName(), generated.ErrorCodeInputInvalid, "arguments", generated.RunStatusFailed, false)
		}
		defer descriptor.Close()
		source = descriptor
	}

	response, err := app.credentials.ImportCredential(ctx, parsed.Value(generated.FlagConfig), input, source)
	if err != nil {
		return app.failServer(parsed.output, parsed.commandName(), err)
	}
	if response.ExitCode != 0 {
		return app.remoteFailure(parsed.output, response.Raw, response.Result, response.ExitCode)
	}
	if parsed.output == outputJSON {
		return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
	}
	return renderHumanCredentialImport(app.stdout, response.Data)
}
