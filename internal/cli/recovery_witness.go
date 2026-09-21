package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"runtime"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/recovery"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

type witnessCollectionInput struct {
	Binding  recovery.WitnessBinding        `json:"binding"`
	Required []recovery.BoundaryRequirement `json:"required"`
}

// This command is a finite custodian operation. A production adapter registry
// is deliberately absent until each direct-denial boundary is qualified.
func (app *App) runRecoveryWitnessCollect(ctx context.Context, mode outputMode, parsed parsedArguments) int {
	const command = generated.CommandNameRecoveryWitnessCollect
	if runtime.GOOS != "linux" || mode != outputJSON || app.files == nil || app.witnessPinLoader == nil {
		return app.fail(mode, command, generated.ErrorCodePrerequisiteBlocked, "recovery-witness", generated.RunStatusBlocked, false)
	}
	keyFD, keyErr := strconv.Atoi(parsed.Value("--signing-key-fd"))
	materialFD, materialErr := strconv.Atoi(parsed.Value("--material-fd"))
	if keyErr != nil || materialErr != nil || keyFD < 3 || materialFD < 3 || keyFD == materialFD || keyFD > 1048575 || materialFD > 1048575 {
		return app.fail(mode, command, generated.ErrorCodeInputInvalid, "arguments", generated.RunStatusFailed, false)
	}
	raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 65536)
	if err != nil || strictjson.Scan(ctx, raw, strictjson.Limits{MaxDepth: 12}) != nil {
		return app.fail(mode, command, generated.ErrorCodeInputInvalid, "recovery-witness-input", generated.RunStatusFailed, false)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var input witnessCollectionInput
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.Required) == 0 || len(input.Required) > 256 {
		return app.fail(mode, command, generated.ErrorCodeInputInvalid, "recovery-witness-input", generated.RunStatusFailed, false)
	}
	pin, err := app.witnessPinLoader(input.Binding)
	if err != nil {
		return app.fail(mode, command, generated.ErrorCodePrerequisiteBlocked, "recovery-witness", generated.RunStatusBlocked, false)
	}
	key, err := openCredentialDescriptor(keyFD)
	if err != nil {
		return app.fail(mode, command, generated.ErrorCodePrerequisiteBlocked, "recovery-witness", generated.RunStatusBlocked, false)
	}
	material, err := openCredentialDescriptor(materialFD)
	if err != nil {
		_ = key.Close()
		return app.fail(mode, command, generated.ErrorCodePrerequisiteBlocked, "recovery-witness", generated.RunStatusBlocked, false)
	}
	signed, envelope, err := recovery.CollectWitness(ctx, recovery.CollectRequest{
		Pin: pin, Binding: input.Binding, Required: input.Required, Adapters: app.witnessAdapters,
		SigningKey: key, Material: material, Now: time.Now,
	})
	if err != nil {
		return app.fail(mode, command, generated.ErrorCodePrerequisiteBlocked, "recovery-witness", generated.RunStatusBlocked, false)
	}
	artifact, err := recovery.EncodeSignedWitness(signed)
	if err != nil {
		return app.fail(mode, command, generated.ErrorCodeIntegrityFailure, "recovery-witness", generated.RunStatusFailed, false)
	}
	protected, err := json.Marshal(envelope)
	if err != nil {
		return app.fail(mode, command, generated.ErrorCodeIntegrityFailure, "recovery-witness", generated.RunStatusFailed, false)
	}
	data := generated.RecoveryWitnessCollectionData{
		Schema: generated.SchemaIDRecoveryWitnessCollectionData, SchemaVersion: "1.0.0",
		ManifestDigest: pin.ManifestDigest, ExpiresAt: signed.Payload.ExpiresAt.UTC().Format(time.RFC3339),
		SignedArtifactBase64:    base64.RawURLEncoding.EncodeToString(artifact),
		ProtectedEnvelopeBase64: base64.RawURLEncoding.EncodeToString(protected),
	}
	encoded, err := json.Marshal(data)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRecoveryWitnessCollectionData, encoded, generated.ContractExact) != nil {
		return app.fail(mode, command, generated.ErrorCodeIntegrityFailure, "recovery-witness", generated.RunStatusFailed, false)
	}
	return app.succeedData(command, data)
}
