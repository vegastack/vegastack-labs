package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

// runBackupCommand handles `backup policy draft`: it reads one exact typed
// backup-policy-draft-request JSON file and submits it as an inert draft. It
// activates nothing; an exact plan and human approval remain required to apply.
func (app *App) runBackupCommand(ctx context.Context, mode outputMode, parsed parsedArguments) int {
	if parsed.commandName() == generated.CommandNameBackupOffsiteRetirementDryRun {
		control, ok := app.control.(BackupOffsiteRetirementControlOperations)
		if !ok || app.files == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-offsite-retirement-control", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 65536)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		var input generated.BackupOffsiteRetirementDryRunRequest
		if generated.ValidateContractJSON(generated.SchemaIDBackupOffsiteRetirementDryRunRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-offsite-retirement-dry-run-contract", generated.RunStatusFailed, false)
		}
		response, err := control.DryRunBackupOffsiteRetirement(ctx, parsed.Value(generated.FlagConfig), input)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		data := response.Data
		if _, err := fmt.Fprintf(app.stdout, "Off-site retirement dry-run selects generation %s (point %s) with intent %s.\nRules (%d -> %d, complete set %s):\n", data.GenerationID, data.PointID, data.IntentDigest, data.PreRuleCount, data.SurvivorRuleCount, data.RuleSetDigest); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		for _, rule := range data.Rules {
			if _, err := fmt.Fprintf(app.stdout, "  %s  %s\n", rule.RuleID, rule.Prefix); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
		if _, err := fmt.Fprintf(app.stdout, "Objects (%d, reclaim %d bytes, max %d objects/%d bytes):\n", data.ObjectCount, data.ExpectedReclaimBytes, data.MaxWorkObjects, data.MaxMutationBytes); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		for _, object := range data.Objects {
			if _, err := fmt.Fprintf(app.stdout, "  %s  %d bytes  %s\n", object.Key, object.Bytes, object.Digest); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
		if _, err := fmt.Fprintf(app.stdout, "Survivors (%d retained bytes, rule digest %s):\n", data.RetainedBytes, data.SurvivorRuleDigest); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		for _, survivor := range data.SurvivorBindings {
			if _, err := fmt.Fprintf(app.stdout, "  %s  generation %s  key %s  dependencies %s\n", survivor.PointID, survivor.GenerationID, survivor.ReferenceID, survivor.DependencyDigest); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
		if _, err := fmt.Fprintf(app.stdout, "Authority: source revision %d, state revision %d, recovery epoch %d, one-owner proof %s.\nG-008: bundle %s, qualification %s, PUT cutoff %s, multipart cutoff %s, exclusive admin %s.\nCredentials: lock-admin %s (%s), retention-delete %s (%s).\n", data.SourceRevision, data.StateRevision, data.RecoveryEpoch, data.OneOwnerProofID, data.G008BundleDigest, data.QualificationDigest, data.PutCutoffDigest, data.MultipartCutoffDigest, data.ExclusiveAdminDigest, data.LockAdminReferenceID, data.LockAdminFingerprint, data.RetentionReferenceID, data.RetentionFingerprint); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if parsed.commandName() == generated.CommandNameBackupOffsiteRetirementStage {
		control, ok := app.control.(BackupOffsiteRetirementControlOperations)
		if !ok || app.files == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-offsite-retirement-control", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 65536)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		var input generated.BackupOffsiteRetirementStageRequest
		if generated.ValidateContractJSON(generated.SchemaIDBackupOffsiteRetirementStageRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-offsite-retirement-stage-contract", generated.RunStatusFailed, false)
		}
		response, err := control.StageBackupOffsiteRetirement(ctx, parsed.Value(generated.FlagConfig), input)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		if _, err := fmt.Fprintf(app.stdout, "Staged off-site retirement %s for generation %s with %d survivor rules.\n", response.Data.IntentID, response.Data.GenerationID, response.Data.SurvivorRuleCount); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if parsed.commandName() == generated.CommandNameBackupRetirementDraft {
		control, ok := app.control.(BackupRetirementControlOperations)
		if !ok || app.files == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-retirement-control", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 65536)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		var input generated.BackupRetirementDraftRequest
		if generated.ValidateContractJSON(generated.SchemaIDBackupRetirementDraftRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-retirement-draft-contract", generated.RunStatusFailed, false)
		}
		response, err := control.SubmitBackupRetirementDraft(ctx, parsed.Value(generated.FlagConfig), input)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		if _, err := fmt.Fprintf(app.stdout, "Inert retirement draft %s selects %d target points; change %s requires an exact destructive human-approved plan.\n", response.Data.DraftID, len(response.Data.TargetPointIDs), response.Data.ChangeID); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if parsed.commandName() == generated.CommandNameBackupRetentionLocksDraft {
		control, ok := app.control.(BackupRetentionLockControlOperations)
		if !ok || app.files == nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-retention-lock-control", generated.RunStatusFailed, false)
		}
		raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 65536)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		var input generated.BackupRetentionLockDraftRequest
		if generated.ValidateContractJSON(generated.SchemaIDBackupRetentionLockDraftRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-retention-lock-draft-contract", generated.RunStatusFailed, false)
		}
		response, err := control.SubmitBackupRetentionLockDraft(ctx, parsed.Value(generated.FlagConfig), input)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		if _, err := fmt.Fprintf(app.stdout, "Inert retention-lock catalog %s (digest %s); change %s requires an exact destructive human-approved plan.\n", response.Data.DraftID, response.Data.CatalogDigest, response.Data.ChangeID); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	control, ok := app.control.(BackupControlOperations)
	if !ok {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-control", generated.RunStatusFailed, false)
	}
	if app.files == nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-file", generated.RunStatusFailed, false)
	}
	config := parsed.Value(generated.FlagConfig)
	raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 65536)
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	if generated.ValidateContractJSON(generated.SchemaIDBackupPolicyDraftRequest, raw, generated.ContractExact) != nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-policy-draft-contract", generated.RunStatusFailed, false)
	}
	var input generated.BackupPolicyDraftRequest
	if json.Unmarshal(raw, &input) != nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-policy-draft-contract", generated.RunStatusFailed, false)
	}
	response, err := control.SubmitBackupPolicyDraft(ctx, config, input)
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	if response.ExitCode != 0 {
		return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
	}
	if _, err := fmt.Fprintf(app.stdout, "Inert backup policy draft %s (digest %s). Bind it through the declaration/plan/run flow and obtain human approval before any backup runs.\n", response.Data.DraftID, response.Data.PolicyDigest); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

func (app *App) runBackupOperation(ctx context.Context, mode outputMode, parsed parsedArguments) int {
	control, ok := app.control.(BackupRunControlOperations)
	if !ok {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-control", generated.RunStatusFailed, false)
	}
	config := parsed.Value(generated.FlagConfig)
	if parsed.commandName() == generated.CommandNameBackupStatus {
		response, err := control.BackupStatus(ctx, config)
		if err != nil {
			return app.failServer(mode, parsed.commandName(), err)
		}
		if response.ExitCode != 0 {
			return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
		}
		if mode == outputJSON {
			return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
		}
		lastGood := "none"
		if response.Data.LastGoodPointID != nil {
			lastGood = *response.Data.LastGoodPointID
		}
		_, err = fmt.Fprintf(app.stdout, "Backup status %s\nReason %s\nSource %s\nProof %s\nLast good point %s\nRecovery required %t\nState revision %d\nRecovery epoch %d\nSafe next action %s\n", response.Data.Status, response.Data.ReasonCode, response.Data.SourceKind, response.Data.ProofClass, lastGood, response.Data.RecoveryRequired, response.Data.StateRevision, response.Data.RecoveryEpoch, response.Data.SafeNextAction)
		if err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		return 0
	}
	if app.files == nil {
		return app.fail(mode, parsed.commandName(), generated.ErrorCodeIntegrityFailure, "backup-file", generated.RunStatusFailed, false)
	}
	raw, err := app.files.Read(ctx, parsed.Value(generated.FlagFile), 4096)
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	var response localapi.TypedResponse[generated.BackupJob]
	switch parsed.commandName() {
	case generated.CommandNameBackupRun:
		if generated.ValidateContractJSON(generated.SchemaIDBackupRunRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-run-contract", generated.RunStatusFailed, false)
		}
		var input generated.BackupRunRequest
		if json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-run-contract", generated.RunStatusFailed, false)
		}
		response, err = control.RunBackup(ctx, config, input)
	case generated.CommandNameBackupVerify:
		if generated.ValidateContractJSON(generated.SchemaIDBackupVerifyRequest, raw, generated.ContractExact) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-verify-contract", generated.RunStatusFailed, false)
		}
		var input generated.BackupVerifyRequest
		if json.Unmarshal(raw, &input) != nil {
			return app.fail(mode, parsed.commandName(), generated.ErrorCodeInputInvalid, "backup-verify-contract", generated.RunStatusFailed, false)
		}
		response, err = control.VerifyBackup(ctx, config, input)
	}
	if err != nil {
		return app.failServer(mode, parsed.commandName(), err)
	}
	if response.ExitCode != 0 {
		return app.remoteFailure(mode, response.Raw, response.Result, response.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, response.Raw, response.ExitCode)
	}
	_, err = fmt.Fprintf(app.stdout, "Backup job %s: %s.\n", response.Data.JobID, response.Data.Status)
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
