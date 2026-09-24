package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func renderHumanHelp(output io.Writer) int {
	if _, err := fmt.Fprintln(output, "vsk-labs commands"); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	if _, err := fmt.Fprintln(output, "\nAvailable commands:"); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	for _, command := range generated.Commands {
		if command.Availability == generated.AvailabilityPlanned {
			continue
		}
		if _, err := fmt.Fprintf(output, "  %-24s %s\n", commandName(command.Path), command.Summary); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		for _, flag := range command.Flags {
			label := flag.Name
			if flag.Kind == generated.FlagKindValue {
				label += " <" + flag.ValueName + ">"
			}
			if _, err := fmt.Fprintf(output, "    %-22s %s", label, flag.Summary); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
			if len(flag.Enum) != 0 {
				if _, err := fmt.Fprintf(output, " Allowed: %s.", strings.Join(flag.Enum, ", ")); err != nil {
					return exitCodeFor(generated.ErrorCodeIntegrityFailure)
				}
			}
			if _, err := fmt.Fprintln(output); err != nil {
				return exitCodeFor(generated.ErrorCodeIntegrityFailure)
			}
		}
	}
	if _, err := fmt.Fprintln(output, "\nPlanned commands (unavailable):"); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	for _, command := range generated.Commands {
		if command.Availability != generated.AvailabilityPlanned {
			continue
		}
		if _, err := fmt.Fprintf(output, "  %-24s %s\n", commandName(command.Path), command.Summary); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	return 0
}

func renderHumanReleaseInspect(output io.Writer, data generated.ReleaseInspectData) int {
	if _, err := fmt.Fprintf(output,
		"Release %s\nBuild %s\nSource %s\nPlatform %s/%s (schema %d)\nVerification not performed\nCompatible assets: %s\n",
		data.ReleaseID, data.BuildID, data.SourceRevision, data.PlatformOS, data.PlatformArchitecture,
		data.PlatformSchemaMajor, strings.Join(data.CompatibleAssetIDs, ", "),
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

func renderHumanReleaseVerify(output io.Writer, data generated.ReleaseVerifyData) int {
	if _, err := fmt.Fprintf(output,
		"Release %s\nBuild %s\nSource %s\nVerification %s\nSupplied policy %s\n",
		data.ReleaseID, data.BuildID, data.SourceRevision, data.VerificationStatus, data.PolicySHA256,
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	for _, asset := range data.Assets {
		if _, err := fmt.Fprintf(output, "Asset %s: %s (%s, %d bytes)\n", asset.AssetID, asset.Status, asset.Digest, asset.Size); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	return 0
}

func renderHumanServerStatus(output io.Writer, data generated.ServerStatusData, exitCode int) int {
	if _, err := fmt.Fprintf(output,
		"State %s\nRead available %t\nMutation available %t\nRemote read %s\nRemote read reason %s\nState revision %d\nRecovery epoch %d\n",
		data.State, data.ReadAvailable, data.MutationAvailable, data.RemoteReadState, data.RemoteReadReason, data.StateRevision, data.RecoveryEpoch,
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return exitCode
}

func renderHumanCredentialImport(output io.Writer, data generated.CredentialImportSubmission) int {
	if _, err := fmt.Fprintf(output,
		"Credential draft %s\nReference %s\nStatus %s\nCiphertext fingerprint %s\nState revision %d\nRecovery epoch %d\n",
		data.DraftID, data.ReferenceID, data.Status, data.CiphertextFingerprint, data.StateRevision, data.RecoveryEpoch,
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

func renderHumanSummary(output io.Writer, data generated.ApiSummaryData) int {
	if _, err := fmt.Fprintf(output,
		"Database mode %s\nRead available %t\nMutation available %t\nDrafts %d (valid %d, blocked %d)\nLast event %d\nSources %d (healthy %d, stale %d, unknown %d, unavailable %d, failed %d)\nWorst source state %s\nState revision %d\nRecovery epoch %d\n",
		data.DatabaseMode, data.ReadAvailable, data.MutationAvailable, data.DraftCount, data.ValidDraftCount, data.BlockedDraftCount, data.LastEventID,
		data.SourceCounts.Total, data.SourceCounts.Healthy, data.SourceCounts.Stale, data.SourceCounts.Unknown, data.SourceCounts.Unavailable, data.SourceCounts.Failed, data.WorstSourceState,
		data.StateRevision, data.RecoveryEpoch,
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

func renderHumanDatabaseStatus(output io.Writer, data generated.DatabaseStatusData) int {
	if _, err := fmt.Fprintf(output,
		"Mode %s\nSchema version %d\nSQLite version %s\nMutation enabled %t\nRecovery pending %t\nIntegrity %s\n",
		data.Mode, data.SchemaVersion, data.SQLiteVersion, data.MutationEnabled, data.RecoveryPending, data.IntegrityStatus,
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	if data.LastIntegrityCheckAt != nil {
		if _, err := fmt.Fprintf(output, "Last integrity check %s\n", *data.LastIntegrityCheckAt); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	if data.SafeModeReason != "" {
		if _, err := fmt.Fprintf(output, "Safe mode reason %s\n", data.SafeModeReason); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	return 0
}

func renderHumanAuditCheckpoints(output io.Writer, data generated.BrowserAuditCheckpointListData) int {
	if _, err := fmt.Fprintf(output, "Audit checkpoints %d\nState revision %d\nRecovery epoch %d\n", len(data.Items), data.StateRevision, data.RecoveryEpoch); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	for _, checkpoint := range data.Items {
		if _, err := fmt.Fprintf(output, "Checkpoint %s events %d-%d status %s reason %s source %s proof %s verification %s digest %s\n", checkpoint.CheckpointID, checkpoint.FirstEventID, checkpoint.LastEventID, checkpoint.Status, checkpoint.ReasonCode, checkpoint.SourceKind, checkpoint.ProofClass, checkpoint.VerificationStatus, checkpoint.ChainDigest); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	return 0
}

func renderHumanAuditVerification(output io.Writer, data generated.BrowserAuditVerificationData) int {
	if _, err := fmt.Fprintf(output, "Audit verification %s\nReason %s\nSource %s\nProof %s\nIndependent match %t\nLast anchored sequence %d\nPre-anchor %t\nState revision %d\nRecovery epoch %d\nSafe next action %s\n", data.Status, data.ReasonCode, data.SourceKind, data.ProofClass, data.IndependentMatch, data.LastAnchoredSequence, data.PreAnchor, data.StateRevision, data.RecoveryEpoch, data.SafeNextAction); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	if data.Status == "incident" {
		if _, err := fmt.Fprintln(output, "Mutations are blocked. Compare the independent signed checkpoint, fence the old controller, and use the documented recovery plan."); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	return 0
}

func renderHumanInventoryImport(output io.Writer, data generated.InventoryImportData) int {
	if _, err := fmt.Fprintf(output,
		"Inert draft %s revision %d\nValidation %s\nCreated %t\nRecords assets=%d nodes=%d aliases=%d addresses=%d observations=%d\nFindings %d\nState revision %d\nRecovery epoch %d\n",
		data.DraftID, data.DraftRevision, data.ValidationStatus, data.Created, data.Counts.Assets, data.Counts.Nodes, data.Counts.Aliases, data.Counts.Addresses, data.Counts.Observations, len(data.Findings), data.StateRevision, data.RecoveryEpoch,
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

func renderHumanInventoryDiff(output io.Writer, data generated.InventoryDiffData) int {
	if _, err := fmt.Fprintf(output,
		"Candidate %s %s\nBaseline inert draft %s revision %d\nChanges added=%d removed=%d changed=%d unchanged=%d\nFindings %d\nState revision %d\nRecovery epoch %d\n",
		data.CandidateKind, data.CandidateDigest, data.BaselineDraft.DraftID, data.BaselineDraft.DraftRevision, data.Counts.Added, data.Counts.Removed, data.Counts.Changed, data.Counts.Unchanged, len(data.Findings), data.StateRevision, data.RecoveryEpoch,
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	for _, record := range data.Records {
		if _, err := fmt.Fprintf(output, "%s %s %s (%d field changes)\n", record.Change, record.RecordKind, record.LocalID, len(record.Fields)); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	return 0
}

func renderHumanInventoryExport(output io.Writer, data generated.InventoryExportData) int {
	if _, err := fmt.Fprintf(output,
		"Verified inert-draft export %s\nDraft %s revision %d\nContent digest %s\nSignature %s key %s fingerprint %s\nVerification %s\nPublication %s\nState revision %d\nRecovery epoch %d\n",
		data.ExportID, data.Draft.DraftID, data.Draft.DraftRevision, data.ContentDigest, data.Algorithm, data.KeyID, data.KeyFingerprint, data.VerificationStatus, data.PublicationStatus, data.StateRevision, data.RecoveryEpoch,
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

func renderHumanPlan(output io.Writer, data generated.Plan) int {
	approval := "explicit human acknowledgement required"
	if data.AuthorizationBranch == "preauthorized" {
		approval = "preauthorized by current server policy"
	}
	if _, err := fmt.Fprintf(output, "Plan %s\nDigest %s\nDeclaration %s revision %d\nRisk %s\nAuthorization %s\nApproval requirement %s\nExpires %s\n", data.PlanID, data.PlanDigest, data.DeclarationID, data.Binding.DeclarationRevision, data.Risk, data.AuthorizationBranch, approval, data.ExpiresAt); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	for _, operation := range data.Operations {
		if _, err := fmt.Fprintf(output, "Operation %d target %s via %s\n", operation.Sequence, operation.TargetID, operation.AdapterID); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	return 0
}

func renderHumanRun(output io.Writer, data generated.RunPresentation) int {
	run := data.Run
	if _, err := fmt.Fprintf(output, "Run %s\nPlan %s\nDigest %s\nStatus %s\nCompleted work %d\n", run.RunID, run.PlanID, run.PlanDigest, run.Status, len(data.CompletedWork)); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	for _, step := range data.CompletedWork {
		if _, err := fmt.Fprintf(output, "  Step %s sequence %d target %s status %s progress %s\n", step.StepID, step.Sequence, step.TargetID, step.Status, step.ProgressState); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	if _, err := fmt.Fprintf(output, "Incomplete work %d\n", len(data.IncompleteWork)); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	for _, step := range data.IncompleteWork {
		if _, err := fmt.Fprintf(output, "  Step %s sequence %d target %s status %s progress %s\n", step.StepID, step.Sequence, step.TargetID, step.Status, step.ProgressState); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	if _, err := fmt.Fprintf(output, "Verification %s\nRollback %s\nChanged %t\nNext safe action: %s\n", run.VerificationStatus, run.RollbackStatus, run.Changed, data.NextSafeAction); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}

func renderHumanVersion(output io.Writer, build BuildInfo) int {
	if _, err := fmt.Fprintf(output, "vsk-labs %s\ncontract %s\nbuild %s\n", build.ToolVersion, generated.RegistrySchemaVersion, build.ReleaseBuildID); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	if build.SourceRevision != nil {
		if _, err := fmt.Fprintf(output, "source %s\n", *build.SourceRevision); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
	}
	return 0
}

func renderHumanFailure(output io.Writer, code, target string, exitCode int) int {
	if _, err := fmt.Fprintf(output, "vsk-labs: %s (%s)\n", code, target); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return exitCode
}
