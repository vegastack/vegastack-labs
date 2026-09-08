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
		"State %s\nRead available %t\nMutation available %t\nState revision %d\nRecovery epoch %d\n",
		data.State, data.ReadAvailable, data.MutationAvailable, data.StateRevision, data.RecoveryEpoch,
	); err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return exitCode
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
