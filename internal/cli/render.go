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
		if command.Availability == availabilityPlanned {
			continue
		}
		if _, err := fmt.Fprintf(output, "  %-24s %s\n", commandName(command.Path), command.Summary); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
		for _, flag := range command.Flags {
			if _, err := fmt.Fprintf(output, "    %-22s %s", flag.Name+" <"+flag.ValueName+">", flag.Summary); err != nil {
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
		if command.Availability != availabilityPlanned {
			continue
		}
		if _, err := fmt.Fprintf(output, "  %-24s %s\n", commandName(command.Path), command.Summary); err != nil {
			return exitCodeFor(generated.ErrorCodeIntegrityFailure)
		}
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
