package cli

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestApplyRequiresExactPlanAndHasNoApprovalFlag(t *testing.T) {
	t.Parallel()

	parsed, failure := parseArguments([]string{"apply", "--config", "profile.json", "--plan-id", "plan-123", "--output", "json"})
	if failure != nil || parsed.Value("--plan-id") != "plan-123" {
		t.Fatalf("apply contract = (%#v, %#v)", parsed, failure)
	}
	if _, failure = parseArguments([]string{"apply", "--config", "profile.json", "--plan-id", "plan-123", "--yes"}); failure == nil {
		t.Fatal("generic approval flag accepted")
	}
}

func TestParsePhase4CommandsRequireBoundedExactSelectors(t *testing.T) {
	t.Parallel()

	valid := [][]string{
		{"plan", "--config", "profile.json", "--declaration-id", "change-1", "--revision", "2"},
		{"apply", "--config", "profile.json", "--plan-id", "plan-1"},
		{"run", "inspect", "--config", "profile.json", "--run-id", "run-1"},
		{"run", "cancel", "--config", "profile.json", "--run-id", "run-1"},
		{"run", "resume", "--config", "profile.json", "--run-id", "run-1"},
	}
	for _, args := range valid {
		if _, failure := parseArguments(args); failure != nil {
			t.Errorf("args %v failure = %#v", args, failure)
		}
	}

	invalid := [][]string{
		{"plan", "--declaration-id", "change-1", "--revision", "2"},
		{"plan", "--config", "profile.json", "--declaration-id", "change-1", "--revision", "0"},
		{"plan", "--config", "profile.json", "--declaration-id", "change-1", "--revision", "9223372036854775808"},
		{"apply", "--config", "profile.json"},
		{"apply", "--config", "profile.json", "--plan-id", strings.Repeat("a", 129)},
		{"run", "inspect", "--config", "profile.json"},
		{"run", "cancel", "--config", "profile.json", "--run-id", "UPPERCASE"},
	}
	for _, args := range invalid {
		if _, failure := parseArguments(args); failure == nil || failure.code != generated.ErrorCodeInputInvalid {
			t.Errorf("args %v failure = %#v", args, failure)
		}
	}
}

func TestParseReleaseFlagsAndSwitches(t *testing.T) {
	t.Parallel()

	parsed, failure := parseArguments([]string{
		"release", "verify",
		"--manifest", "release set/manifest $.json",
		"--policy", "policy.json",
		"--asset", "linux-amd64",
		"--asset", "darwin-arm64",
		"--all",
		"--output", "json",
	})
	if failure != nil {
		t.Fatalf("parseArguments() failure = %#v", failure)
	}
	if got := parsed.Values(generated.FlagAsset); !reflect.DeepEqual(got, []string{"linux-amd64", "darwin-arm64"}) {
		t.Fatalf("asset values = %#v", got)
	}
	if got := parsed.Values(generated.FlagManifest); !reflect.DeepEqual(got, []string{"release set/manifest $.json"}) {
		t.Fatalf("manifest values = %#v", got)
	}
	if !parsed.Switch(generated.FlagAll) || parsed.output != outputJSON {
		t.Fatalf("switch/output not retained: %#v", parsed)
	}
}

func TestParseSwitchDoesNotConsumeFollowingFlag(t *testing.T) {
	t.Parallel()

	parsed, failure := parseArguments([]string{
		"release", "verify", "--manifest", "manifest.json", "--policy", "policy.json", "--all", "--output", "json",
	})
	if failure != nil || !parsed.Switch(generated.FlagAll) || parsed.output != outputJSON {
		t.Fatalf("parseArguments() = (%#v, %#v)", parsed, failure)
	}
}

func TestParseValueFlagStillRequiresValue(t *testing.T) {
	t.Parallel()

	_, failure := parseArguments([]string{
		"release", "verify", "--manifest", "manifest.json", "--policy", "policy.json", "--asset", "--output", "json",
	})
	if failure == nil || failure.code != generated.ErrorCodeInputInvalid {
		t.Fatalf("failure = %#v", failure)
	}
}

func TestParseServerCommandsRequireOneExplicitConfig(t *testing.T) {
	t.Parallel()
	for _, command := range []string{"run", "status"} {
		if _, failure := parseArguments([]string{"server", command}); failure == nil || failure.code != generated.ErrorCodeInputInvalid {
			t.Fatalf("server %s without config failure = %#v", command, failure)
		}
		if _, failure := parseArguments([]string{"server", command, "--config", "one.json", "--config", "two.json"}); failure == nil || failure.code != generated.ErrorCodeInputInvalid {
			t.Fatalf("server %s duplicate config failure = %#v", command, failure)
		}
		parsed, failure := parseArguments([]string{"server", command, "--config", "fixture/server-profile.json"})
		if failure != nil || parsed.Value(generated.FlagConfig) != "fixture/server-profile.json" {
			t.Fatalf("server %s parse = (%#v, %#v)", command, parsed, failure)
		}
	}
}

func TestParseServerAPISSHRequiresFixedBindingArguments(t *testing.T) {
	t.Parallel()

	parsed, parseFailure := parseArguments([]string{"server", "api-ssh", "--config", "profile.json", "--ssh-principal-id", "ssh-principal.operator", "--device-id", "device.operator"})
	if parseFailure != nil || parsed.commandName() != generated.CommandNameServerAPISSH || parsed.Value(generated.FlagSSHPrincipalID) != "ssh-principal.operator" || parsed.Value(generated.FlagDeviceID) != "device.operator" {
		t.Fatalf("server api-ssh parse = (%#v, %#v)", parsed, parseFailure)
	}
	for _, arguments := range [][]string{
		{"server", "api-ssh", "--config", "profile.json", "--device-id", "device.operator"},
		{"server", "api-ssh", "--config", "profile.json", "--ssh-principal-id", "UPPERCASE", "--device-id", "device.operator"},
		{"server", "api-ssh", "--config", "profile.json", "--ssh-principal-id", "ssh-principal.operator", "--device-id", "../../device"},
		{"server", "api-ssh", "--config", "profile.json", "--ssh-principal-id", "ssh-principal.operator", "--device-id", "device.operator", "status"},
		{"server", "api-ssh", "--config", "profile.json", "--ssh-principal-id", "ssh-principal.operator", "--device-id", "device.operator", "--output", "json"},
	} {
		if _, failure := parseArguments(arguments); failure == nil || failure.code != generated.ErrorCodeInputInvalid {
			t.Errorf("server api-ssh args %v failure = %#v", arguments, failure)
		}
	}
}

func TestParseCredentialImportAllowsOnlyBoundedPublicSelectors(t *testing.T) {
	t.Parallel()
	base := credentialImportArguments()
	for _, arguments := range [][]string{
		base,
		append(append([]string{}, base...), "--input-fd", "3"),
		append(append([]string{}, base...), "--input-fd", "1048575"),
	} {
		parsed, failure := parseArguments(arguments)
		if failure != nil || parsed.commandName() != generated.CommandNameCredentialImport {
			t.Fatalf("valid credential import %v = (%#v, %#v)", arguments, parsed, failure)
		}
	}
	for _, extra := range [][]string{
		{"--expected-state-revision", "-1"},
		{"--recovery-epoch", "-1"},
		{"--input-fd", "2"},
		{"--input-fd", "1048576"},
		{"--input-fd", "invalid"},
		{"--value", privateCredentialCanary},
		{"--file", "/private/path/canary"},
	} {
		arguments := append([]string{}, base...)
		if strings.HasPrefix(extra[0], "--expected-") || extra[0] == "--recovery-epoch" {
			for index := range arguments {
				if arguments[index] == extra[0] {
					arguments[index+1] = extra[1]
				}
			}
		} else {
			arguments = append(arguments, extra...)
		}
		if _, failure := parseArguments(arguments); failure == nil || failure.code != generated.ErrorCodeInputInvalid {
			t.Errorf("invalid credential import %v failure = %#v", arguments, failure)
		}
	}
}

func TestParseInventoryDiffRequiresExactlyOneCompleteSelector(t *testing.T) {
	base := []string{"inventory", "diff", "--config", "profile.json"}
	invalid := [][]string{
		base,
		append(append([]string{}, base...), "--draft-id", "draft"),
		append(append([]string{}, base...), "--draft-id", "draft", "--draft-revision", "0"),
		append(append([]string{}, base...), "--file", "/tmp/input", "--format", "typed-json", "--source-revision", "source"),
		append(append([]string{}, base...), "--draft-id", "draft", "--draft-revision", "1", "--file", "/tmp/input", "--format", "typed-json", "--source-revision", "source", "--captured-at", "2026-09-08T06:00:00Z"),
	}
	for _, args := range invalid {
		if _, failure := parseArguments(args); failure == nil || failure.code != generated.ErrorCodeInputInvalid {
			t.Fatalf("args %v failure = %#v", args, failure)
		}
	}
	for _, args := range [][]string{
		append(append([]string{}, base...), "--draft-id", "draft", "--draft-revision", "1"),
		append(append([]string{}, base...), "--file", "/tmp/input", "--format", "typed-json", "--source-revision", "source", "--captured-at", "2026-09-08T06:00:00Z"),
	} {
		if _, failure := parseArguments(args); failure != nil {
			t.Fatalf("args %v failure = %#v", args, failure)
		}
	}
}

func TestParseInventoryRevisionsAndCaptureTime(t *testing.T) {
	validImport := []string{"inventory", "import", "--config", "profile.json", "--file", "/tmp/input", "--format", "typed-json", "--source-revision", "source", "--captured-at", "2026-09-08T06:00:00Z", "--idempotency-key", "opaque"}
	for _, extra := range [][]string{{"--expected-state-revision", "-1"}, {"--expected-state-revision", "9223372036854775808"}} {
		if _, failure := parseArguments(append(append([]string{}, validImport...), extra...)); failure == nil {
			t.Fatalf("accepted invalid revision %v", extra)
		}
	}
	invalidTime := append([]string{}, validImport...)
	for index := range invalidTime {
		if invalidTime[index] == "2026-09-08T06:00:00Z" {
			invalidTime[index] = "2026-09-08T06:00:00+01:00"
		}
	}
	if _, failure := parseArguments(invalidTime); failure == nil {
		t.Fatal("accepted non-UTC capture time")
	}
	if _, failure := parseArguments(append(validImport, "--expected-state-revision", "0")); failure != nil {
		t.Fatalf("rejected zero expected revision: %#v", failure)
	}
}
