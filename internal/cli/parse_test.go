package cli

import (
	"reflect"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

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
