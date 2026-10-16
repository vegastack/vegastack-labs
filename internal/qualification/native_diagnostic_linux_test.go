//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func nativeDiagnosticRequirements(t *testing.T, err error) []string {
	t.Helper()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing unavailable error: %v", err)
	}
	var diagnostic interface{ nativeStepRequirements() []string }
	if !errors.As(err, &diagnostic) {
		t.Fatal("native refusal lost its bounded failure reason")
	}
	return diagnostic.nativeStepRequirements()
}

func TestNativeStepDiagnosticPreservesOnlyValidatedFailureCode(t *testing.T) {
	for _, status := range []string{"failed", "blocked", "interrupted"} {
		t.Run(status, func(t *testing.T) {
			raw := refusalEnvelope(t, status, generated.CommandNameQualificationStep, generated.ErrorCodePrerequisiteBlocked)
			_, err := readConsoleStep(generated.NativeStepRequest{}, strings.NewReader(string(raw)))
			got := nativeDiagnosticRequirements(t, err)
			want := []string{"native-step-cli-" + status, "native-step-cli-error-" + generated.ErrorCodePrerequisiteBlocked}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("diagnostic %q; want %q", got, want)
			}
			if strings.Contains(strings.Join(got, " "), "private-target-never-exported") {
				t.Fatal("untrusted target exported")
			}
		})
	}
}

func TestNativeStepDiagnosticRejectsUnvalidatedAndUnrelatedFrames(t *testing.T) {
	valid := refusalEnvelope(t, "failed", generated.CommandNameQualificationStep, generated.ErrorCodeIntegrityFailure)
	unknown := strings.Replace(string(valid), generated.ErrorCodeIntegrityFailure, "PRIVATE_UNRECOGNIZED_VALUE", 1)
	_, unknownError := readConsoleStep(generated.NativeStepRequest{}, strings.NewReader(unknown))
	if got := nativeDiagnosticRequirements(t, unknownError); !reflect.DeepEqual(got, []string{"native-step-cli-failed"}) {
		t.Fatalf("unknown error code projected: %q", got)
	}
	for name, raw := range map[string]string{
		"wrong-command": string(refusalEnvelope(t, "failed", generated.CommandNameServerStatus, generated.ErrorCodeIntegrityFailure)),
		"console-text":  "not-json-private-console-text\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readConsoleStep(generated.NativeStepRequest{}, strings.NewReader(raw))
			if got := nativeDiagnosticRequirements(t, err); !reflect.DeepEqual(got, []string{"native-step-result-missing"}) {
				t.Fatalf("unvalidated input projected: %q", got)
			}
		})
	}
	// A correctly identified CLI envelope with an invalid inner native contract
	// must be distinguished from a command that never emitted an envelope.
	var envelope generated.RunResult
	if json.Unmarshal(valid, &envelope) != nil {
		t.Fatal("fixture")
	}
	envelope.Status = "succeeded"
	envelope.Errors = []generated.ResultError{}
	raw, _ := json.Marshal(envelope)
	_, err := readConsoleStep(generated.NativeStepRequest{}, strings.NewReader(string(raw)+"\n"))
	if got := nativeDiagnosticRequirements(t, err); !reflect.DeepEqual(got, []string{"native-step-result-contract"}) {
		t.Fatalf("wrong inner contract diagnostic: %q", got)
	}
}

func TestNativeStepDiagnosticRetainsBoundaryAndPendingReport(t *testing.T) {
	// An unlaunched guest fails at the real pre-command boot identity boundary,
	// before connecting or executing any guest command.
	driver := &ownedGuestLifecycle{scope: validatedNativeScope{guests: map[string]generated.QualificationGuest{"subject": {Role: "subject"}}}}
	_, err := driver.executeConsoleStep(context.Background(), generated.NativeStepRequest{})
	if got := nativeDiagnosticRequirements(t, err); !reflect.DeepEqual(got, []string{"native-step-boot-id-subject"}) {
		t.Fatalf("lost pre-command boundary: %q", got)
	}
	report := generated.NativeReport{PendingRequirements: []string{"baseline-access", "control-setup"}, Scenarios: []generated.ScenarioResult{{ScenarioID: "control-setup", Status: "uncertain", CleanupResult: "passed"}}}
	appendNativeStepDiagnostic(&report, err)
	if !reflect.DeepEqual(report.PendingRequirements, []string{"baseline-access", "control-setup", "native-step-boot-id-subject"}) || report.Scenarios[0].Status != "uncertain" || report.Scenarios[0].CleanupResult != "passed" {
		t.Fatal("diagnostic altered acceptance or cleanup")
	}
	before := append([]string(nil), report.PendingRequirements...)
	privateCause := errors.New("private-error-never-exported")
	appendNativeStepDiagnostic(&report, privateCause)
	if !reflect.DeepEqual(report.PendingRequirements, before) {
		t.Fatal("untyped error projected")
	}
	wrapped := nativeStepError("console-connect", privateCause)
	if !errors.Is(wrapped, privateCause) || strings.Contains(wrapped.Error(), privateCause.Error()) {
		t.Fatal("cause lost or private error leaked")
	}
}
