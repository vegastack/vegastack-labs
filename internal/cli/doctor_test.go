package cli

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"strings"
	"testing"
)

func TestDoctorReportsFirstInvariantWithoutLeakingOrMutating(t *testing.T) {
	for _, tc := range []struct {
		name, mode, source, want string
		read                     bool
		code                     int
	}{
		{"healthy", "ready", "healthy", "", true, 0},
		{"stale", "ready", "stale", "source-stale", true, 5},
		{"unknown", "ready", "unknown", "source-unknown", true, 6},
		{"failed", "ready", "failed", "source-failed", true, 6},
		{"unavailable", "ready", "unavailable", "source-unavailable", true, 6},
		{"database-first", "safe-mode", "stale", "database-mode", true, 8},
		{"read-denied", "ready", "healthy", "read-unavailable", false, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := generated.ApiSummaryData{DatabaseMode: tc.mode, ReadAvailable: tc.read, WorstSourceState: tc.source, StateRevision: 7, RecoveryEpoch: 2}
			stub := &stubControlOperations{summaryResponse: operationResponse(t, "api.v1.summary.get", false, 2, 7, data)}
			code, out, errout := runTestAppWithOptions(t, context.Background(), []string{"doctor", "--config", "profile.json", "--output", "json"}, nil, WithControlOperations(stub, nil))
			if code != tc.code || errout != "" || !strings.Contains(out, `"command":"doctor"`) || !strings.Contains(out, `"stateRevision":7`) || !strings.Contains(out, `"changed":false`) || tc.want != "" && !strings.Contains(out, tc.want) {
				t.Fatalf("%d %s %s", code, out, errout)
			}
		})
	}
}
func TestDoctorDeniedUnavailableAndUnclassifiedFailureStaySanitized(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code int
		want string
	}{
		{failure.New(generated.ErrorCodeAuthorizationDenied, "summary", false), 4, "AUTHORIZATION_DENIED"},
		{failure.New(generated.ErrorCodeDependencyUnavailable, "control-service", true), 6, "DEPENDENCY_UNAVAILABLE"},
		{errors.New("secret-private-canary"), 8, "INTEGRITY_FAILURE"},
	} {
		stub := &stubControlOperations{err: tc.err}
		code, out, errout := runTestAppWithOptions(t, context.Background(), []string{"doctor", "--config", "profile.json", "--output", "json"}, nil, WithControlOperations(stub, nil))
		if code != tc.code || !strings.Contains(out, tc.want) || strings.Contains(out+errout, "secret-private-canary") {
			t.Fatalf("%d %s %s", code, out, errout)
		}
	}
}
func TestDoctorHumanNextActionDoesNotSuggestBypass(t *testing.T) {
	data := generated.ApiSummaryData{DatabaseMode: "ready", ReadAvailable: true, WorstSourceState: "stale", StateRevision: 7, RecoveryEpoch: 2}
	stub := &stubControlOperations{summaryResponse: operationResponse(t, "api.v1.summary.get", false, 2, 7, data)}
	code, out, errout := runTestAppWithOptions(t, context.Background(), []string{"doctor", "--config", "profile.json"}, nil, WithControlOperations(stub, nil))
	if code != 5 || errout != "" || !strings.Contains(out, "Next:") || !strings.Contains(out, "approved observation workflow") {
		t.Fatalf("%d %s %s", code, out, errout)
	}
}

func TestDoctorWithoutControlCannotGuessHealth(t *testing.T) {
	code, out, stderr := runTestAppWithOptions(t, context.Background(), []string{"doctor", "--config", "profile.json", "--output", "json"}, nil)
	if code != 6 || stderr != "" || !strings.Contains(out, "doctor-summary") {
		t.Fatalf("%d %s %s", code, out, stderr)
	}
}
