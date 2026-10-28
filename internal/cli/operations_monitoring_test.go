package cli

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

type operationsFixture struct {
	*stubControlOperations
	calls   int
	observe bool
}

func (f *operationsFixture) OperationsStatus(_ context.Context, _ string, observe bool) (localapi.TypedResponse[generated.OperationsStatusData], error) {
	f.calls++
	f.observe = observe
	return localapi.TypedResponse[generated.OperationsStatusData]{Data: generated.OperationsStatusData{Alerts: []generated.OperationsAlert{}, Notifications: "disabled"}}, nil
}
func TestOperationsCommandsCannotUploadHealthOrSelectProviderTargets(t *testing.T) {
	for _, action := range []string{"status", "observe"} {
		f := &operationsFixture{stubControlOperations: successfulControlOperations(t)}
		code, out, _ := runTestAppWithOptions(t, context.Background(), []string{"operations", action, "--config", "fixture/profile.json"}, nil, WithControlOperations(f, &stubFileReader{}))
		if code != 0 || f.calls != 1 || f.observe != (action == "observe") || !strings.Contains(out, "notifications: disabled") {
			t.Fatal(code, out, f)
		}
		for _, args := range [][]string{{"--state", "healthy"}, {"--target", "vsk-node-04"}, {"--file", "health.json"}} {
			before := f.calls
			argv := append([]string{"operations", action, "--config", "fixture/profile.json"}, args...)
			code, _, _ = runTestAppWithOptions(t, context.Background(), argv, nil, WithControlOperations(f, &stubFileReader{}))
			if code == 0 || f.calls != before {
				t.Fatal("caller-supplied health accepted", argv)
			}
		}
	}
}
