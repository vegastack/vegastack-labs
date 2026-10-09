package cli

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

type lifecycleControlFixture struct {
	*stubControlOperations
	HostControlOperations
	prepared int
}

func (f *lifecycleControlFixture) PrepareHostTarget(context.Context, string, generated.HostDiscoveryTargetDraftRequest) (localapi.TypedResponse[generated.HostDiscoveryTargetDraftSubmission], error) {
	f.prepared++
	return localapi.TypedResponse[generated.HostDiscoveryTargetDraftSubmission]{}, nil
}
func (f *lifecycleControlFixture) SubmitHostAction(context.Context, string, generated.HostActionRequest) (localapi.TypedResponse[generated.HostActionSubmission], error) {
	f.prepared++
	return localapi.TypedResponse[generated.HostActionSubmission]{}, nil
}
func (f *lifecycleControlFixture) SubmitHostAccess(context.Context, string, generated.HostAccessDraftRequest) (localapi.TypedResponse[generated.HostActionSubmission], error) {
	f.prepared++
	return localapi.TypedResponse[generated.HostActionSubmission]{}, nil
}

func TestHostLifecycleCLIRejectsMalformedBeforeTransport(t *testing.T) {
	for _, tt := range []struct {
		command string
		limit   int64
	}{{"target", 16384}, {"action", 131072}, {"access", 1048576}, {"replacement", 32768}} {
		t.Run(tt.command, func(t *testing.T) {
			f := &lifecycleControlFixture{stubControlOperations: successfulControlOperations(t)}
			files := &stubFileReader{content: []byte(`{"unknown":"secret-canary"}`)}
			args := []string{"node", tt.command, "prepare", "--config", "fixture.json", "--file", "request.json", "--output", "json"}
			code, out, _ := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(f, files))
			if code == 0 || f.prepared != 0 || files.limit != tt.limit || !strings.Contains(out, "INPUT_INVALID") || strings.Contains(out, "secret-canary") {
				t.Fatalf("malformed handling: code=%d prepared=%d limit=%d out=%s", code, f.prepared, files.limit, out)
			}
		})
	}
}
