package cli

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"os"
	"strings"
	"testing"
)

type replacementCLIControl struct {
	*stubControlOperations
	HostControlOperations
	calls      int
	fail       bool
	submission generated.HostReplacementSubmission
}

func (f *replacementCLIControl) PrepareHostReplacement(_ context.Context, _ string, in generated.HostReplacementRequest) (localapi.TypedResponse[generated.HostReplacementSubmission], error) {
	f.calls++
	if f.fail {
		return localapi.TypedResponse[generated.HostReplacementSubmission]{}, failure.New(generated.ErrorCodeRecoveryRequired, "host-replacement", false)
	}
	digest := hostaction.Digest(in)
	id := "host-replacement-" + digest[7:39]
	f.submission = generated.HostReplacementSubmission{Schema: generated.SchemaIDHostReplacementSubmission, SchemaVersion: "1.0.0", ReplacementID: in.ReplacementID, DraftID: id, DeclarationID: id, ContentDigest: digest, StateRevision: 2, RecoveryEpoch: 0}
	raw, _ := json.Marshal(struct {
		Data generated.HostReplacementSubmission `json:"data"`
	}{f.submission})
	return localapi.TypedResponse[generated.HostReplacementSubmission]{Data: f.submission, Raw: raw}, nil
}
func TestHostReplacementCLIIsInertAndDoesNotRetry(t *testing.T) {
	raw, err := os.ReadFile("../localapi/testdata/host-replacement.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"human", "json", "failed"} {
		t.Run(mode, func(t *testing.T) {
			f := &replacementCLIControl{stubControlOperations: successfulControlOperations(t), fail: mode == "failed"}
			output := mode
			if mode == "failed" {
				output = "json"
			}
			files := &stubFileReader{content: raw}
			code, out, _ := runTestAppWithOptions(t, context.Background(), []string{"node", "replacement", "prepare", "--config", "profile.json", "--file", "replacement.json", "--output", output}, nil, WithControlOperations(f, files))
			if f.calls != 1 || files.limit != 32768 {
				t.Fatalf("calls/limit %d/%d", f.calls, files.limit)
			}
			if mode == "failed" {
				if code == 0 || !strings.Contains(out, "RECOVERY_REQUIRED") {
					t.Fatalf("failure %d %s", code, out)
				}
				return
			}
			if code != 0 || !strings.Contains(out, f.submission.ContentDigest) || !strings.Contains(out, f.submission.DeclarationID) {
				t.Fatalf("missing exact draft %d %s", code, out)
			}
			if mode == "human" && (!strings.Contains(out, "old-host") || !strings.Contains(out, "new-host") || !strings.Contains(out, "inert") && !strings.Contains(out, "Inert")) {
				t.Fatal(out)
			}
		})
	}
}
