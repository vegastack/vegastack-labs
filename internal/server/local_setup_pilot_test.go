package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func pilotSetupReview() (localSetupReview, []byte) {
	artifact := []byte("local executable bytes")
	request := validLocalSetupRequest(time.Now())
	request.ReleaseManifestPath, request.ReleaseManifestDigest = "", ""
	request.ReleasePolicyPath, request.ReleasePolicyDigest, request.ExecutableAssetID = "", "", ""
	request.LocalBuild = &generated.LocalSetupBuild{Schema: "vegastack-labs.dev/local-setup-build", SchemaVersion: "1.0.0", Digest: setupSHA256(artifact), Size: int64(len(artifact)), OS: "linux", Architecture: "amd64"}
	return localSetupReview{request: request}, artifact
}

func TestLocalSetupPilotExecutable(t *testing.T) {
	for _, name := range []string{"valid", "changed-bytes", "extra-bytes", "size", "platform", "build", "missing-opt-in", "mixed-modes", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			review, artifact := pilotSetupReview()
			platform := Platform{OS: "linux", Architecture: "amd64"}
			build := "build-123"
			ctx := context.Background()
			switch name {
			case "changed-bytes":
				artifact[0] ^= 1
			case "extra-bytes":
				artifact = append(artifact, 'x')
			case "size":
				review.request.LocalBuild.Size++
			case "platform":
				platform.Architecture = "arm64"
			case "build":
				build = "different"
			case "missing-opt-in":
				review.request.LocalBuild = nil
			case "mixed-modes":
				review.request.ReleasePolicyPath = "/policy.json"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := verifyLocalSetupRelease(ctx, review, build, platform, func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(artifact)), nil })
			if (err == nil) != (name == "valid") {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}
func TestLocalSetupPilotRequest(t *testing.T) {
	review, _ := pilotSetupReview()
	if err := validateLocalSetupRequest(review.request, time.Now()); err != nil {
		t.Fatalf("pilot rejected: %v", err)
	}
	review.request.LocalBuild = nil
	if err := validateLocalSetupRequest(review.request, time.Now()); err == nil {
		t.Fatal("missing signed inputs accepted without opt-in")
	}
}

func TestLocalSetupPilotSchemaAndReview(t *testing.T) {
	review, _ := pilotSetupReview()
	raw, _ := json.Marshal(review.request)
	for _, input := range []string{
		strings.Replace(string(raw), `"size":22`, `"size":0`, 1),
		strings.Replace(string(raw), `"os":"linux"`, `"os":"windows"`, 1),
		strings.Replace(string(raw), `"architecture":"amd64"`, `"architecture":"unknown"`, 1),
		strings.Replace(string(raw), `"localBuild":{`, `"localBuild":{"extra":true,`, 1),
	} {
		if input == string(raw) {
			t.Fatal("test mutation did not change input")
		}
		if generated.ValidateContractJSON(generated.SchemaIDLocalSetupRequest, []byte(input), generated.ContractExact) == nil {
			t.Fatal("invalid local build accepted")
		}
	}
	// The persisted review preserves the entire local build, so changing the hash
	// changes the bytes to which the Slack acknowledgement is bound.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "requestNonce")
	fields["requestNonceDigest"], _ = json.Marshal(setupSHA256([]byte(review.request.RequestNonce)))
	fields["schema"], _ = json.Marshal(generated.SchemaIDLocalSetupReviewRequest)
	reviewRaw, _ := json.Marshal(fields)
	if err := generated.ValidateContractJSON(generated.SchemaIDLocalSetupReviewRequest, reviewRaw, generated.ContractExact); err != nil {
		t.Fatal(err)
	}
	var stored generated.LocalSetupReviewRequest
	if err := json.Unmarshal(reviewRaw, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.LocalBuild == nil || *stored.LocalBuild != *review.request.LocalBuild {
		t.Fatal("review lost pilot binding")
	}
	before, _ := json.Marshal(stored)
	stored.LocalBuild.Digest = "sha256:" + strings.Repeat("0", 64)
	after, _ := json.Marshal(stored)
	if setupSHA256(before) == setupSHA256(after) {
		t.Fatal("changed executable did not change review binding")
	}
}
