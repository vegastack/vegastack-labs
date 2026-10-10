package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"strings"
	"testing"
)

func (*stubControlOperations) InspectQualification(context.Context, string, generated.QualificationInspectRequest) (localapi.TypedResponse[generated.QualificationInspectData], error) {
	return localapi.TypedResponse[generated.QualificationInspectData]{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-fixture", false)
}
func (*stubControlOperations) RunNativeQualification(context.Context, generated.QualificationScope) (generated.NativeReport, error) {
	return generated.NativeReport{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-fixture", false)
}
func (*stubControlOperations) ExecuteQualificationStep(context.Context, string, generated.NativeStepRequest) (generated.NativeStepResult, error) {
	return generated.NativeStepResult{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-fixture", false)
}
func TestQualificationRejectsArbitraryScriptBeforeDispatch(t *testing.T) {
	for _, name := range []string{"inspect", "native", "step"} {
		t.Run(name, func(t *testing.T) {
			args := []string{"qualification", name, "--config", "profile.json", "--file", "input.json", "--output", "json"}
			code, out, _ := runTestAppWithOptions(t, context.Background(), args, nil, WithControlOperations(successfulControlOperations(t), &stubFileReader{content: []byte(`{"shell":"untrusted"}`)}))
			if code != 2 || !strings.Contains(out, `"code":"INPUT_INVALID"`) {
				t.Fatalf("unexpected result: %d %s", code, out)
			}
		})
	}
}

func TestNativeJSONPreservesActualChangedAggregate(t *testing.T) {
	for _, changed := range []bool{false, true} {
		var stdout, stderr bytes.Buffer
		app := New(&stdout, &stderr, BuildInfo{ToolVersion: "1.0.0", ReleaseBuildID: "test"}, func() (string, error) { return "native-test", nil })
		code := app.renderQualification(generated.CommandNameQualificationNative, generated.NativeReport{Changed: changed})
		var envelope generated.RunResult
		if code != 0 || json.Unmarshal(stdout.Bytes(), &envelope) != nil || envelope.Changed != changed {
			t.Fatalf("changed=%v: %d %s", changed, code, stdout.String())
		}
	}
}

func (*stubControlOperations) RunSlackFixturePeer(context.Context) error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, "qualification-native", false)
}
