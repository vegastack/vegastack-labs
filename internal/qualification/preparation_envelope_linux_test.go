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
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

type profileEnvelopeClient struct {
	localapi.Client
	response localapi.TypedResponse[generated.GateProfileDraftSubmission]
}

func (c profileEnvelopeClient) SubmitProfileDraft(context.Context, serverconfig.Profile, generated.GateProfileDraftRequest) (localapi.TypedResponse[generated.GateProfileDraftSubmission], error) {
	return c.response, nil
}

func currentProfilePreparation(t *testing.T) (nativeAPIPacket, profileEnvelopeClient) {
	t.Helper()
	scope := scopeFixture()
	step := generated.NativeStepRequest{Schema: generated.SchemaIDNativeStepRequest, SchemaVersion: "1.0.0", ScopeDigest: hostaction.Digest(scope), GuestID: "controller", ScenarioID: "control-setup", Ordinal: 1, ControllerInstanceID: scope.ControllerInstanceID, RecoveryEpoch: 0, Nonce: hostaction.Digest("profile-step"), Deadline: scope.ExpiresAt, Operation: "prepare"}
	data := generated.GateProfileDraftSubmission{Schema: generated.SchemaIDGateProfileDraftSubmission, SchemaVersion: "1.1.0", DraftID: "native-profile", ChangeID: "profile-change", BindingID: "native-profile", Status: "draft", StateRevision: 3, RecoveryEpoch: 0}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "native-test"}, func() (string, error) { return "request-profile", nil })
	envelope, err := factory.SuccessWithRequestID("api.v1.gate-profile-drafts.create", "request-profile", true, 0, 3, data)
	if err != nil || envelope.SchemaVersion != generated.RegistrySchemaVersion {
		t.Fatal("production envelope fixture", err)
	}
	return nativeAPIPacket{Step: step, Kind: "prepare", Preparation: &generated.NativePreparationRequest{Kind: "profile", Profile: &generated.GateProfileDraftRequest{}}}, profileEnvelopeClient{response: localapi.TypedResponse[generated.GateProfileDraftSubmission]{Result: envelope, Data: data}}
}

func TestNativeProfilePreparationProjectsCurrentAPIEnvelope(t *testing.T) {
	packet, client := currentProfilePreparation(t)
	before := client.response.Result
	reply, err := dispatchNativeAPI(context.Background(), packet, client, serverconfig.Profile{})
	if err != nil {
		t.Fatal(err)
	}
	if !exactNativeJSON(generated.SchemaIDNativeStepResult, reply.Result) {
		t.Fatal("current production API envelope cannot cross exact native preparation transport")
	}
	expected := before
	expected.SchemaVersion = "1.0.0"
	if reply.Result.Preparation == nil || !reflect.DeepEqual(reply.Result.Preparation.Result, expected) || !reflect.DeepEqual(client.response.Result, before) || hostaction.Digest(reply.Result.Binding) != hostaction.Digest(packet.Step) {
		t.Fatal("projection changed payload, original response, or native binding")
	}
	outerFactory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "native-test"}, func() (string, error) { return "outer-step", nil })
	outer, err := outerFactory.Success(generated.CommandNameQualificationStep, 0, 3, reply.Result)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(outer)
	if _, err = readConsoleStep(packet.Step, strings.NewReader(string(raw)+"\n")); err != nil {
		t.Fatal("projected preparation refused by real native console reader", err)
	}
	changed := packet.Step
	changed.Nonce = hostaction.Digest("different-step")
	if _, err = readConsoleStep(changed, strings.NewReader(string(raw)+"\n")); !errors.Is(err, ErrUnavailable) {
		t.Fatal("foreign native binding accepted")
	}
}

func TestNativeProfilePreparationDoesNotProjectUnknownMajorOrInvalidEnvelope(t *testing.T) {
	for _, version := range []string{"2.0.0", "invalid"} {
		t.Run(version, func(t *testing.T) {
			packet, client := currentProfilePreparation(t)
			client.response.Result.SchemaVersion = version
			reply, err := dispatchNativeAPI(context.Background(), packet, client, serverconfig.Profile{})
			if err != nil {
				t.Fatal(err)
			}
			if exactNativeJSON(generated.SchemaIDNativeStepResult, reply.Result) || reply.Result.Preparation.Result.SchemaVersion != version {
				t.Fatal("unsupported envelope was converted into native transport")
			}
		})
	}
	packet, client := currentProfilePreparation(t)
	client.response.Result.Schema = "not-a-run-result"
	reply, err := dispatchNativeAPI(context.Background(), packet, client, serverconfig.Profile{})
	if err != nil || exactNativeJSON(generated.SchemaIDNativeStepResult, reply.Result) {
		t.Fatal("invalid ordinary envelope became native result", err)
	}
}
