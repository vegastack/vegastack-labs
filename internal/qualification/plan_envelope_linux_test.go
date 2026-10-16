//go:build linux

package qualification

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
)

func nativePlanEnvelopeFixture(t *testing.T) (generated.NativeStepRequest, localapi.TypedResponse[generated.Plan], *result.Factory) {
	t.Helper()
	// This complete golden is the canonical output checked against the owning
	// plan.Service.Create producer, not a reduced plan-shaped response stub.
	raw, err := os.ReadFile(filepath.Join("..", "plan", "testdata", "plan.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var plan generated.Plan
	if json.Unmarshal(raw, &plan) != nil || !exactNativeJSON(generated.SchemaIDPlan, plan) {
		t.Fatal("invalid production plan golden")
	}
	canonical, _ := json.Marshal(plan)
	data := generated.PlanPresentation{Plan: plan, ReadablePlan: "owning production plan fixture", CanonicalPlan: string(canonical)}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-native-plan", nil })
	envelope, err := factory.Success("api.v1.plans.create", plan.Binding.RecoveryEpoch, plan.Binding.StateRevision, data)
	if err != nil {
		t.Fatal(err)
	}
	packet, _ := currentProfilePreparation(t)
	step := packet.Step
	step.Ordinal = 2
	step.RecoveryEpoch = plan.Binding.RecoveryEpoch
	return step, localapi.TypedResponse[generated.Plan]{Result: envelope, Data: plan}, factory
}

func TestNativePlanEnvelopeSeparatesKnownPayloadFromCompatibleMetadata(t *testing.T) {
	step, response, factory := nativePlanEnvelopeFixture(t)
	t.Run("preparation-boundary", func(t *testing.T) {
		before := response.Result
		prepared := preparationResult(response)
		prepared.Plan = &response.Data
		inner := generated.NativeStepResult{Schema: generated.SchemaIDNativeStepResult, SchemaVersion: "1.0.0", Binding: step, Status: "completed", Preparation: &prepared, ObservationDigests: []string{}, ReceiptDigests: []string{}, ProducerRunIDs: []string{}}
		if !exactNativeJSON(generated.SchemaIDNativeStepResult, inner) {
			t.Fatal("real plan payload prevented compatible metadata projection")
		}
		expected := before
		expected.SchemaVersion = "1.0.0"
		if !reflect.DeepEqual(prepared.Result, expected) || !reflect.DeepEqual(response.Result, before) {
			t.Fatal("plan payload or original API response changed")
		}
	})
	// Independently exercise the console boundary with an already exact inner
	// preparation, so the preceding boundary cannot mask a second rejection.
	prepared := generated.NativePreparationResult{Schema: generated.SchemaIDNativePreparationResult, SchemaVersion: "1.0.0", Result: response.Result, Plan: &response.Data}
	prepared.Result.SchemaVersion = "1.0.0"
	inner := generated.NativeStepResult{Schema: generated.SchemaIDNativeStepResult, SchemaVersion: "1.0.0", Binding: step, Status: "completed", Preparation: &prepared, ObservationDigests: []string{}, ReceiptDigests: []string{}, ProducerRunIDs: []string{}}
	if !exactNativeJSON(generated.SchemaIDNativeStepResult, inner) {
		t.Fatal("invalid exact inner native fixture")
	}
	envelope, err := factory.Success(generated.CommandNameQualificationStep, step.RecoveryEpoch, response.Result.StateRevision, inner)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(envelope)
	t.Run("console-boundary", func(t *testing.T) {
		out, e := readConsoleStep(step, strings.NewReader(string(raw)+"\n"))
		if e != nil || hostaction.Digest(out) != hostaction.Digest(inner) {
			t.Fatal("real plan payload rejected by console envelope reader", e)
		}
	})
	t.Run("foreign-binding", func(t *testing.T) {
		changed := step
		changed.Nonce = hostaction.Digest("foreign-nonce")
		if _, e := readConsoleStep(changed, strings.NewReader(string(raw)+"\n")); !errors.Is(e, ErrUnavailable) {
			t.Fatal("foreign binding accepted")
		}
	})
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture")
	}
	for name, change := range map[string]func(map[string]json.RawMessage){
		"unknown-major":    func(m map[string]json.RawMessage) { m["schemaVersion"] = json.RawMessage(`"2.0.0"`) },
		"unsafe-outer-key": func(m map[string]json.RawMessage) { m["apiToken"] = json.RawMessage(`"must-not-be-accepted"`) },
		"unsafe-outer-value": func(m map[string]json.RawMessage) {
			m["extra"] = json.RawMessage(`{"privateKey":"must-not-be-accepted"}`)
		},
		"unknown-inner-key": func(m map[string]json.RawMessage) {
			var data map[string]json.RawMessage
			_ = json.Unmarshal(m["data"], &data)
			data["unknownInner"] = json.RawMessage(`true`)
			m["data"], _ = json.Marshal(data)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := make(map[string]json.RawMessage)
			for k, v := range fields {
				changed[k] = v
			}
			change(changed)
			bad, _ := json.Marshal(changed)
			if _, e := readConsoleStep(step, strings.NewReader(string(bad)+"\n")); !errors.Is(e, ErrUnavailable) {
				t.Fatal("unsafe envelope or payload accepted")
			}
		})
	}
	t.Run("duplicate-data", func(t *testing.T) {
		bad := string(raw[:len(raw)-1]) + `,"data":{}}` + "\n"
		if _, e := readConsoleStep(step, strings.NewReader(bad)); !errors.Is(e, ErrUnavailable) {
			t.Fatal("duplicate data accepted")
		}
	})
}
