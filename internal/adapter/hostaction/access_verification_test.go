package hostaction

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
)

type recordingControls struct {
	calls        int
	fail         bool
	binding      adapter.ExactExecutionBinding
	measurements []generated.AccessMeasurement
}

func (r *recordingControls) RecordVerifiedControlResults(_ context.Context, _ adapter.Operation, b adapter.ExactExecutionBinding, _ adapter.Effect, result generated.HostActionResult) error {
	r.calls++
	r.binding = b
	r.measurements = result.ControlMeasurements
	if r.fail {
		return denied()
	}
	return nil
}
func TestMeasuredVerificationRequiresDurableRecorder(t *testing.T) {
	a, op, b, _, _, _, _ := fixture(t, "success")
	d := protocol.Digest("measured")
	effect := adapter.Effect{Status: "succeeded", ResultDigest: d, EffectObserved: true}
	m := generated.AccessMeasurement{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: "ssh", Kind: "ssh", Status: "passed", SubjectHostID: "test-host", SubjectIdentityDigest: d, ProfileLockDigest: d, ProducerID: "test-producer", ProducerVersion: "1.0.0", BundleDigest: d, ObservedAt: time.Now().UTC().Format(time.RFC3339), ConfigurationDigest: d, PositiveProbeDigest: d, NegativeProbeDigest: d, Reason: "measured"}
	m.MeasurementDigest = protocol.MeasurementDigest(m)
	result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, Status: "succeeded", Reason: "measured", EffectObserved: true, ControlMeasurements: []generated.AccessMeasurement{m}}
	result.ResultDigest = protocol.ResultDigest(result)
	effect.ResultDigest = result.ResultDigest
	recorder := &recordingControls{fail: true}
	a.recorder = recorder
	if err := a.remember(op, b, effect, result); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Verify(context.Background(), op, effect); err == nil {
		t.Fatal("persistence failure accepted")
	}
	recorder.fail = false
	if _, err := a.Verify(context.Background(), op, effect); err != nil {
		t.Fatal(err)
	}
	if recorder.calls != 2 || protocol.Digest(recorder.binding) != protocol.Digest(b) || len(recorder.measurements) != 1 {
		t.Fatal("binding/measurement lost")
	}
	if _, err := a.Verify(context.Background(), op, effect); err == nil {
		t.Fatal("consumed verification accepted")
	}
}

func TestMeasuredSSHResultPayloadReachesRecorder(t *testing.T) {
	for _, mode := range []string{"measured", "tampered-measured"} {
		t.Run(mode, func(t *testing.T) {
			a, op, b, value, _, _, _ := fixture(t, mode)
			recorder := &recordingControls{}
			a.recorder = recorder
			effect, err := a.ExecuteBoundWithCredentials(context.Background(), op, b, []*credentialref.Value{value})
			if mode == "tampered-measured" {
				if err == nil || recorder.calls != 0 {
					t.Fatal("tampered measured payload accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if recorder.calls != 0 {
				t.Fatal("recorded before engine receipt")
			}
			if _, err = a.Verify(context.Background(), op, effect); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(recorder.measurements)
			if len(recorder.measurements) != 8 || len(raw) <= protocol.MaximumFrame {
				t.Fatalf("large canonical payload lost: %d bytes", len(raw))
			}
		})
	}
}
