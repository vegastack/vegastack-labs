package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"testing"
	"time"
)

func TestControlSetupRequiresAllMeasuredAttempts(t *testing.T) {
	now := time.Now().UTC()
	w := generated.NativeControlSetupWitness{InstanceID: "instance-original", InitialPID: 20, InitialStartIdentity: "start-initial", FinalPID: 22, FinalStartIdentity: "start-final"}
	for i, k := range []string{"incomplete-refusal", "fresh", "populated-refusal", "writer-refusal", "restart", "crash-restart"} {
		a := generated.NativeControlSetupAttempt{Kind: k, BeforeDigest: "before", AfterDigest: "after", PID: int64(30 + i), StartIdentity: k, InstanceID: w.InstanceID, ObservedAt: now.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)}
		if i == 0 || i == 2 || i == 3 {
			a.AfterDigest = a.BeforeDigest
			a.ErrorCode = "STATE_CONFLICT"
		}
		w.Attempts = append(w.Attempts, a)
	}
	w.Attempts[1].PID = w.InitialPID
	w.Attempts[1].StartIdentity = w.InitialStartIdentity
	w.Attempts[5].PID = w.FinalPID
	w.Attempts[5].StartIdentity = w.FinalStartIdentity
	if err := validateSetupAttempts(w, now, now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"missing", "modified-incomplete", "modified-populated", "modified-writer", "restart-instance", "reused-process", "refusal-succeeded", "reordered", "future"} {
		t.Run(kind, func(t *testing.T) {
			bad := w
			bad.Attempts = append([]generated.NativeControlSetupAttempt{}, w.Attempts...)
			switch kind {
			case "missing":
				bad.Attempts = bad.Attempts[:5]
			case "modified-incomplete":
				bad.Attempts[0].AfterDigest = "different"
			case "modified-populated":
				bad.Attempts[2].AfterDigest = "different"
			case "modified-writer":
				bad.Attempts[3].AfterDigest = "different"
			case "restart-instance":
				bad.Attempts[4].InstanceID = "other"
			case "reused-process":
				bad.Attempts[4].StartIdentity = bad.FinalStartIdentity
			case "refusal-succeeded":
				bad.Attempts[3].ErrorCode = ""
			case "reordered":
				bad.Attempts[2], bad.Attempts[3] = bad.Attempts[3], bad.Attempts[2]
			case "future":
				bad.Attempts[5].ObservedAt = now.Add(time.Hour).Format(time.RFC3339Nano)
			}
			if validateSetupAttempts(bad, now, now.Add(6*time.Second)) == nil {
				t.Fatal("incomplete native setup proof accepted")
			}
		})
	}
}
