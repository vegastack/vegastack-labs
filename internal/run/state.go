// Package run owns the in-process durable plan-run state machine.
package run

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type Boundary string

const (
	BoundaryRunCreated      Boundary = "01-run-created"
	BoundaryRunStarted      Boundary = "02-run-started"
	BoundaryLeaseAcquired   Boundary = "03-lease-acquired"
	BoundaryIntentRecorded  Boundary = "04-intent-recorded"
	BoundaryEffectReturned  Boundary = "05-effect-returned"
	BoundaryReceiptRecorded Boundary = "06-receipt-recorded"
	BoundaryVerified        Boundary = "07-verified"
	BoundaryRunCompleted    Boundary = "08-run-completed"
)

type Error struct {
	code      string
	target    string
	retryable bool
}

func (err *Error) Error() string   { return fmt.Sprintf("%s: %s", err.code, err.target) }
func (err *Error) Code() string    { return err.code }
func (err *Error) Target() string  { return err.target }
func (err *Error) Retryable() bool { return err.retryable }

func Code(err error) string {
	var runError *Error
	if errors.As(err, &runError) {
		return runError.code
	}
	type coded interface{ Code() string }
	var other coded
	if errors.As(err, &other) {
		return other.Code()
	}
	return ""
}

func runError(code, target string) error { return &Error{code: code, target: target} }

func digest(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func runID(planID, submitKey string) string {
	return "run-" + strings.TrimPrefix(digest("run", planID, submitKey), "sha256:")[:32]
}
func stepID(id string, sequence int64) string {
	return fmt.Sprintf("step-%d-%s", sequence, strings.TrimPrefix(digest("step", id, fmt.Sprint(sequence)), "sha256:")[:16])
}

func terminal(status string) bool {
	return status == "succeeded" || status == "failed" || status == "partial" || status == "cancelled"
}

func exactContract(schema string, value any) bool {
	raw, err := jsonMarshal(value)
	return err == nil && generated.ValidateContractJSON(schema, raw, generated.ContractExact) == nil
}

var jsonMarshal = func(value any) ([]byte, error) { return json.Marshal(value) }
