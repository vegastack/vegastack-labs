// Package cijobguard holds one job until its trusted controller allows the exact
// assignment. It supplies no transport authentication or job sandbox.
package cijobguard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const MaxFrame = 4096

// ErrTerminated means the caller's abort function reported whole-job termination,
// not that the hook merely failed. A real own-job abort generally kills Hold too.
var ErrTerminated = errors.New("ci job terminated")
var ErrCgroup = errors.New("ci job cgroup unavailable")

type Binding struct {
	LifecycleID string `json:"lifecycleId"`
	RunID       string `json:"runId"`
	JobID       string `json:"jobId"`
	PlanID      string `json:"planId"`
	LeaseID     string `json:"leaseId"`
	Attempt     uint32 `json:"attempt"`
	Epoch       uint64 `json:"epoch"`
}
type Decision struct {
	Binding Binding `json:"binding"`
	Action  string  `json:"action"`
}

func validBinding(b Binding) bool {
	for _, id := range []string{b.LifecycleID, b.PlanID, b.LeaseID} {
		if len(id) == 0 || len(id) > 128 {
			return false
		}
		for _, c := range []byte(id) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	for _, id := range []string{b.RunID, b.JobID} {
		n, err := strconv.ParseInt(id, 10, 64)
		if err != nil || n <= 0 || strconv.FormatInt(n, 10) != id {
			return false
		}
	}
	return b.Attempt > 0
}

// Hold consumes exactly one newline-terminated frame followed by EOF. The
// controller must close its write side after deciding. input.Close must unblock
// Read; the later trusted launcher supplies that property and authentication.
// Only an exact allow returns nil. Every other path calls abort. abort may return
// nil ONLY after verifying the entire job is terminated. If it fails (or is nil),
// Hold never returns, even on cancellation: a failed hook could run always steps.
// This function alone provides no durable cross-invocation replay protection;
// the server must consume the unique lifecycle/lease before sending its allow.
func Hold(ctx context.Context, expected Binding, deadline time.Time, input io.ReadCloser, abort func() error) error {
	terminate := func() error {
		if input != nil {
			_ = input.Close()
		}
		if abort != nil && abort() == nil {
			return ErrTerminated
		}
		// Keep a timer pending even in a standalone hook process: a bare
		// select{} can trigger Go's deadlock detector and exit the hook.
		for {
			time.Sleep(time.Hour)
		}
	}
	if ctx == nil || input == nil || !validBinding(expected) || deadline.IsZero() || !time.Now().Before(deadline) {
		return terminate()
	}
	held, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(held, func() { _ = input.Close() })
	defer stop()
	defer input.Close()
	reader := bufio.NewReaderSize(input, MaxFrame+2)
	raw, err := hostaction.ReadFrame(reader, MaxFrame)
	if err != nil || held.Err() != nil || strictjson.Scan(held, raw, strictjson.Limits{MaxDepth: 3}) != nil {
		return terminate()
	}
	// Reject missing, wrong-case and null fields as well as unknown fields.
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || !exactKeys(top, "binding", "action") {
		return terminate()
	}
	var bound map[string]json.RawMessage
	if json.Unmarshal(top["binding"], &bound) != nil || !exactKeys(bound, "lifecycleId", "runId", "jobId", "planId", "leaseId", "attempt", "epoch") {
		return terminate()
	}
	for _, value := range bound {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return terminate()
		}
	}
	var d Decision
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || d.Action != "allow" || d.Binding != expected {
		return terminate()
	}
	if _, err = reader.ReadByte(); err != io.EOF || held.Err() != nil || !time.Now().Before(deadline) {
		return terminate()
	}
	return nil
}
func exactKeys(m map[string]json.RawMessage, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return false
		}
	}
	return true
}
