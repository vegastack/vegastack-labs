package cijobguard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func binding() Binding {
	return Binding{LifecycleID: "one-job", RunID: "123", JobID: "456", Attempt: 2, PlanID: "plan-1", LeaseID: "lease-1", Epoch: 3}
}
func frame(d Decision) string { b, _ := json.Marshal(d); return string(b) + "\n" }
func TestExactAllow(t *testing.T) {
	if err := Hold(context.Background(), binding(), time.Now().Add(time.Second), io.NopCloser(strings.NewReader(frame(Decision{Binding: binding(), Action: "allow"}))), func() error { t.Fatal("allow aborted"); return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestDenials(t *testing.T) {
	good := frame(Decision{Binding: binding(), Action: "allow"})
	cases := map[string]string{"eof": "", "malformed": "{\n", "oversize": strings.Repeat("x", MaxFrame+1) + "\n", "second-frame": good + good, "no-newline": strings.TrimSuffix(good, "\n"), "unknown": strings.Replace(good, `"action":`, `"unknown":0,"action":`, 1), "duplicate": strings.Replace(good, `"action":`, `"action":"allow","action":`, 1), "null-binding": `{"binding":null,"action":"allow"}` + "\n", "missing": `{"action":"allow"}` + "\n", "wrong-case": strings.Replace(good, `"action"`, `"Action"`, 1), "abort": frame(Decision{Binding: binding(), Action: "abort"})}
	mutations := []func(*Binding){func(b *Binding) { b.LifecycleID = "other" }, func(b *Binding) { b.RunID = "124" }, func(b *Binding) { b.JobID = "457" }, func(b *Binding) { b.Attempt++ }, func(b *Binding) { b.PlanID = "plan-2" }, func(b *Binding) { b.LeaseID = "lease-2" }, func(b *Binding) { b.Epoch++ }}
	for i, mutate := range mutations {
		b := binding()
		mutate(&b)
		cases[string(rune('a'+i))+"-mismatch"] = frame(Decision{Binding: b, Action: "allow"})
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			aborted := false
			err := Hold(context.Background(), binding(), time.Now().Add(time.Second), io.NopCloser(strings.NewReader(raw)), func() error { aborted = true; return nil })
			if !aborted || !errors.Is(err, ErrTerminated) {
				t.Fatalf("aborted=%v error=%v", aborted, err)
			}
		})
	}
}
func TestExpiryAndCancellationCloseBlockedStream(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		t.Run(map[bool]string{true: "expiry", false: "cancel"}[expiry], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			deadline := time.Now().Add(time.Minute)
			if expiry {
				deadline = time.Now().Add(20 * time.Millisecond)
			}
			r, w := io.Pipe()
			defer w.Close()
			done := make(chan error, 1)
			go func() { done <- Hold(ctx, binding(), deadline, r, func() error { return nil }) }()
			if !expiry {
				cancel()
			}
			select {
			case err := <-done:
				if !errors.Is(err, ErrTerminated) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("blocked read not closed")
			}
		})
	}
}
func TestAbortFailureCannotReturn(t *testing.T) {
	if os.Getenv("VSK_GUARD_ABORT_CHILD") == "1" {
		_ = Hold(context.Background(), binding(), time.Now().Add(time.Second), io.NopCloser(strings.NewReader("bad\n")), func() error {
			_, _ = os.Stdout.WriteString("abort-attempted\n")
			return errors.New("synthetic failure")
		})
		os.Exit(41)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAbortFailureCannotReturn$")
	cmd.Env = append(os.Environ(), "VSK_GUARD_ABORT_CHILD=1")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == nil || err == nil || !strings.Contains(string(out), "abort-attempted") {
		t.Fatalf("abort failure released child: %v %s", err, out)
	}
}

func TestExplicitZeroEpochAllowed(t *testing.T) {
	b := binding()
	b.Epoch = 0
	if err := Hold(context.Background(), b, time.Now().Add(time.Second), io.NopCloser(strings.NewReader(frame(Decision{Binding: b, Action: "allow"}))), func() error { t.Fatal("zero epoch aborted"); return nil }); err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(frame(Decision{Binding: b, Action: "allow"}), `,"epoch":0`, "", 1)
	aborted := false
	if err := Hold(context.Background(), b, time.Now().Add(time.Second), io.NopCloser(strings.NewReader(raw)), func() error { aborted = true; return nil }); !aborted || !errors.Is(err, ErrTerminated) {
		t.Fatal("missing epoch accepted")
	}
}
func TestInvalidTrustedInputsTerminate(t *testing.T) {
	for _, mutate := range []func(*Binding){func(b *Binding) { b.RunID = "0123" }, func(b *Binding) { b.JobID = "-1" }, func(b *Binding) { b.LifecycleID = "" }, func(b *Binding) { b.Attempt = 0 }} {
		b := binding()
		mutate(&b)
		aborted := false
		err := Hold(context.Background(), b, time.Now().Add(time.Second), io.NopCloser(strings.NewReader(frame(Decision{Binding: b, Action: "allow"}))), func() error { aborted = true; return nil })
		if !aborted || !errors.Is(err, ErrTerminated) {
			t.Fatal("invalid trusted binding released")
		}
	}
}
