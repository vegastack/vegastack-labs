package cijobrunner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/cijobguard"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func TestDecisionCannotChangeLaunch(t *testing.T) {
	b := LaunchBinding{LifecycleID: "life", RunID: "42", PlanID: "plan", LeaseID: "lease", Attempt: 1}
	d := cijobguard.Decision{Binding: cijobguard.Binding{LifecycleID: "life", RunID: "42", JobID: "99", PlanID: "plan", LeaseID: "other", Attempt: 1}, Action: "allow"}
	if ValidateDecision(b, d) == nil {
		t.Fatal("changed lease allowed")
	}
	d.Binding.LeaseID = "lease"
	if err := ValidateDecision(b, d); err != nil {
		t.Fatal(err)
	}
}
func TestStrictFrames(t *testing.T) {
	for _, raw := range []string{`{"kind":"ready","kind":"ready"}`, `{"Kind":"ready"}`, `{"kind":"ready","extra":1}`, `{"kind":null}`} {
		var f frame
		if decodeFrame(context.Background(), []byte(raw), &f) == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestLifecycleEventsNeverContainRawOutput(t *testing.T) {
	var out bytes.Buffer
	s := NewStream(strings.NewReader(""), &out)
	if s.Event(context.Background(), LifecycleEvent{Stage: "SECRET"}) == nil {
		t.Fatal("arbitrary string accepted")
	}
	if strings.Contains(out.String(), "SECRET") {
		t.Fatal("raw output leaked")
	}
	if err := s.Event(context.Background(), LifecycleEvent{Stage: "started", Sequence: 1}); err != nil {
		t.Fatal(err)
	}
}

func TestMissingEpochAndNestedCaseRejected(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{
		`{"kind":"decision","decision":{"binding":{"lifecycleId":"life","runId":"42","jobId":"99","planId":"plan","leaseId":"lease","attempt":1},"action":"allow"}}`,
		`{"kind":"decision","decision":{"binding":{"lifecycleId":"life","runId":"42","jobId":"99","planId":"plan","leaseId":"lease","attempt":1,"epoch":0},"Action":"allow"}}`,
		`{"kind":"ready","spec":null}`,
	} {
		var f frame
		if decodeFrame(ctx, []byte(raw), &f) == nil {
			t.Fatal(raw)
		}
	}
}
func TestControlSequentialHandshakeAndReadAhead(t *testing.T) {
	input := strings.NewReader("{\"kind\":\"ready\"}\n{\"kind\":\"configured\",\"runner\":{\"stage\":\"configured\",\"runnerId\":7,\"runnerName\":\"owned\"}}\n{\"kind\":\"held\"}\n{\"kind\":\"complete\",\"completion\":{\"succeeded\":true,\"logDigest\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"stopped\":true,\"volumesRemoved\":true}}\n{\"final\":true}\n")
	r := bufio.NewReaderSize(input, 32)
	var out bytes.Buffer
	c := NewControl(r, &out)
	ctx := context.Background()
	if c.WriteDecision(ctx, cijobguard.Decision{}) == nil {
		t.Fatal("early decision")
	}
	if m, e := c.Receive(ctx); e != nil || m.Kind != "ready" {
		t.Fatal(m, e)
	}
	v, _ := credentialref.NewValue([]byte("synthetic"))
	defer v.Close()
	if e := c.WriteRegistration(ctx, v); e != nil {
		t.Fatal(e)
	}
	if c.WriteRegistration(ctx, v) == nil {
		t.Fatal("replayed token")
	}
	if m, e := c.Receive(ctx); e != nil || m.Runner.RunnerID != 7 {
		t.Fatal(m, e)
	}
	if m, e := c.Receive(ctx); e != nil || m.Kind != "held" {
		t.Fatal(m, e)
	}
	d := cijobguard.Decision{Action: "allow"}
	if c.WriteDecision(ctx, d) != nil || c.WriteDecision(ctx, d) == nil {
		t.Fatal("decision replay")
	}
	if m, e := c.Receive(ctx); e != nil || m.Kind != "complete" {
		t.Fatal(m, e)
	}
	final, _ := r.ReadString('\n')
	if final != "{\"final\":true}\n" {
		t.Fatal("lost shared buffered result", final)
	}
}

func TestRuntimeDigestBindsEveryProfileField(t *testing.T) {
	p := RuntimeProfile{ImageIndexDigest: "sha256:" + Image[len(Image)-64:], ExecutableDigest: "sha256:" + strings.Repeat("a", 64), HookDigest: "sha256:" + strings.Repeat("b", 64), NetworkID: "none", DaemonUID: 505, MemoryBytes: 256 << 20, CPUQuotaMicros: 50000, CPUPeriodMicros: 100000, PidsLimit: 64, Offline: true}
	s := Spec{Binding: LaunchBinding{LifecycleID: "life", RunID: "42", PlanID: "plan", LeaseID: "lease", Attempt: 1}, Deadline: time.Now().Add(time.Minute), RuntimeProfileID: "offline", RuntimeDigest: ComputeRuntimeDigest(p), Organization: "org", RunnerName: "runner", RunnerGroup: "Default", Labels: []string{"isolated"}}
	if e := ValidateSpec(s, p); e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*RuntimeProfile){"image": func(q *RuntimeProfile) { q.ImageIndexDigest = "sha256:" + strings.Repeat("c", 64) }, "binary": func(q *RuntimeProfile) { q.ExecutableDigest = "sha256:" + strings.Repeat("c", 64) }, "hook": func(q *RuntimeProfile) { q.HookDigest = "sha256:" + strings.Repeat("c", 64) }, "network": func(q *RuntimeProfile) { q.NetworkID = "other" }, "networkEvidence": func(q *RuntimeProfile) { q.NetworkEvidenceDigest = "sha256:" + strings.Repeat("c", 64) }, "uid": func(q *RuntimeProfile) { q.DaemonUID++ }, "memory": func(q *RuntimeProfile) { q.MemoryBytes += 1 << 20 }, "cpuQuota": func(q *RuntimeProfile) { q.CPUQuotaMicros++ }, "cpuPeriod": func(q *RuntimeProfile) { q.CPUPeriodMicros++ }, "pids": func(q *RuntimeProfile) { q.PidsLimit++ }, "offline": func(q *RuntimeProfile) { q.Offline = false }} {
		t.Run(name, func(t *testing.T) {
			q := p
			change(&q)
			if ComputeRuntimeDigest(q) == s.RuntimeDigest || ValidateSpec(s, q) == nil {
				t.Fatal("runtime drift allowed")
			}
		})
	}
}
func TestUncertainRegistrationCannotReachHeld(t *testing.T) {
	raw := "{\"kind\":\"ready\"}\n{\"kind\":\"configured\",\"runner\":{\"stage\":\"registration_secret_delivered\",\"runnerId\":0,\"runnerName\":\"\"}}\n{\"kind\":\"held\"}\n"
	var out bytes.Buffer
	c := NewControl(strings.NewReader(raw), &out)
	ctx := context.Background()
	if _, e := c.Receive(ctx); e != nil {
		t.Fatal(e)
	}
	v, _ := credentialref.NewValue([]byte("synthetic"))
	defer v.Close()
	if c.WriteRegistration(ctx, v) != nil {
		t.Fatal("register")
	}
	m, e := c.Receive(ctx)
	if e != nil || m.Runner.Stage != "registration_secret_delivered" {
		t.Fatal(m, e)
	}
	if _, e = c.Receive(ctx); e == nil {
		t.Fatal("uncertain registration admitted")
	}
}

func TestSharedSmallReaderAcceptsBoundedRegistrationFrame(t *testing.T) {
	token := bytes.Repeat([]byte("a"), 4096)
	var wire bytes.Buffer
	raw, e := json.Marshal(frame{Kind: "registration", Token: token})
	if e != nil {
		t.Fatal(e)
	}
	wire.Write(raw)
	wire.WriteByte('\n')
	wire.WriteString("following\n")
	reader := bufio.NewReaderSize(&wire, 32)
	var output bytes.Buffer
	session := NewStream(reader, &output)
	v, e := session.Registration(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer v.Close()
	if !bytes.Equal(v.Bytes(), token) {
		t.Fatal("token corrupted")
	}
	remaining, e := reader.ReadString('\n')
	if e != nil || remaining != "following\n" {
		t.Fatal("following frame lost", remaining, e)
	}
}
