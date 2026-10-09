//go:build linux

package linuxrole

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func handoffFixture(t *testing.T) (*nativeRuntime, HandoffReceipt, *[]string) {
	t.Helper()
	in := fixture()
	now := time.Now().UTC()
	unit := hostaction.BytesDigest(DesiredFiles(in)["etc/systemd/system/vsk-labs.service"])
	in.ExpectedServiceState = "inactive"
	in.ExpectedUnitDigest = unit
	in.Handoff = &generated.ControlHandoffInput{Schema: generated.SchemaIDControlHandoffInput, SchemaVersion: "1.0.0", ForegroundPID: 1234, ForegroundStartIdentity: in.ExecutableDigest, ServiceUID: in.Accounts[0].UID, DatabaseInstanceID: "instance-a", RecoveryEpoch: 2, WriterLockDigest: in.ConfigDigest, UnitDigest: unit, ConfigDigest: in.ConfigDigest, ExecutableDigest: in.ExecutableDigest, SocketIdentityDigest: in.ConfigDigest, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339), RollbackDeadline: now.Add(time.Minute).Format(time.RFC3339)}
	in.RoleBindingDigest = RoleBindingDigest(in)
	if e := ValidateInput(in); e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	if e := os.MkdirAll(filepath.Join(root, "var/lib/vsk-labs/access-rollback"), 0700); e != nil {
		t.Fatal(e)
	}
	calls := []string{}
	active := false
	state := ControlServiceState{DatabaseInstanceID: "instance-a", RecoveryEpoch: 2, ServiceUID: in.Accounts[0].UID, PID: 1234, StartIdentity: in.ExecutableDigest, WriterLockDigest: in.ConfigDigest, UnitDigest: unit, ConfigDigest: in.ConfigDigest, ExecutableDigest: in.ExecutableDigest, SocketIdentityDigest: in.ConfigDigest, Healthy: true}
	n := &nativeRuntime{root: root, now: func() time.Time { return now }, run: func(_ context.Context, bin string, args []string) ([]byte, error) {
		calls = append(calls, args[0])
		if bin != "/usr/bin/systemctl" || len(args) != 2 || args[1] != "vsk-labs.service" {
			t.Fatal("unexpected command", bin, args)
		}
		if args[0] == "start" {
			active = true
		}
		return nil, nil
	}}
	n.handoffHooks = &handoffHooks{state: func(context.Context, generated.LinuxRoleInput) (ControlServiceState, error) {
		s := state
		if active {
			s.ServiceActive = true
			s.PID = 5678
			s.StartIdentity = in.ConfigDigest
		}
		return s, nil
	}, files: func(generated.LinuxRoleInput) error { calls = append(calls, "files"); return nil }, released: func(int64, string) error { calls = append(calls, "released"); return nil }, prepareStop: func(*generated.ControlHandoffInput) (func(context.Context) error, func(), error) {
		return func(context.Context) error { calls = append(calls, "stop"); return nil }, func() {}, nil
	}}
	r := HandoffReceipt{Input: in, Bundle: generated.HostActionBundle{HostID: in.HostID, ActionID: "debian.control.handoff", ExpiresAt: in.Handoff.ExpiresAt}, Status: "pending", State: state}
	if e := n.saveHandoff(&r); e != nil {
		t.Fatal(e)
	}
	return n, r, &calls
}
func TestControlHandoffWorkerSurvivesDisconnectedCaller(t *testing.T) {
	n, _, calls := handoffFixture(t)
	c, cancel := context.WithCancel(context.Background())
	cancel()
	_ = c // The durable worker has its own systemd lifetime, not the caller context.
	if e := n.runHandoff(context.Background()); e != nil {
		t.Fatal(e)
	}
	r, e := n.readHandoff()
	if e != nil || r.Status != "completed" || !r.State.ServiceActive {
		t.Fatal(r.Status, e)
	}
	if !reflect.DeepEqual(*calls, []string{"stop", "released", "files", "enable", "start"}) {
		t.Fatal(*calls)
	}
	if n.runHandoff(context.Background()) == nil {
		t.Fatal("completed transition replayed")
	}
}
func TestControlHandoffNeverResumesUncertainTransition(t *testing.T) {
	for _, stage := range []string{"stopping", "starting", "recovery-required", "completed"} {
		t.Run(stage, func(t *testing.T) {
			n, r, calls := handoffFixture(t)
			r.Status = stage
			n.saveHandoff(&r)
			if n.runHandoff(context.Background()) == nil || len(*calls) != 0 {
				t.Fatal("unsafe implicit resume", *calls)
			}
		})
	}
}
func TestControlHandoffRefusesExpiredApprovalAndPIDReuse(t *testing.T) {
	for _, kind := range []string{"lease", "handoff", "pid-reuse"} {
		t.Run(kind, func(t *testing.T) {
			n, r, calls := handoffFixture(t)
			switch kind {
			case "lease":
				r.Bundle.ExpiresAt = n.now().Add(-time.Second).Format(time.RFC3339)
			case "handoff":
				r.Input.Handoff.ExpiresAt = n.now().Add(-time.Second).Format(time.RFC3339)
				r.Input.Handoff.RollbackDeadline = r.Input.Handoff.ExpiresAt
			case "pid-reuse":
				n.handoffHooks.prepareStop = func(*generated.ControlHandoffInput) (func(context.Context) error, func(), error) {
					return nil, nil, errNative
				}
			}
			n.saveHandoff(&r)
			if n.runHandoff(context.Background()) == nil || len(*calls) != 0 {
				t.Fatal("invalid authority signaled process", *calls)
			}
		})
	}
}
func TestControlHandoffFailuresPreserveDatabaseAndRequireRecovery(t *testing.T) {
	for _, kind := range []string{"stop", "writer", "unit-config-executable", "enable", "start", "health"} {
		t.Run(kind, func(t *testing.T) {
			n, _, _ := handoffFixture(t)
			db := filepath.Join(n.root, "preserved.db")
			os.WriteFile(db, []byte("untouched database"), 0600)
			switch kind {
			case "stop":
				n.handoffHooks.prepareStop = func(*generated.ControlHandoffInput) (func(context.Context) error, func(), error) {
					return func(context.Context) error { return errNative }, func() {}, nil
				}
			case "writer":
				n.handoffHooks.released = func(int64, string) error { return errNative }
			case "unit-config-executable":
				n.handoffHooks.files = func(generated.LinuxRoleInput) error { return errNative }
			case "enable", "start":
				old := n.run
				n.run = func(c context.Context, b string, a []string) ([]byte, error) {
					if a[0] == kind {
						return nil, errNative
					}
					return old(c, b, a)
				}
			case "health":
				old := n.handoffHooks.state
				count := 0
				n.handoffHooks.state = func(c context.Context, in generated.LinuxRoleInput) (ControlServiceState, error) {
					count++
					if count > 1 {
						return ControlServiceState{}, errNative
					}
					return old(c, in)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if n.runHandoff(ctx) == nil {
				t.Fatal("failure accepted")
			}
			r, e := n.readHandoff()
			if e != nil || r.Status != "recovery-required" {
				t.Fatal(r.Status, e)
			}
			body, _ := os.ReadFile(db)
			if string(body) != "untouched database" {
				t.Fatal("database touched")
			}
		})
	}
}
func TestHandoffReceiptTamperingRejected(t *testing.T) {
	n, r, _ := handoffFixture(t)
	r.Input.Handoff.ForegroundPID++
	body, _ := os.ReadFile(filepath.Join(n.root, handoffReceiptPath))
	body = append(body, []byte(" trailing")...)
	os.WriteFile(filepath.Join(n.root, handoffReceiptPath), body, 0600)
	if _, e := n.readHandoff(); e == nil {
		t.Fatal("malformed protected receipt accepted")
	}
}
