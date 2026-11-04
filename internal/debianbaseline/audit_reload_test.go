//go:build linux || darwin

package debianbaseline

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

// The packaged auditd unit has CanReload=no and no ExecReload. Exercise the
// actual method called by Apply; never run privileged whole-Apply fixtures.
func TestAuditReloadSupportsPackagedUnitWithoutExecReload(t *testing.T) {
	calls := 0
	ctx := context.WithValue(context.Background(), struct{}{}, "reload-context")
	n := &nativeRuntime{run: func(got context.Context, bin string, args []string, stdin []byte) ([]byte, error) {
		calls++
		if got != ctx || stdin != nil {
			t.Fatal("reload context or stdin changed")
		}
		if bin == "/usr/bin/systemctl" && reflect.DeepEqual(args, []string{"reload", "auditd.service"}) {
			return nil, errors.New("Job type reload is not applicable for unit auditd.service")
		}
		if bin != "/usr/sbin/auditctl" || !reflect.DeepEqual(args, []string{"--signal", "reload"}) {
			t.Fatalf("unexpected reload: %s %v", bin, args)
		}
		return nil, nil
	}}
	if err := n.reloadAudit(ctx); err != nil {
		t.Fatalf("packaged service cannot reload through systemctl: %v", err)
	}
	if calls != 1 {
		t.Fatalf("reload attempts: %d", calls)
	}
}

func TestAuditReloadFailureIsPreservedWithoutRetry(t *testing.T) {
	for _, failure := range []error{errors.New("audit reload failed"), context.Canceled} {
		calls := 0
		ctx, cancel := context.WithCancel(context.Background())
		if errors.Is(failure, context.Canceled) {
			cancel()
		}
		n := &nativeRuntime{run: func(got context.Context, bin string, args []string, stdin []byte) ([]byte, error) {
			calls++
			if got != ctx || bin != "/usr/sbin/auditctl" || !reflect.DeepEqual(args, []string{"--signal", "reload"}) || stdin != nil {
				t.Fatalf("unexpected reload command: %s %v", bin, args)
			}
			return nil, failure
		}}
		err := n.reloadAudit(ctx)
		cancel()
		if !errors.Is(err, failure) || calls != 1 {
			t.Fatalf("failure lost or retried: %v calls%d", err, calls)
		}
	}
}
