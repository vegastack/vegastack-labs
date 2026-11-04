//go:build linux || darwin

package debianbaseline

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestFail2banWaitsForAsynchronousStartup(t *testing.T) {
	daemonReady, jailReady := false, false
	statuses, reloads, starts := 0, 0, 0
	n := &nativeRuntime{run: func(ctx context.Context, bin string, args []string, _ []byte) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		switch {
		case bin == "/usr/bin/fail2ban-client" && reflect.DeepEqual(args, []string{"-t"}):
			return nil, nil
		case bin == "/usr/bin/systemctl" && reflect.DeepEqual(args, []string{"is-active", "fail2ban.service"}):
			return nil, errors.New("inactive")
		case bin == "/usr/bin/systemctl" && reflect.DeepEqual(args, []string{"start", "fail2ban.service"}):
			daemonReady = true
			starts++
			return nil, nil
		case bin == "/usr/bin/fail2ban-client" && reflect.DeepEqual(args, []string{"status", "sshd"}):
			if !daemonReady {
				t.Fatal("status before start")
			}
			statuses++
			if statuses < 3 {
				return nil, errors.New("daemon ready but SSH jail not yet available")
			}
			jailReady = true
			return []byte("Status for the jail: sshd\n"), nil
		case bin == "/usr/bin/fail2ban-client" && reflect.DeepEqual(args, []string{"reload", "sshd"}):
			reloads++
			if !jailReady {
				return nil, errors.New("selected SSH jail not ready")
			}
			return nil, nil
		default:
			t.Fatalf("unexpected command %s %v", bin, args)
			return nil, nil
		}
	}}
	if e := n.startFail2ban(context.Background()); e != nil {
		t.Fatalf("reload raced selected jail readiness: %v; starts=%d statuses=%d reloads=%d", e, starts, statuses, reloads)
	}
	if starts != 1 || statuses != 3 || reloads != 1 {
		t.Fatalf("unexpected command counts %d/%d/%d", starts, statuses, reloads)
	}
}
func TestFail2banNeverReadyOrCancelledCannotReload(t *testing.T) {
	for _, mode := range []string{"never-ready", "cancel-after-start"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			reloads := 0
			n := &nativeRuntime{run: func(ctx context.Context, bin string, args []string, _ []byte) ([]byte, error) {
				if reflect.DeepEqual(args, []string{"-t"}) {
					return nil, nil
				}
				if reflect.DeepEqual(args, []string{"is-active", "fail2ban.service"}) {
					return nil, errors.New("inactive")
				}
				if reflect.DeepEqual(args, []string{"start", "fail2ban.service"}) {
					if mode == "cancel-after-start" {
						cancel()
					}
					return nil, nil
				}
				if reflect.DeepEqual(args, []string{"status", "sshd"}) {
					return nil, errors.New("not ready")
				}
				if reflect.DeepEqual(args, []string{"reload", "sshd"}) {
					reloads++
					return nil, errors.New("not ready")
				}
				t.Fatalf("unexpected %s %v", bin, args)
				return nil, nil
			}}
			if e := n.startFail2ban(ctx); e == nil {
				t.Fatal("unavailable jail accepted")
			}
			if reloads != 0 {
				t.Fatalf("reload attempted before readiness: %d", reloads)
			}
		})
	}
}
func TestFail2banActiveServicePreservesSingleReload(t *testing.T) {
	reloads := 0
	n := &nativeRuntime{run: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
		if reflect.DeepEqual(args, []string{"-t"}) || reflect.DeepEqual(args, []string{"is-active", "fail2ban.service"}) {
			return nil, nil
		}
		if reflect.DeepEqual(args, []string{"reload", "sshd"}) {
			reloads++
			return nil, nil
		}
		t.Fatalf("active service got new readiness/start operation %s %v", bin, args)
		return nil, nil
	}}
	if e := n.startFail2ban(context.Background()); e != nil || reloads != 1 {
		t.Fatalf("active path changed: %v reloads%d", e, reloads)
	}
}

func TestFail2banCommandFailuresStopWithoutRetry(t *testing.T) {
	for _, failed := range []string{"configuration", "start", "reload"} {
		t.Run(failed, func(t *testing.T) {
			failure := errors.New("selected command failed")
			starts, reloads, statuses := 0, 0, 0
			n := &nativeRuntime{run: func(_ context.Context, bin string, args []string, _ []byte) ([]byte, error) {
				switch {
				case bin == "/usr/bin/fail2ban-client" && reflect.DeepEqual(args, []string{"-t"}):
					if failed == "configuration" {
						return nil, failure
					}
					return nil, nil
				case bin == "/usr/bin/systemctl" && reflect.DeepEqual(args, []string{"is-active", "fail2ban.service"}):
					return nil, errors.New("inactive")
				case bin == "/usr/bin/systemctl" && reflect.DeepEqual(args, []string{"start", "fail2ban.service"}):
					starts++
					if failed == "start" {
						return nil, failure
					}
					return nil, nil
				case bin == "/usr/bin/fail2ban-client" && reflect.DeepEqual(args, []string{"status", "sshd"}):
					statuses++
					return nil, nil
				case bin == "/usr/bin/fail2ban-client" && reflect.DeepEqual(args, []string{"reload", "sshd"}):
					reloads++
					return nil, failure
				default:
					t.Fatalf("unexpected command %s %v", bin, args)
					return nil, nil
				}
			}}
			if err := n.startFail2ban(context.Background()); !errors.Is(err, failure) {
				t.Fatalf("failure not preserved: %v", err)
			}
			expectedStarts, expectedStatuses, expectedReloads := 0, 0, 0
			if failed != "configuration" {
				expectedStarts = 1
			}
			if failed == "reload" {
				expectedStatuses = 1
				expectedReloads = 1
			}
			if starts != expectedStarts || statuses != expectedStatuses || reloads != expectedReloads {
				t.Fatalf("command continued or retried after failure: starts%d statuses%d reloads%d", starts, statuses, reloads)
			}
		})
	}
}
