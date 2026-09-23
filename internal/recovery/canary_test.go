package recovery

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type canaryFixture struct {
	calls  []string
	fail   string
	digest string
}

func (f *canaryFixture) step(name string) error {
	f.calls = append(f.calls, name)
	if f.fail == name {
		return errors.New("failed")
	}
	return nil
}
func (f *canaryFixture) VerifyRecoveryRead(context.Context, CanaryRequest) error {
	return f.step("read")
}
func (f *canaryFixture) VerifyOldEpochDenied(context.Context, CanaryRequest) error {
	return f.step("old-epoch")
}
func (f *canaryFixture) RunRecoveryCanaryNoop(context.Context, CanaryRequest) (string, error) {
	if err := f.step("noop"); err != nil {
		return "", err
	}
	return "run-canary", nil
}
func (f *canaryFixture) AppendAndVerifyRecoveryCheckpoint(context.Context, CanaryRequest, string) (string, error) {
	if err := f.step("audit"); err != nil {
		return "", err
	}
	return "checkpoint-canary", nil
}
func (f *canaryFixture) CreateAndVerifyRecoveryBackup(context.Context, CanaryRequest) (string, error) {
	if err := f.step("backup"); err != nil {
		return "", err
	}
	return "point-canary", nil
}
func (f *canaryFixture) VerifyFormerWriterDenied(context.Context, CanaryRequest) error {
	return f.step("former-writer")
}
func (f *canaryFixture) EnableAuthority(_ context.Context, _ CanaryRequest, digest string) error {
	f.digest = digest
	return f.step("enable")
}

func TestAuthorityEnablesOnlyAfterCompleteCanary(t *testing.T) {
	request := CanaryRequest{PlanID: "plan-a", PlanDigest: "sha256:" + strings.Repeat("a", 64), NewInstanceID: "instance-new", FenceSetDigest: "sha256:" + strings.Repeat("b", 64), RecoveryEpoch: 8, ExpectedStateRevision: 19, ResponsibleHumanID: "human-a", PrincipalMethod: "local-os-peer"}
	for _, failureAt := range []string{"read", "old-epoch", "noop", "audit", "backup", "former-writer", "enable"} {
		t.Run(failureAt, func(t *testing.T) {
			f := &canaryFixture{fail: failureAt}
			v := CanaryVerifier{Read: f, OldEpoch: f, Noop: f, Audit: f, Backup: f, FormerWriter: f, Enable: f, Clock: func() time.Time { return time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC) }}
			if _, err := v.Verify(context.Background(), request); failureCode(err) != generated.ErrorCodeRecoveryRequired {
				t.Fatalf("code=%s err=%v", failureCode(err), err)
			}
			for _, call := range f.calls {
				if call == "enable" && failureAt != "enable" {
					t.Fatal("enabled after incomplete canary")
				}
			}
		})
	}
	f := &canaryFixture{}
	v := CanaryVerifier{Read: f, OldEpoch: f, Noop: f, Audit: f, Backup: f, FormerWriter: f, Enable: f, Clock: func() time.Time { return time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC) }}
	result, err := v.Verify(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"read", "old-epoch", "noop", "audit", "backup", "former-writer", "enable"}
	if !reflect.DeepEqual(f.calls, want) || result.Status != "verified" || !restoreDigest.MatchString(f.digest) {
		t.Fatalf("calls=%v result=%#v digest=%s", f.calls, result, f.digest)
	}
}

type authorityStateStub struct{ state AuthorityBinding }

func (s authorityStateStub) CurrentAuthority(context.Context) (AuthorityBinding, error) {
	return s.state, nil
}
func TestOldAuthorityBindingIsDenied(t *testing.T) {
	current := AuthorityBinding{InstanceID: "new", RecoveryEpoch: 4, StateRevision: 9, Mode: "ready"}
	admission := AuthorityAdmission{State: authorityStateStub{current}}
	old := current
	old.RecoveryEpoch = 3
	if code := failureCode(admission.Require(context.Background(), old)); code != generated.ErrorCodeRecoveryEpochMismatch {
		t.Fatalf("code=%s", code)
	}
	wrong := current
	wrong.InstanceID = "old"
	if code := failureCode(admission.Require(context.Background(), wrong)); code != generated.ErrorCodeStateConflict {
		t.Fatalf("code=%s", code)
	}
	if err := admission.Require(context.Background(), current); err != nil {
		t.Fatal(err)
	}
}

func failureCode(err error) string {
	if stable, ok := failure.As(err); ok {
		return stable.Code
	}
	return ""
}
