package run

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"strings"
	"testing"
)

// The optional continuation path must never fall through to an ordinary
// verifier, which could repeat the restart of an already interrupted attempt.
func TestNativeRestartContinuationWithoutPortsNeverRestarts(t *testing.T) {
	e := &CoreCredentialEffect{lifecycleVerifier: UnavailableCredentialLifecycleVerifier{}}
	b := credentialref.LifecycleBinding{NativeRestartContinuation: &credentialref.NativeRestartContinuation{PriorRunID: "run-a", PriorStepID: "step-a"}}
	if _, err := e.verifyLifecycle(context.Background(), ExactStepBinding{}, b); err == nil {
		t.Fatal("missing continuation ports accepted")
	}
}

type restartPanicVerifier struct {
	UnavailableCredentialLifecycleVerifier
}

func (restartPanicVerifier) PrepareNativeRestart(context.Context, ExactStepBinding, credentialref.LifecycleBinding) (credentialref.NativeRestartPending, bool, error) {
	panic("synthetic secret")
}
func (restartPanicVerifier) EnqueueNativeRestart(context.Context, credentialref.NativeRestartPending) error {
	return errors.New("unexpected")
}
func (restartPanicVerifier) VerifyNativeContinuation(context.Context, ExactStepBinding, credentialref.LifecycleBinding, credentialref.NativeRestartPending) ([]credentialref.ConsumerVerification, error) {
	return nil, errors.New("unexpected")
}
func TestNativeRestartVerifierPanicRemainsRedacted(t *testing.T) {
	e := &CoreCredentialEffect{lifecycleVerifier: restartPanicVerifier{}}
	b := credentialref.LifecycleBinding{HostActionConsole: &credentialref.HostActionConsoleBinding{}, ResolverID: "native-systemd", ConsumerIDs: []string{"host-action"}}
	if _, err := e.verifyLifecycle(context.Background(), ExactStepBinding{}, b); err == nil || err.Error() == "synthetic secret" {
		t.Fatal("restart panic leaked or passed")
	}
}

type restartOrderRepository struct {
	CredentialLifecycleRepository
	events *[]string
	fail   bool
}

func (r restartOrderRepository) RecordNativeRestartPending(context.Context, credentialref.NativeRestartPending, audit.Attribution) error {
	*r.events = append(*r.events, "persist")
	if r.fail {
		return errors.New("synthetic persistence failure")
	}
	return nil
}
func (restartOrderRepository) ReadNativeRestartPending(context.Context, string, string) (credentialref.NativeRestartPending, error) {
	return credentialref.NativeRestartPending{}, errors.New("unexpected")
}

type restartOrderVerifier struct {
	UnavailableCredentialLifecycleVerifier
	events *[]string
}

func (v restartOrderVerifier) PrepareNativeRestart(context.Context, ExactStepBinding, credentialref.LifecycleBinding) (credentialref.NativeRestartPending, bool, error) {
	*v.events = append(*v.events, "observe-before")
	return credentialref.NativeRestartPending{}, true, nil
}
func (v restartOrderVerifier) EnqueueNativeRestart(context.Context, credentialref.NativeRestartPending) error {
	*v.events = append(*v.events, "queue")
	return nil
}
func (restartOrderVerifier) VerifyNativeContinuation(context.Context, ExactStepBinding, credentialref.LifecycleBinding, credentialref.NativeRestartPending) ([]credentialref.ConsumerVerification, error) {
	return nil, errors.New("unexpected")
}
func TestNativeRestartPersistsBeforeQueueAndNeverReportsVerified(t *testing.T) {
	for _, fail := range []bool{false, true} {
		events := []string{}
		e := &CoreCredentialEffect{repository: restartOrderRepository{events: &events, fail: fail}, lifecycleVerifier: restartOrderVerifier{events: &events}}
		b := credentialref.LifecycleBinding{HostActionConsole: &credentialref.HostActionConsoleBinding{}, ResolverID: "native-systemd", ConsumerIDs: []string{"host-action"}}
		verified, err := e.verifyLifecycle(context.Background(), ExactStepBinding{}, b)
		if err == nil || len(verified) != 0 {
			t.Fatal("restart queue became verification")
		}
		want := "observe-before,persist,queue"
		if fail {
			want = "observe-before,persist"
		}
		if strings.Join(events, ",") != want {
			t.Fatalf("restart order %v", events)
		}
	}
}
