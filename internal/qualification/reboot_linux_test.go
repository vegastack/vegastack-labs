//go:build linux

package qualification

import (
	"context"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestNativeRebootTargetCannotBroadenScenario(t *testing.T) {
	s, err := validateScope(scopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		scenario, guest string
		allowed         bool
	}{
		{"access-rollback-reboot", "subject", true},
		{"access-rollback-reboot", "controller", false},
		{"replacement-recovery", "controller", true},
		{"replacement-recovery", "subject", false},
		{"baseline-access", "subject", false},
		{"access-rollback-reboot", "outside", false},
	} {
		if got := nativeRebootAllowed(s, generated.NativeStepRequest{ScenarioID: tc.scenario, GuestID: tc.guest}); got != tc.allowed {
			t.Fatalf("%s/%s = %v", tc.scenario, tc.guest, got)
		}
	}
}
func TestNativeRebootRequiresChangedBootAndHonorsCancellation(t *testing.T) {
	before := "11111111-1111-4111-8111-111111111111"
	after := "22222222-2222-4222-8222-222222222222"
	for _, bad := range []string{before, "invalid"} {
		if _, err := waitChangedBoot(context.Background(), before, func(context.Context) (string, error) { return bad, nil }); err == nil {
			t.Fatal("unchanged/malformed boot accepted")
		}
	}
	got, err := waitChangedBoot(context.Background(), before, func(context.Context) (string, error) { return after, nil })
	if err != nil || got != after {
		t.Fatal("fresh boot rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := waitChangedBoot(ctx, before, func(context.Context) (string, error) { return "", ErrUnavailable }); err != context.Canceled {
		t.Fatalf("cancel = %v", err)
	}
}
