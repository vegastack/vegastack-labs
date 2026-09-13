//go:build linux

package server

import "testing"

func TestPhase4AcceptanceBuiltExecutableKeepsIntentInertAndPrivate(t *testing.T) {
	fixture := newPhase3ExecutableFixture(t)
	outcome := runPhase4AcceptanceBuiltProbe(t, fixture)
	if outcome.SchemaVersion != 1 || outcome.Check != "phase-4-real-change-server" || outcome.Status != "pass" {
		t.Fatalf("phase 4 built-process outcome = %#v", outcome)
	}
}
