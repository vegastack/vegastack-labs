//go:build linux

package nativecredential

import (
	"context"
	"strings"
	"testing"
)

func TestNativeAuthorityScope(t *testing.T) {
	authority, err := NewNativeAuthority([]string{"example.service"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Restart(context.Background(), "other.service"); err == nil {
		t.Fatal("unenrolled unit restarted")
	}
	if _, err := NewNativeAuthority([]string{"*.service"}); err == nil {
		t.Fatal("wildcard enrollment accepted")
	}
	if _, err := NewNativeAuthority([]string{"example.service", "example.service"}); err == nil {
		t.Fatal("duplicate enrollment accepted")
	}
}

func TestNativeAuthorityRejectsServiceRootOverrides(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		valid        bool
	}{
		{"default-root", "RootDirectory=\nRootImage=\n", true},
		{"custom-directory", "RootDirectory=/srv/jail\nRootImage=\n", false},
		{"root-image", "RootDirectory=\nRootImage=/srv/root.raw\n", false},
		{"missing-field", "RootDirectory=\n", false},
		{"duplicate-field", "RootDirectory=\nRootImage=\nRootImage=\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if parseSystemdRootProfile(tc.output) != tc.valid {
				t.Fatal("root profile qualification mismatch")
			}
		})
	}
}

func TestEffectiveAuthorityRejectsBroadGrants(t *testing.T) {
	unit := "alpha.service"
	subject := "123,456,1001"
	allAllowed := func(context.Context, string, []string) int { return 0 }
	listing := func(context.Context) ([]byte, error) {
		return []byte("Matching Defaults entries for vsk-labs on host:\n    env_reset\n\nUser vsk-labs may run the following commands on host:\n    (root) NOPASSWD: /usr/local/bin/vsk-labs __native-credential-access-probe\n    (root) NOPASSWD: /usr/local/bin/vsk-labs __native-credential-policy-check\n"), nil
	}
	if effectiveAuthorityPolicy(context.Background(), unit, subject, []string{unit}, allAllowed, listing, func(context.Context, string, string) bool { return true }) {
		t.Fatal("broad polkit/sudo grants qualified")
	}
	called := 0
	exact := func(_ context.Context, path string, args []string) int {
		called++
		if path == "/usr/bin/pkcheck" && strings.Contains(strings.Join(args, " "), "org.freedesktop.systemd1.manage-units") && strings.Contains(strings.Join(args, " "), "--detail verb restart --detail unit alpha.service") {
			return 0
		}
		if path == "/usr/bin/sudo" && len(args) > 0 && (args[len(args)-1] == accessProbeMode || args[len(args)-1] == policyCheckMode) {
			return 0
		}
		return 1
	}
	if !effectiveAuthorityPolicy(context.Background(), unit, subject, []string{unit}, exact, listing, func(context.Context, string, string) bool { return true }) {
		t.Fatal("exact allow/deny policy rejected")
	}
	if called != 8 {
		t.Fatalf("effective policy matrix changed: %d", called)
	}
	if effectiveAuthorityPolicy(context.Background(), unit, subject, []string{unit}, exact, listing, func(context.Context, string, string) bool { return false }) {
		t.Fatal("interactive challenge counted as explicit denial")
	}
	for _, broad := range []string{
		"    (root) NOPASSWD: ALL\n",
		"    (root) NOPASSWD: /usr/bin/true\n",
		"    (root) NOPASSWD: /usr/local/bin/vsk-labs __native-credential-access-probe\n    (root) NOPASSWD: /usr/bin/true\n",
	} {
		data := []byte("User vsk-labs may run the following commands on host:\n" + broad)
		if exactSudoAggregate(data) {
			t.Fatalf("broad aggregate accepted: %q", broad)
		}
	}
}

func TestTrustedPolkitPolicyRejectsChallengeAndBroadRules(t *testing.T) {
	unit, subject := "alpha.service", "123,456,1001"
	exact := func(_ context.Context, _ string, args []string) int {
		if strings.Contains(strings.Join(args, " "), "--detail verb restart --detail unit alpha.service") {
			return 0
		}
		return 1
	}
	if !trustedPolkitPolicy(context.Background(), unit, subject, []string{unit}, exact) {
		t.Fatal("exact polkit decisions rejected")
	}
	if trustedPolkitPolicy(context.Background(), unit, subject, []string{unit}, func(context.Context, string, []string) int { return 0 }) {
		t.Fatal("broad polkit rule accepted")
	}
	if trustedPolkitPolicy(context.Background(), unit, subject, []string{unit}, func(ctx context.Context, path string, args []string) int {
		if strings.Contains(strings.Join(args, " "), "--detail verb stop") {
			return 2
		}
		return exact(ctx, path, args)
	}) {
		t.Fatal("interactive challenge accepted")
	}
}
