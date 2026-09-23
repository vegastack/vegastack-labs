//go:build linux

package localretention

import (
	"context"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestLocalRetentionHasNoUnboundExecutionPath(t *testing.T) {
	instance := &Adapter{}
	if _, err := instance.Execute(context.Background(), adapter.Operation{}); err == nil {
		t.Fatal("plain execution admitted destructive local retention")
	}
	if _, err := instance.ExecuteWithCredentials(context.Background(), adapter.Operation{}, nil); err == nil {
		t.Fatal("credential-only execution admitted destructive local retention")
	}
	if _, err := instance.ExecuteBoundWithCredentials(context.Background(), adapter.Operation{}, adapter.ExactExecutionBinding{}, nil); err == nil {
		t.Fatal("malformed exact binding admitted destructive local retention")
	}
}

func TestCustodyPolicyMustMatchServerProfileBeforeClaim(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "srv", "vsk-backup")
	profile := &serverconfig.LocalBackup{StandardRoot: filepath.Join(base, "standard"), CriticalRoot: filepath.Join(base, "critical"), ResticBinaryPath: "/usr/local/bin/restic"}
	policy := backup.CustodyPolicy{ControllerUID: 1000, StandardRoot: profile.StandardRoot, CriticalRoot: profile.CriticalRoot,
		StandardQuarantine: filepath.Join(base, "standard-quarantine"), CriticalQuarantine: filepath.Join(base, "critical-quarantine"), ResticBinaryPath: profile.ResticBinaryPath}
	if !custodyPolicyMatchesProfile(policy, profile, 1000, "standard") || !custodyPolicyMatchesProfile(policy, profile, 1000, "critical") {
		t.Fatal("exact custody policy/profile binding rejected")
	}
	for name, mutate := range map[string]func(*backup.CustodyPolicy){
		"controller":    func(value *backup.CustodyPolicy) { value.ControllerUID++ },
		"standard-root": func(value *backup.CustodyPolicy) { value.StandardRoot = filepath.Join(base, "other") },
		"critical-root": func(value *backup.CustodyPolicy) { value.CriticalRoot = filepath.Join(base, "other") },
		"restic":        func(value *backup.CustodyPolicy) { value.ResticBinaryPath = "/usr/bin/restic" },
		"quarantine": func(value *backup.CustodyPolicy) {
			value.StandardQuarantine = filepath.Join(string(filepath.Separator), "other", "quarantine")
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := policy
			mutate(&changed)
			if custodyPolicyMatchesProfile(changed, profile, 1000, "standard") {
				t.Fatal("mismatched custody policy admitted")
			}
		})
	}
}

func TestBoundSelectionDigestRequiresExactNamedBindings(t *testing.T) {
	selection := "sha256:" + strings.Repeat("a", 64)
	credential := "sha256:" + strings.Repeat("b", 64)
	valid := []generated.ContractExtension{{Name: "x-backup-local-retirement", ValueDigest: selection}, {Name: "x-credential-bindings", ValueDigest: credential}}
	if got, ok := boundSelectionDigest(valid, credential); !ok || got != selection {
		t.Fatalf("exact extensions rejected: %q %t", got, ok)
	}
	for name, extensions := range map[string][]generated.ContractExtension{
		"missing-selection":   {{Name: "x-credential-bindings", ValueDigest: credential}},
		"missing-credential":  {{Name: "x-backup-local-retirement", ValueDigest: selection}},
		"swapped-values":      {{Name: "x-backup-local-retirement", ValueDigest: credential}, {Name: "x-credential-bindings", ValueDigest: selection}},
		"unknown-extension":   append(append([]generated.ContractExtension(nil), valid...), generated.ContractExtension{Name: "x-other", ValueDigest: selection}),
		"duplicate-selection": append(append([]generated.ContractExtension(nil), valid...), valid[0]),
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := boundSelectionDigest(extensions, credential); ok {
				t.Fatal("malformed plan extensions accepted")
			}
		})
	}
}

func TestMeasuredRetirementBytesRejectInvalidInventory(t *testing.T) {
	if got, ok := inventoryBytes([]backup.ExpectedObject{{Bytes: 5}, {Bytes: 7}}); !ok || got != 12 {
		t.Fatalf("bounded inventory bytes=%d ok=%t", got, ok)
	}
	for _, objects := range [][]backup.ExpectedObject{{{Bytes: -1}}, {{Bytes: math.MaxInt64}, {Bytes: 1}}} {
		if _, ok := inventoryBytes(objects); ok {
			t.Fatal("invalid inventory bytes accepted")
		}
	}
}

func TestLocalRetentionRequiresServerOwnedRepositories(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("local retention constructed without server-owned repositories")
	}
}
