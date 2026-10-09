//go:build linux

package qualification

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeRootWitnessLoadsServiceOwnedProfile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires approved disposable root ownership test")
	}
	const uid = 65534
	root, err := os.MkdirTemp("/var/tmp", "vsk-native-profile-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	var filesystem unix.Statfs_t
	if err = unix.Statfs(root, &filesystem); err != nil {
		t.Fatal(err)
	}
	t.Logf("profile fixture filesystem: %#x", uint64(filesystem.Type))
	exports := filepath.Join(root, "exports")
	if err := os.Mkdir(exports, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(exports, uid, uid); err != nil {
		t.Fatal(err)
	}
	in := generated.ServerProfile{Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.3.0", SocketPath: "/run/vsk-labs/control.sock", SocketOwnerUID: uid, SocketMode: "0600", ShutdownGraceSeconds: 5, InventoryExportRoot: exports, PrincipalBindings: []generated.LocalPrincipalBinding{{UID: 0, PrincipalID: "native-operator"}}, RemoteRead: generated.RemoteReadProfile{Enabled: false}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "client.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(path, uid, uid); err != nil {
		t.Fatal(err)
	}
	// Reproduce the old root-owner failure on the very same actual file.
	if _, err = serverconfig.NewLoader(0).Load(context.Background(), path); err == nil {
		t.Fatal("root-owner loader unexpectedly accepted service-owned profile")
	}
	profile, err := serverconfig.NewLoader(uid).Load(context.Background(), path)
	if err != nil || validateQualificationClientProfile(profile, uid) != nil || len(profile.PrincipalBindings) != 1 || profile.PrincipalBindings[0].UID != 0 {
		t.Fatal("root witness could not load actual service-owned profile without changing its OS-peer identity", err)
	}
	if err = os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = serverconfig.NewLoader(uid).Load(context.Background(), path); err == nil {
		t.Fatal("root-owned replacement profile accepted")
	}
}
