//go:build linux || darwin

package debianbaseline

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func volumeRecoveryFixture(t *testing.T) (string, generated.VolumeRecoveryInput) {
	t.Helper()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	header := make([]byte, 16<<20)
	copy(header, []byte{'L', 'U', 'K', 'S', 0xba, 0xbe})
	binary.BigEndian.PutUint16(header[6:8], 2)
	binary.BigEndian.PutUint64(header[8:16], 16384)
	uuid := "11111111-2222-3333-4444-555555555555"
	copy(header[168:208], uuid)
	d := func(s string) string { return hostaction.BytesDigest([]byte(s)) }
	b := generated.HostVolumeBinding{Schema: generated.SchemaIDHostVolumeBinding, SchemaVersion: "1.0.0", HostID: "subject", HostIdentityDigest: d("subject"), VolumeID: "data", ControlHostID: "controller", ControlHostIdentityDigest: d("controller"), HeaderBytes: int64(len(header)), LUKSUUID: uuid, HeaderDigest: hostaction.BytesDigest(header), MappingDigest: d("mapping"), MountBindingDigest: d("mount"), MapperName: "data", MountPath: "/srv/data", DeviceMajor: 8, DeviceMinor: 1, KeySlot: 0, RecoveryCustodianID: "custodian", RecoveryCustodianIdentityDigest: d("custodian"), RecoveryTargetDigest: d("target"), RecoveryReferenceDigest: d("initial"), DeclarationID: "declaration", DeclarationRevision: 1, RecoveryEpoch: 0}
	in := generated.VolumeRecoveryInput{Schema: generated.SchemaIDVolumeRecoveryInput, SchemaVersion: "1.0.0", HostID: b.RecoveryCustodianID, HostIdentityDigest: b.RecoveryCustodianIdentityDigest, ProfileLockDigest: d("profile"), Binding: b, PriorVolumeReceiptDigest: d("actual-prior-receipt"), RecoveryReferenceID: "recovery-data", RecoveryMaterialVersion: "v1"}
	dir := filepath.Join(root, "etc/vsk-labs/volume-recovery/recovery-data")
	if e := os.MkdirAll(dir, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(root, "usr/sbin"), 0700); e != nil {
		t.Fatal(e)
	}
	tool := []byte("synthetic test tool bytes, never executed")
	policy, digest, e := PrepareVolumeRecoveryPolicy(in, hostaction.BytesDigest(tool))
	if e != nil {
		t.Fatal(e)
	}
	in.Binding.RecoveryReferenceDigest = digest
	for name, raw := range map[string][]byte{"policy.json": policy, "header": header, "key": []byte("synthetic-key-canary")} {
		if e := os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.WriteFile(filepath.Join(root, "usr/sbin/cryptsetup"), tool, 0700); e != nil {
		t.Fatal(e)
	}
	return root, in
}
func TestVolumeRecoveryRejectsWrongHeaderBeforeKeyUse(t *testing.T) {
	root, in := volumeRecoveryFixture(t)
	headerPath := filepath.Join(root, "etc/vsk-labs/volume-recovery/recovery-data/header")
	f, writeErr := os.OpenFile(headerPath, os.O_WRONLY, 0)
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if _, writeErr = f.WriteAt([]byte{1}, 4096); writeErr != nil {
		f.Close()
		t.Fatal(writeErr)
	}
	f.Close()
	calls := 0
	_, e := verifyVolumeRecoveryFiles(context.Background(), root, uint32(os.Getuid()), in, func(context.Context, []byte, *os.File, *os.File, int64) error { calls++; return nil }, time.Now())
	if e == nil || calls != 0 {
		t.Fatal("wrong header reached recovery operation")
	}
}
func TestVolumeRecoveryPrivateFilesAndObservedResult(t *testing.T) {
	root, in := volumeRecoveryFixture(t)
	before, e := os.ReadFile(filepath.Join(root, "etc/vsk-labs/volume-recovery/recovery-data/header"))
	if e != nil {
		t.Fatal(e)
	}
	rows, e := verifyVolumeRecoveryFiles(context.Background(), root, uint32(os.Getuid()), in, func(_ context.Context, _ []byte, h, k *os.File, slot int64) error {
		key, e := readVolumeKey(k)
		defer clear(key)
		if e != nil || string(key) != "synthetic-key-canary" || slot != 0 {
			return errVolume
		}
		return nil
	}, time.Now())
	if e != nil || len(rows) != 1 || rows[0].Volume == nil || rows[0].Volume.Kind != "recovery" {
		t.Fatal(rows, e)
	}
	encoded, marshalErr := json.Marshal(rows)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), "synthetic-key-canary") {
		t.Fatal("key leaked")
	}
	after, _ := os.ReadFile(filepath.Join(root, "etc/vsk-labs/volume-recovery/recovery-data/header"))
	if hostaction.BytesDigest(before) != hostaction.BytesDigest(after) {
		t.Fatal("header mutated")
	}
	for _, file := range []string{"key", "header", "policy.json"} {
		t.Run(file, func(t *testing.T) {
			p := filepath.Join(root, "etc/vsk-labs/volume-recovery/recovery-data", file)
			if e := os.Chmod(p, 0644); e != nil {
				t.Fatal(e)
			}
			defer os.Chmod(p, 0600)
			called := false
			_, e := verifyVolumeRecoveryFiles(context.Background(), root, uint32(os.Getuid()), in, func(context.Context, []byte, *os.File, *os.File, int64) error { called = true; return nil }, time.Now())
			if e == nil || called {
				t.Fatal("public private-file reached key test")
			}
		})
	}
}
func TestVolumeRecoveryRejectsHeaderChangeAndFailedKey(t *testing.T) {
	for _, change := range []bool{false, true} {
		root, in := volumeRecoveryFixture(t)
		_, e := verifyVolumeRecoveryFiles(context.Background(), root, uint32(os.Getuid()), in, func(context.Context, []byte, *os.File, *os.File, int64) error {
			if !change {
				return errVolume
			}
			return os.WriteFile(filepath.Join(root, "etc/vsk-labs/volume-recovery/recovery-data/header"), []byte("changed"), 0600)
		}, time.Now())
		if e == nil {
			t.Fatal("failed key or changed header passed")
		}
	}
}
func TestVolumeProtectedFilesRejectLinkAndTraversal(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "source"), []byte("synthetic"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("source", filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"link", "../source", "/source"} {
		if f, e := openVolumeProtected(root, p, uint32(os.Getuid()), true); e == nil {
			f.Close()
			t.Fatal("unsafe path accepted")
		}
	}
	if e := os.Link(filepath.Join(root, "source"), filepath.Join(root, "hard")); e != nil {
		t.Fatal(e)
	}
	if f, e := openVolumeProtected(root, "hard", uint32(os.Getuid()), true); e == nil {
		f.Close()
		t.Fatal("hard link accepted")
	}
}

func TestVolumeRecoveryUsesVerifiedToolSnapshotAfterReplacement(t *testing.T) {
	root, in := volumeRecoveryFixture(t)
	toolPath := filepath.Join(root, "usr/sbin/cryptsetup")
	verified, e := os.ReadFile(toolPath)
	if e != nil {
		t.Fatal(e)
	}
	called := false
	_, e = verifyVolumeRecoveryFiles(context.Background(), root, uint32(os.Getuid()), in, func(_ context.Context, tool []byte, _, _ *os.File, _ int64) error {
		called = true
		// Replacement after the digest check cannot change the bytes handed to
		// the production sealed-executable runner (which never reopens this path).
		if e := os.WriteFile(toolPath, []byte("unverified replacement"), 0700); e != nil {
			return e
		}
		if hostaction.BytesDigest(tool) != hostaction.BytesDigest(verified) {
			t.Fatal("unverified executable snapshot reached key boundary")
		}
		return nil
	}, time.Now())
	if e != nil || !called {
		t.Fatal(e, called)
	}
}
