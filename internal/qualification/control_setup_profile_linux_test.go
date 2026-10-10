//go:build linux

package qualification

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/sys/unix"
)

func TestFixtureSignerProfileReplacementPreservesInvalidInputs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires approved disposable root ownership test")
	}
	for _, variant := range []string{"valid", "stale-pin", "wrong-owner", "wrong-mode", "symlink", "occupied-temporary", "unverified-backup"} {
		t.Run(variant, func(t *testing.T) {
			root, err := os.MkdirTemp("/var/tmp", "vsk-native-signer-test-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			initial, final := fixtureSignerProfiles(t)
			if variant == "unverified-backup" {
				standard, critical, binary, custody := "/var/lib/vsk-labs/backup/standard", "/var/lib/vsk-labs/backup/critical", "/unavailable-native-fixture/restic", "/etc/vsk-labs/control/custody.json"
				final.StandardBackupRoot, final.CriticalBackupRoot, final.ResticBinaryPath, final.CustodyPolicyPath = &standard, &critical, &binary, &custody
			}
			finalRaw, _ := json.Marshal(final)
			old, staged := filepath.Join(root, "server.json"), filepath.Join(root, "server-after-setup.json")
			for path, raw := range map[string][]byte{old: initial, staged: finalRaw} {
				if os.WriteFile(path, raw, 0600) != nil || os.Chown(path, 22001, 22001) != nil {
					t.Fatal("could not prepare owned profile")
				}
			}
			pin := hostaction.BytesDigest(initial)
			temporary := filepath.Join(root, "server.signer-transition")
			switch variant {
			case "stale-pin":
				pin = hostaction.BytesDigest([]byte("changed"))
			case "wrong-owner":
				if os.Chown(staged, 0, 0) != nil {
					t.Fatal("chown failed")
				}
			case "wrong-mode":
				if os.Chmod(staged, 0644) != nil {
					t.Fatal("chmod failed")
				}
			case "symlink":
				if os.Rename(staged, staged+".preserved") != nil || os.Symlink(staged+".preserved", staged) != nil {
					t.Fatal("symlink fixture failed")
				}
			case "occupied-temporary":
				if os.WriteFile(temporary, []byte("preserve"), 0600) != nil {
					t.Fatal("occupied fixture failed")
				}
			}
			digest, err := replaceFixtureSignerProfile(old, staged, 22001, 22001, pin)
			got, readErr := os.ReadFile(old)
			if variant == "valid" {
				var st unix.Stat_t
				if err != nil || readErr != nil || !bytes.Equal(got, finalRaw) || digest != hostaction.BytesDigest(finalRaw) || unix.Lstat(old, &st) != nil || st.Uid != 22001 || st.Gid != 22001 || st.Mode&0777 != 0600 {
					t.Fatal("exact service-owned signer profile not installed", err)
				}
			} else if err == nil || readErr != nil || !bytes.Equal(got, initial) {
				t.Fatal("invalid transition changed initial profile", err)
			}
			if variant == "occupied-temporary" {
				data, err := os.ReadFile(temporary)
				if err != nil || string(data) != "preserve" {
					t.Fatal("occupied artifact changed")
				}
			}
		})
	}
}
