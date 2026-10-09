package qualification

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func fixtureSignerProfiles(t *testing.T) ([]byte, generated.ServerProfile) {
	t.Helper()
	in := generated.ServerProfile{Schema: generated.SchemaIDServerProfile, SchemaVersion: "1.3.0", SocketPath: "/run/vsk-labs-control/control.sock", SocketOwnerUID: 22001, SocketMode: "0600", ShutdownGraceSeconds: 5, InventoryExportRoot: "/var/lib/vsk-labs/control/exports", PrincipalBindings: []generated.LocalPrincipalBinding{{UID: 22001, PrincipalID: "human-native"}}, AcknowledgementAdapterConfigPath: "/etc/vsk-labs/control/slack.json"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	in.HostActionSignerPath = fixtureControlSignerPath
	in.HostActionKeyID = "native-fixture-action"
	in.HostActionIdentityDigests = []string{"sha256:" + strings.Repeat("a", 64)}
	return raw, in
}

func TestFixtureSignerTransitionAllowsOnlyPreparedSigner(t *testing.T) {
	initial, final := fixtureSignerProfiles(t)
	raw, _ := json.Marshal(final)
	pin := hostaction.BytesDigest(initial)
	if validateFixtureSignerProfiles(initial, raw, 22001, pin) != nil {
		t.Fatal("signer-only transition denied")
	}
	for _, variant := range []string{"socket", "principal", "uid", "backup", "adapter", "partial", "other-key-path", "stale-pin", "already-enabled", "duplicate-field"} {
		t.Run(variant, func(t *testing.T) {
			before, after, digest := initial, final, pin
			switch variant {
			case "socket":
				after.SocketPath = "/run/another.sock"
			case "principal":
				after.PrincipalBindings = []generated.LocalPrincipalBinding{{UID: 22001, PrincipalID: "other"}}
			case "uid":
				after.SocketOwnerUID++
			case "backup":
				path := "/var/lib/backup"
				after.StandardBackupRoot = &path
			case "adapter":
				after.AcknowledgementAdapterConfigPath = "/etc/another.json"
			case "partial":
				after.HostActionKeyID = ""
			case "other-key-path":
				after.HostActionSignerPath = "/etc/other.key"
			case "stale-pin":
				digest = hostaction.BytesDigest([]byte("stale"))
			case "already-enabled":
				before, _ = json.Marshal(final)
				digest = hostaction.BytesDigest(before)
			case "duplicate-field":
				before = append([]byte(`{"socketMode":"0600",`), initial[1:]...)
				digest = hostaction.BytesDigest(before)
			}
			data, _ := json.Marshal(after)
			if validateFixtureSignerProfiles(before, data, 22001, digest) == nil {
				t.Fatal("non-signer transition accepted")
			}
		})
	}
}

func TestFixtureSetupProfileMustMatchProtectedReview(t *testing.T) {
	pin := hostaction.BytesDigest([]byte("original setup profile"))
	request := generated.LocalSetupReviewRequest{ProfileSHA256: pin}
	raw, _ := json.Marshal(map[string]any{"request": request})
	if !fixtureSetupProfileMatches(raw, pin) {
		t.Fatal("original pin denied")
	}
	for _, review := range []json.RawMessage{json.RawMessage(`{}`), json.RawMessage(`{"request":{"profileSha256":"other"}}`), json.RawMessage(`{broken`)} {
		if fixtureSetupProfileMatches(review, pin) {
			t.Fatal("unbound initial profile accepted")
		}
	}
	if fixtureSetupProfileMatches(raw, "") {
		t.Fatal("empty pin accepted")
	}
}

func TestFixtureRuntimeProfileAcceptsCompleteExistingLocalBackup(t *testing.T) {
	initial, final := fixtureSignerProfiles(t)
	standard, critical, binary, custody := "/var/lib/vsk-labs/backup/standard", "/var/lib/vsk-labs/backup/critical", "/usr/bin/restic", "/etc/vsk-labs/control/custody.json"
	final.StandardBackupRoot, final.CriticalBackupRoot, final.ResticBinaryPath, final.CustodyPolicyPath = &standard, &critical, &binary, &custody
	raw, _ := json.Marshal(final)
	if validateFixtureSignerProfiles(initial, raw, 22001, hostaction.BytesDigest(initial)) != nil {
		t.Fatal("complete existing local backup profile denied")
	}
	final.CustodyPolicyPath = nil
	raw, _ = json.Marshal(final)
	if validateFixtureSignerProfiles(initial, raw, 22001, hostaction.BytesDigest(initial)) == nil {
		t.Fatal("partial backup profile accepted")
	}
}
