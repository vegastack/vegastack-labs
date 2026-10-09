package debianaccess

import (
	"context"
	"crypto/ed25519"
	"os"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func preparedFixture(t *testing.T) Preparation {
	t.Helper()
	in := validInput(t)
	p, err := Prepare(context.Background(), in, hostaction.Policy{HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, CallerUID: uint32(in.AutomationUID), KeyID: "server", PublicKey: make(ed25519.PublicKey, 32), ReceiptDirectory: "/var/lib/vsk-labs/host-action"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPreparationCannotInstallBroadSudo(t *testing.T) {
	p := preparedFixture(t)
	p.Files = append(p.Files, PreparedFile{Name: "sudoers", Bytes: []byte("automation ALL=(ALL) NOPASSWD: ALL")})
	if ValidatePreparation(p) == nil {
		t.Fatal("broad privilege accepted")
	}
}
func TestPreparationRejectsRehashedPrivilegeWidening(t *testing.T) {
	p := preparedFixture(t)
	p.Files[1].Bytes = []byte("automation ALL=(root) NOPASSWD: /usr/local/bin/vsk-labs *\n")
	p.Files[1].Digest = digestBytes(p.Files[1].Bytes)
	if ValidatePreparation(p) == nil {
		t.Fatal("arbitrary arguments accepted")
	}
}
func TestPreparationOnlyPublicPolicyAndExactCommand(t *testing.T) {
	p := preparedFixture(t)
	if err := ValidatePreparation(p); err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) == 0 {
		t.Fatal("human preparation missing")
	}
}

func TestPreparationUnitTemplatesMatchCompiledBoundary(t *testing.T) {
	for file, want := range map[string]string{"vsk-access-rollback.service.j2": rollbackService, "vsk-access-rollback-boot.service.j2": rollbackBootService, "vsk-access-rollback.timer.j2": string(timerBytes(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)))} {
		raw, e := os.ReadFile("../../ansible/roles/debian_access/templates/" + file)
		if e != nil {
			t.Fatal(e)
		}
		got := strings.ReplaceAll(string(raw), "{{ vsk_access_deadline_utc }}", "2000-01-01 00:00:00 UTC")
		if got != want {
			t.Fatal("reviewed template differs from fixed native unit", file)
		}
	}
}
