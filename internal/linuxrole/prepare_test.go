package linuxrole

import (
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparationHasNoEffects(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	p, err := Prepare(fixture())
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("preparation mutated filesystem")
	}
	if err = ValidatePreparation(p); err != nil {
		t.Fatal(err)
	}
	for _, file := range p.Files {
		if filepath.IsAbs(file.Path) {
			t.Fatal("unbounded path")
		}
	}
	p.Files[0].Content = "ExecStart=/bin/evil"
	if ValidatePreparation(p) == nil {
		t.Fatal("tampered preparation accepted")
	}
}

func TestInertPreparationNeedsNoBaselineProof(t *testing.T) {
	in := fixture()
	in.BaselineSnapshotDigest = ""
	p, e := Prepare(in)
	if e != nil {
		t.Fatal(e)
	}
	if p.Input.BaselineSnapshotDigest != "" {
		t.Fatal("preparation invented baseline proof")
	}
	if ValidateInput(p.Input) == nil {
		t.Fatal("unsealed preparation executable")
	}
}

func TestCanonicalControlCredentialDelivery(t *testing.T) {
	raw, _ := json.Marshal(fixture())
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	name := "credential-" + strings.Repeat("a", 32)
	fields["controlPlainCredentials"] = []string{"slack-bot", "slack-app"}
	fields["controlEncryptedCredentials"] = []string{name}
	fields["controlLocalBackup"] = true
	raw, _ = json.Marshal(fields)
	in, err := DecodeDesiredInput(raw)
	if err != nil {
		t.Fatalf("finite credential delivery missing: %v", err)
	}

	swapped := in
	swapped.ControlPlainCredentials = []string{"slack-app", "slack-bot"}
	if PolicyDigest(swapped) != PolicyDigest(in) || RoleBindingDigest(swapped) != RoleBindingDigest(in) {
		t.Fatal("name order changed canonical policy binding")
	}
	for kind, change := range map[string]func(*generated.LinuxRoleInput){
		"bad-encrypted":        func(i *generated.LinuxRoleInput) { i.ControlEncryptedCredentials = []string{"foreign"} },
		"cross-list-duplicate": func(i *generated.LinuxRoleInput) { i.ControlPlainCredentials = append(i.ControlPlainCredentials, name) },
		"combined-over-cap": func(i *generated.LinuxRoleInput) {
			i.ControlPlainCredentials = nil
			for n := 0; n < 16; n++ {
				i.ControlPlainCredentials = append(i.ControlPlainCredentials, fmt.Sprintf("name-%d", n))
			}
		},
	} {
		t.Run(kind, func(t *testing.T) {
			changed := in
			change(&changed)
			if ValidateDesiredInput(changed) == nil {
				t.Fatal("unsafe credential delivery accepted")
			}
		})
	}
	unit := string(DesiredFiles(in)["etc/systemd/system/vsk-labs.service"])
	if !strings.Contains(unit, "ReadWritePaths=/var/lib/vsk-labs/control /run/vsk-labs-control /run/vsk-labs/backup/requests /run/vsk-labs/backup/exchange\n") {
		t.Fatal("declared existing custody exchange cannot be written")
	}
	for _, line := range []string{"LoadCredential=slack-app:/etc/vsk-labs/control/credentials/slack-app\n", "LoadCredential=slack-bot:/etc/vsk-labs/control/credentials/slack-bot\n", "LoadCredentialEncrypted=" + name + ":/var/lib/vsk-labs/control/credential-drafts/" + name + "\n"} {
		if !strings.Contains(unit, line) {
			t.Fatal("canonical delivery missing", line)
		}
	}
	for kind, names := range map[string][]string{"newline": {"slack-app\nExecStart=/bin/sh"}, "path": {"../secret"}, "percent": {"%n"}, "duplicate": {"slack-app", "slack-app"}} {
		t.Run(kind, func(t *testing.T) {
			fields["controlPlainCredentials"] = names
			raw, _ := json.Marshal(fields)
			if _, err := DecodeDesiredInput(raw); err == nil {
				t.Fatal("unsafe credential name accepted")
			}
		})
	}
}

func TestControlPrivilegesFollowDeclaredHelpers(t *testing.T) {
	for _, test := range []struct {
		name              string
		encrypted, backup bool
	}{
		{"default", false, false}, {"encrypted", true, false}, {"backup", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := fixture()
			if test.encrypted {
				in.ControlEncryptedCredentials = []string{"credential-" + strings.Repeat("a", 32)}
			}
			in.ControlLocalBackup = test.backup
			want := "yes"
			if test.encrypted || test.backup {
				want = "no"
			}
			unit := string(DesiredFiles(in)["etc/systemd/system/vsk-labs.service"])
			if !strings.Contains(unit, "NoNewPrivileges="+want+"\n") || !strings.Contains(unit, "ProtectSystem=strict\n") {
				t.Fatal("declared fixed helpers and canonical service protections disagree")
			}
		})
	}
}
