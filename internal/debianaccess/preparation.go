package debianaccess

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type PreparedFile struct {
	Name     string
	Bytes    []byte
	Digest   string
	OwnerUID uint32
	Mode     os.FileMode
}
type Preparation struct {
	Account generated.AccessAccount
	Files   []PreparedFile
	Steps   []string
}

// Prepare is inert: it neither discovers credentials nor writes files or installs trust.
func Prepare(ctx context.Context, input generated.DebianAccessInput, policy hostaction.Policy) (Preparation, error) {
	if ctx == nil || ctx.Err() != nil || input.HostID != policy.HostID || input.HostIdentityDigest != policy.HostIdentityDigest || input.AutomationUID != int64(policy.CallerUID) || policy.CallerUID == 0 || len(policy.PublicKey) != ed25519.PublicKeySize || policy.KeyID == "" || policy.ReceiptDirectory != "/var/lib/vsk-labs/host-action" {
		return Preparation{}, errAccess
	}
	encoded, e := json.Marshal(input)
	if e != nil {
		return Preparation{}, e
	}
	if _, e = DecodeInput(encoded); e != nil {
		return Preparation{}, e
	}
	name := ""
	var account generated.AccessAccount
	for _, a := range input.Accounts {
		if a.Role == "automation" && a.UID == input.AutomationUID && accessName.MatchString(a.Name) {
			if name != "" {
				return Preparation{}, errAccess
			}
			name = a.Name
			account = a
		}
	}
	if name == "" {
		return Preparation{}, errAccess
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return Preparation{}, err
	}
	sudo := []byte(fmt.Sprintf("%s ALL=(root) NOPASSWD: /usr/local/bin/vsk-labs host-action-once\n", name))
	profileRaw, _ := json.Marshal(input.ProfileLock)
	desired, err := DesiredFiles(input)
	if err != nil {
		return Preparation{}, err
	}
	p := Preparation{Account: account, Files: []PreparedFile{{Name: "etc/vsk-labs/host-action.json", Bytes: raw, Mode: 0600}, {Name: "etc/sudoers.d/vsk-host-action", Bytes: sudo, Mode: 0440},
		{Name: "etc/vsk-labs/debian-profile.json", Bytes: profileRaw, Mode: 0600},
		{Name: "etc/systemd/system/vsk-access-rollback.service", Bytes: []byte(rollbackService), Mode: 0644},
		{Name: "etc/systemd/system/vsk-access-rollback-boot.service", Bytes: []byte(rollbackBootService), Mode: 0644},
		{Name: "etc/ssh/sshd_config.d/70-vsk-access.conf", Bytes: initialAutomationSSH(name), Mode: 0644},
		{Name: "etc/vsk-labs/authorized_keys/" + name, Bytes: desired["etc/vsk-labs/authorized_keys/"+name], Mode: 0644}}, Steps: []string{
		"At the independently verified console, verify the exact machine and executable release signature/digest before installation.",
		"Review existing automation UID/GID/home and preserve all unrelated users, groups and keys; refuse conflicting account identities.",
		"Install the verified executable at /usr/local/bin/vsk-labs, root-owned mode0755 with protected ancestors; never fetch or execute a caller-selected binary.",
		"Create root-owned private /var/lib/vsk-labs/host-action and /var/lib/vsk-labs/access-rollback directories; install only the reviewed public-key policy and exact sudoers asset.",
		"Validate the temporary sudoers file with /usr/sbin/visudo -cf before its atomic installation; preserve unknown existing sudo policy for review.",
		"Install the reviewed finite rollback service/timer/boot units and validate their exact bytes; do not arm access mutation during preparation.",
		"Verify the automation user cannot alter the executable, policy, units or receipts; verify unrelated sudo commands and credentials remain unavailable.",
		"Record the exact installed asset digests and identity; preparation does not confer workload admission or authorize a baseline apply.",
	}}
	for i := range p.Files {
		p.Files[i].Digest = digestBytes(p.Files[i].Bytes)
	}
	if err := ValidatePreparation(p); err != nil {
		return Preparation{}, err
	}
	return p, nil
}
func ValidatePreparation(p Preparation) error {
	if len(p.Files) != 7 || !accessName.MatchString(p.Account.Name) || p.Account.Role != "automation" || p.Account.UID <= 0 || p.Account.GID <= 0 || p.Account.Home != "/home/"+p.Account.Name {
		return errAccess
	}
	if p.Account.Name == "root" || len(p.Account.PublicKeys) == 0 || len(p.Account.PublicKeys) != len(p.Account.PublicKeyDigests) {
		return errAccess
	}
	for i, key := range p.Account.PublicKeys {
		if !validPublicKey(key) || digestBytes([]byte(key)) != p.Account.PublicKeyDigests[i] {
			return errAccess
		}
	}
	seen := map[string]bool{}
	for _, f := range p.Files {
		if seen[f.Name] || f.OwnerUID != 0 || f.Digest != digestBytes(f.Bytes) || len(f.Bytes) > 32768 {
			return errAccess
		}
		seen[f.Name] = true
		switch f.Name {
		case "etc/vsk-labs/host-action.json":
			var policy hostaction.Policy
			if f.Mode != 0600 || json.Unmarshal(f.Bytes, &policy) != nil || int64(policy.CallerUID) != p.Account.UID || len(policy.PublicKey) != ed25519.PublicKeySize || policy.KeyID == "" || !digestRE.MatchString(policy.HostIdentityDigest) || policy.ReceiptDirectory != "/var/lib/vsk-labs/host-action" {
				return errAccess
			}
			canonical, _ := json.Marshal(policy)
			if string(canonical) != string(f.Bytes) {
				return errAccess
			}
		case "etc/sudoers.d/vsk-host-action":
			if f.Mode != 0440 {
				return errAccess
			}
			var name string
			if _, err := fmt.Sscanf(string(f.Bytes), "%s ALL=(root) NOPASSWD: /usr/local/bin/vsk-labs host-action-once\n", &name); err != nil || name != p.Account.Name || string(f.Bytes) != fmt.Sprintf("%s ALL=(root) NOPASSWD: /usr/local/bin/vsk-labs host-action-once\n", name) {
				return errAccess
			}
		case "etc/vsk-labs/debian-profile.json":
			if f.Mode != 0600 || generated.ValidateContractJSON(generated.SchemaIDDebianProfileLock, f.Bytes, generated.ContractExact) != nil {
				return errAccess
			}
		case "etc/systemd/system/vsk-access-rollback.service":
			if f.Mode != 0644 || string(f.Bytes) != rollbackService {
				return errAccess
			}
		case "etc/systemd/system/vsk-access-rollback-boot.service":
			if f.Mode != 0644 || string(f.Bytes) != rollbackBootService {
				return errAccess
			}
		case "etc/ssh/sshd_config.d/70-vsk-access.conf":
			if f.Mode != 0644 || string(f.Bytes) != string(initialAutomationSSH(p.Account.Name)) {
				return errAccess
			}
		default:
			if f.Name != "etc/vsk-labs/authorized_keys/"+p.Account.Name || f.Mode != 0644 {
				return errAccess
			}
			keys := append([]string(nil), p.Account.PublicKeys...)
			sort.Strings(keys)
			for i := range keys {
				keys[i] = "restrict " + keys[i]
			}
			if string(f.Bytes) != strings.Join(keys, "\n")+"\n" {
				return errAccess
			}
		}
	}
	return nil
}

func initialAutomationSSH(name string) []byte {
	return []byte("# Initial exact automation account only; other SSH users are unchanged.\nMatch User " + name + "\n    AuthorizedKeysFile /etc/vsk-labs/authorized_keys/%u\n    AuthenticationMethods publickey\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    PermitTTY no\n    AllowTcpForwarding no\n    AllowAgentForwarding no\nMatch all\n")
}
