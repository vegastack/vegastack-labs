package nativecredential

import "testing"

func TestLoadedCredentialProtectionAcceptsOnlyServiceOwnedOrSystemdRootFiles(t *testing.T) {
	const service = 988
	for _, test := range []struct {
		name  string
		owner uint32
		mode  uint32
		want  bool
	}{
		{"service-owned 0400", service, 0o100400, true},
		{"service-owned 0600", service, 0o100600, true},
		{"service-owned 0640 gives the group access", service, 0o100640, false},
		{"service-owned 0604 gives others access", service, 0o100604, false},
		{"root-owned 0400", 0, 0o100400, true},
		{"root-owned 0440 as systemd delivers with an ACL", 0, 0o100440, true},
		{"root-owned 0600 is not the systemd layout", 0, 0o100600, false},
		{"root-owned 0444 is readable by everyone", 0, 0o100444, false},
		{"root-owned 0640 adds group bits beyond the systemd layout", 0, 0o100640, false},
		{"root-owned 0460", 0, 0o100460, false},
		{"root-owned 0441 has an execute bit for others", 0, 0o100441, false},
		{"another account's file is refused even if private", 1234, 0o100400, false},
		{"another account's 0440 is refused", 1234, 0o100440, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := loadedCredentialProtected(test.owner, test.mode, service); got != test.want {
				t.Fatalf("protected = %v want %v", got, test.want)
			}
		})
	}
}

func TestLoadedCredentialDirectoryProtectionAcceptsOnlyServiceOwnedOrSystemdRootDirectories(t *testing.T) {
	const service = 988
	for _, test := range []struct {
		name  string
		owner uint32
		mode  uint32
		want  bool
	}{
		{"service-owned 0700", service, 0o040700, true},
		{"service-owned 0500", service, 0o040500, true},
		{"service-owned 0750 gives the group access", service, 0o040750, false},
		{"service-owned 0705 gives others access", service, 0o040705, false},
		{"root-owned 0550 as systemd creates it with an ACL", 0, 0o040550, true},
		{"root-owned 0500", 0, 0o040500, true},
		{"root-owned 0700 is not the systemd layout", 0, 0o040700, false},
		{"root-owned 0555 is readable by everyone", 0, 0o040555, false},
		{"root-owned 0755 is readable and listable by everyone", 0, 0o040755, false},
		{"root-owned 0570 lets the group write", 0, 0o040570, false},
		{"root-owned 0551 lets others traverse", 0, 0o040551, false},
		{"another account's private directory is refused", 1234, 0o040500, false},
		{"another account's 0550 directory is refused", 1234, 0o040550, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := loadedCredentialDirectoryProtected(test.owner, test.mode, service); got != test.want {
				t.Fatalf("protected = %v want %v", got, test.want)
			}
		})
	}
}
