//go:build windows

package clientprofile

import (
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsKnownHostsPathUsesOneOpenSSHSafeForwardSlashValue(t *testing.T) {
	path := `C:\Users\operator\known-hosts`
	if !validKnownHostsPath(path) {
		t.Fatalf("validKnownHostsPath(%q) = false", path)
	}
	arguments := constrainedSSHArguments(path, "operator@control-plane")
	want := []string{"-o", "UserKnownHostsFile=C:/Users/operator/known-hosts", "-o", "VerifyHostKeyDNS=no", "operator@control-plane"}
	if !reflect.DeepEqual(arguments[len(arguments)-5:], want) {
		t.Fatalf("known-hosts tail = %#v, want %#v", arguments[len(arguments)-5:], want)
	}
}

func TestWindowsFileMetadataTrustRejectsReparseDirectoriesAndHardlinks(t *testing.T) {
	for name, test := range map[string]struct {
		attributes uint32
		links      uint32
		want       bool
	}{
		"regular":   {windows.FILE_ATTRIBUTE_NORMAL, 1, true},
		"reparse":   {windows.FILE_ATTRIBUTE_REPARSE_POINT, 1, false},
		"directory": {windows.FILE_ATTRIBUTE_DIRECTORY, 1, false},
		"hardlink":  {windows.FILE_ATTRIBUTE_NORMAL, 2, false},
		"no links":  {windows.FILE_ATTRIBUTE_NORMAL, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := windowsFileMetadataTrusted(test.attributes, test.links); got != test.want {
				t.Fatalf("windowsFileMetadataTrusted() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestWindowsDirectoryMetadataTrustRejectsReparseAndNonDirectories(t *testing.T) {
	for name, test := range map[string]struct {
		attributes uint32
		links      uint32
		want       bool
	}{
		"directory":        {windows.FILE_ATTRIBUTE_DIRECTORY, 1, true},
		"linked directory": {windows.FILE_ATTRIBUTE_DIRECTORY, 2, true},
		"reparse":          {windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT, 1, false},
		"regular":          {windows.FILE_ATTRIBUTE_NORMAL, 1, false},
		"no links":         {windows.FILE_ATTRIBUTE_DIRECTORY, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := windowsPathMetadataTrusted(test.attributes, test.links, windowsDirectory); got != test.want {
				t.Fatalf("windowsPathMetadataTrusted() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestWindowsACLTrustRequiresOwnerAndRejectsUnsafeGrants(t *testing.T) {
	current := "S-1-5-21-current"
	system := "S-1-5-18"
	users := "S-1-5-32-545"
	for name, test := range map[string]struct {
		owner      string
		entries    []windowsAccess
		executable bool
		want       bool
	}{
		"private current owner":                   {current, []windowsAccess{{current, windows.GENERIC_ALL, 0}, {system, windows.GENERIC_ALL, 0}}, false, true},
		"private wrong owner":                     {users, []windowsAccess{{current, windows.GENERIC_ALL, 0}}, false, false},
		"private other read":                      {current, []windowsAccess{{current, windows.GENERIC_ALL, 0}, {users, windows.GENERIC_READ, 0}}, false, false},
		"executable system owner and public read": {system, []windowsAccess{{system, windows.GENERIC_ALL, 0}, {users, windows.GENERIC_READ | windows.GENERIC_EXECUTE, 0}}, true, true},
		"executable public write":                 {system, []windowsAccess{{system, windows.GENERIC_ALL, 0}, {users, windows.GENERIC_WRITE, 0}}, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := windowsACLTrusted(test.owner, current, test.entries, test.executable); got != test.want {
				t.Fatalf("windowsACLTrusted() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestWindowsDirectoryACLTrustRejectsReplaceableAncestors(t *testing.T) {
	current := "S-1-5-21-current"
	system := "S-1-5-18"
	users := "S-1-5-32-545"
	for name, test := range map[string]struct {
		owner   string
		entries []windowsAccess
		want    bool
	}{
		"private current owner":        {current, []windowsAccess{{current, windows.GENERIC_ALL, 0}, {system, windows.GENERIC_ALL, 0}}, true},
		"system owner public traverse": {system, []windowsAccess{{system, windows.GENERIC_ALL, 0}, {users, windows.GENERIC_READ | windows.GENERIC_EXECUTE, 0}}, true},
		"untrusted owner":              {users, []windowsAccess{{users, windows.GENERIC_ALL, 0}}, false},
		"public add file":              {system, []windowsAccess{{system, windows.GENERIC_ALL, 0}, {users, windows.FILE_WRITE_DATA, 0}}, false},
		"public add directory":         {system, []windowsAccess{{system, windows.GENERIC_ALL, 0}, {users, windows.FILE_APPEND_DATA, 0}}, false},
		"public delete child":          {system, []windowsAccess{{system, windows.GENERIC_ALL, 0}, {users, windowsDirectoryDeleteChild, 0}}, false},
		"public change ACL":            {system, []windowsAccess{{system, windows.GENERIC_ALL, 0}, {users, windows.WRITE_DAC, 0}}, false},
		"inherit-only public write":    {system, []windowsAccess{{system, windows.GENERIC_ALL, 0}, {users, windows.GENERIC_ALL, windows.INHERIT_ONLY_ACE}}, true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := windowsDirectoryACLTrusted(test.owner, current, test.entries); got != test.want {
				t.Fatalf("windowsDirectoryACLTrusted() = %t, want %t", got, test.want)
			}
		})
	}
}
