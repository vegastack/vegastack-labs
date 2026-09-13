//go:build windows

package clientprofile

import (
	"testing"

	"golang.org/x/sys/windows"
)

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
		"private current owner":                   {current, []windowsAccess{{current, windows.GENERIC_ALL}, {system, windows.GENERIC_ALL}}, false, true},
		"private wrong owner":                     {users, []windowsAccess{{current, windows.GENERIC_ALL}}, false, false},
		"private other read":                      {current, []windowsAccess{{current, windows.GENERIC_ALL}, {users, windows.GENERIC_READ}}, false, false},
		"executable system owner and public read": {system, []windowsAccess{{system, windows.GENERIC_ALL}, {users, windows.GENERIC_READ | windows.GENERIC_EXECUTE}}, true, true},
		"executable public write":                 {system, []windowsAccess{{system, windows.GENERIC_ALL}, {users, windows.GENERIC_WRITE}}, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := windowsACLTrusted(test.owner, current, test.entries, test.executable); got != test.want {
				t.Fatalf("windowsACLTrusted() = %t, want %t", got, test.want)
			}
		})
	}
}
