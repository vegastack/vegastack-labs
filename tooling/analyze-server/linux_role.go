package main

import (
	"crypto/sha256"
	"fmt"
)

// #230 restores the durable run.created actor joined to an active principal.
// This complete source seal permits only the reviewed setter; siblings or edits
// cannot acquire authority to inject a verified principal into a context.
func reviewedLinuxRoleActorFile(relative string, content []byte) bool {
	if relative != "internal/store/host_role_reservation.go" {
		return false
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)) == "30e82a459ed8de9dc3ef404d148ed15203a58200b36c48ec243a98ddec620697"
}

// #230's finite Linux role files use protected descriptors, a writer lock and
// process namespaces. No package-wide or filename-suffix Unix scope is granted.
func reviewedLinuxRoleUnixFile(relative string, content []byte) bool {
	var expected string
	switch relative {
	case "internal/linuxrole/boot_linux.go":
		expected = "bb03247f69a2900c4bdd63cabee5047fc5440e28a46ec31cc1bf75f916a6cf2a"
	case "internal/linuxrole/control_handoff_linux.go":
		expected = "45e25155e5d8792673c45d07961ca5a1dbee71e9a924a9fa00eac61d02b96721"
	case "internal/linuxrole/isolation_linux.go":
		expected = "995541e077e8a62f3946fc5235a214718fc944af4901d88acd113217e5d32cfc"
	case "internal/linuxrole/runtime_linux.go":
		expected = "e999a9dfd74bb0b5723efcb7cde161567f9ac474f46f3c96c8a4099debf487fb"
	default:
		return false
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)) == expected
}
