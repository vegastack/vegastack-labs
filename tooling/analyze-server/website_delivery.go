package main

import (
	"crypto/sha256"
	"fmt"
)

// Issues330–333 grant Unix access only to these complete protected-file paths.
// Neither siblings nor changed source inherit this finite authority.
func reviewedWebsiteDeliveryUnixFile(relative string, content []byte) bool {
	var expected string
	switch relative {
	case "internal/linuxrole/controller_bootstrap_linux.go":
		expected = "b533aff0f1840707ca36c613c05ba44a3d7fb635500e16ce68391305bbeb0e1c"
	case "internal/linuxrole/controller_custody_linux.go":
		expected = "2f6aed418de08a9585a1825393aa8bf32562ac0cf7b1c8af2701ea5de1cdc577"
	case "internal/linuxrole/controller_service_linux.go":
		expected = "13c43d64b7e694230d31a76fe514974bbd29aec58a73682cf8b74570d6a1db09"
	case "internal/linuxrole/control_handoff_linux.go":
		expected = "9b01a24b69cf93d38e29ad4f4035ae9ac79cc2df0e14ffb007d050eb4b0c3565"
	case "internal/server/controller_setup_client_linux.go":
		expected = "471fdee932c9edf90876e9b0db46dc3b5fabb4738789df1af53ba6961c43ad4f"
	default:
		return false
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)) == expected
}
