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
		expected = "eefa2b5d3624c311588768e8027e2bece31446405afa40f3b789f11813a4cd31"
	case "internal/linuxrole/controller_custody_linux.go":
		expected = "66be9bf70bbeed1bc4968c381581b7ae39c905f0f17d04a22e8f66847a988880"
	case "internal/linuxrole/controller_service_linux.go":
		expected = "5e6acfd3e1cdfededc73e276c9a4dfb1042747881e9dc447878b6483590f91d1"
	case "internal/linuxrole/control_handoff_linux.go":
		expected = "9b01a24b69cf93d38e29ad4f4035ae9ac79cc2df0e14ffb007d050eb4b0c3565"
	case "internal/server/controller_setup_client_linux.go":
		expected = "471fdee932c9edf90876e9b0db46dc3b5fabb4738789df1af53ba6961c43ad4f"
	default:
		return false
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)) == expected
}
