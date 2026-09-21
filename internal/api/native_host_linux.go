//go:build linux

package api

import (
	"os"
	"regexp"
	"strings"
)

var localMachineIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func localNativeHostID() (string, error) {
	raw, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if !localMachineIDPattern.MatchString(id) {
		return "", apiFailure("PREREQUISITE_BLOCKED", "native-host-identity")
	}
	return id, nil
}
