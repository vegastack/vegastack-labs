//go:build !linux

package main

import "context"

func runControllerSetupMode(_ context.Context, args []string) (bool, int) {
	if len(args) > 0 && (args[0] == controllerSetupMode || args[0] == controllerSetupAPIMode || args[0] == controllerPilotHealthMode || args[0] == controllerSetupRecoveryMode) {
		return true, 1
	}
	return false, 0
}
