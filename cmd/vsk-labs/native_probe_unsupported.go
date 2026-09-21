//go:build !linux

package main

import "context"

func runPrivateNativeProbe(_ context.Context, args []string) (bool, int) {
	if len(args) > 0 && (args[0] == "__native-credential-access-probe" || args[0] == "__native-credential-access-probe-child" || args[0] == "__native-credential-policy-check") {
		return true, 2
	}
	return false, 0
}
