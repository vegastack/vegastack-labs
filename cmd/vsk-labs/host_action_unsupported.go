//go:build !linux

package main

import "context"

func runHostActionOnce(_ context.Context, args []string) (bool, int) {
	if len(args) > 0 && args[0] == "host-action-once" {
		return true, 1
	}
	return false, 0
}
