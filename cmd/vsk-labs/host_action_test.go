package main

import (
	"context"
	"testing"
)

func TestHostActionModeRejectsArbitraryArguments(t *testing.T) {
	handled, code := runHostActionOnce(context.Background(), []string{"host-action-once", "--command", "id"})
	if !handled || code == 0 {
		t.Fatal("accepted arbitrary privileged command")
	}
}
