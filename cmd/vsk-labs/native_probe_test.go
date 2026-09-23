package main

import (
	"context"
	"testing"
)

func TestPrivateNativeProbeRejectsExtraArguments(t *testing.T) {
	for _, mode := range []string{"__native-credential-access-probe", "__native-credential-access-probe-child", "__native-credential-policy-check"} {
		handled, code := runPrivateNativeProbe(context.Background(), []string{mode, "extra"})
		if !handled || code != 2 {
			t.Fatalf("%s extra argument passed to public CLI", mode)
		}
	}
	handled, _ := runPrivateNativeProbe(context.Background(), []string{"version"})
	if handled {
		t.Fatal("public command swallowed by private dispatcher")
	}
}
