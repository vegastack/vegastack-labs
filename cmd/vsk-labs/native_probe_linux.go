//go:build linux

package main

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"os"
)

func runPrivateNativeProbe(ctx context.Context, args []string) (bool, int) {
	if len(args) == 0 {
		return false, 0
	}
	switch args[0] {
	case "__native-credential-policy-check":
		if len(args) != 1 {
			return true, 2
		}
		return true, nativecredential.RunPolicyCheckMode(ctx, os.Stdin)
	case "__native-credential-access-probe":
		if len(args) != 1 {
			return true, 2
		}
		return true, nativecredential.RunAccessProbeMode(ctx, os.Stdin, os.Stdout)
	case "__native-credential-access-probe-child":
		if len(args) != 1 {
			return true, 2
		}
		return true, nativecredential.RunAccessProbeChildMode(os.Stdin, os.Stdout)
	default:
		return false, 0
	}
}
