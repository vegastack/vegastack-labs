//go:build !recovery_disposable

package cli

import "github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"

// The ordinary vsk-labs binary has no qualified direct-denial adapter.
func disposableWitnessAdapters() map[string]recoverydenial.Adapter { return nil }
