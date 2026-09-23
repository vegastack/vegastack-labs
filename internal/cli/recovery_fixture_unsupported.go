//go:build recovery_disposable && !linux

package cli

import "github.com/vegastack/vegastack-labs/internal/adapter/recoverydenial"

func disposableWitnessAdapters() map[string]recoverydenial.Adapter { return nil }
