//go:build linux

package api

import "testing"

func TestNetworkEndpointApprovedAPI(t *testing.T) { testGrantBatchApprovedAPI(t, "network-endpoint") }
