//go:build linux

package server

import "os"

func currentServiceOwnerUID() (uint32, error) { return uint32(os.Geteuid()), nil }
