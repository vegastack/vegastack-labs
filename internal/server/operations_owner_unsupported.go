//go:build !linux

package server

import "errors"

func currentServiceOwnerUID() (uint32, error) { return 0, errors.New("unsupported") }
