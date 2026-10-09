//go:build !linux && !darwin

package hostaction

import "github.com/vegastack/vegastack-labs/internal/generated"

type Receipts struct{}

func OpenReceipts(string, uint32) (*Receipts, error)              { return nil, blocked() }
func (*Receipts) Claim(string) error                              { return blocked() }
func (*Receipts) Finish(string, generated.HostActionResult) error { return blocked() }
func (*Receipts) Close() error                                    { return nil }
func LoadPolicy(string) (Policy, error)                           { return Policy{}, blocked() }
