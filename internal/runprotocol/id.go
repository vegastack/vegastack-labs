// Package runprotocol contains provider-neutral values shared by the run
// engine and its local API clients.
package runprotocol

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// ID derives the durable run identifier bound to one exact plan and one
// idempotency key. It is an inspection address, not authorization.
func ID(planID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"run", planID, idempotencyKey}, "\x00")))
	return "run-" + hex.EncodeToString(sum[:])[:32]
}
