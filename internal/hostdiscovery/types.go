// Package hostdiscovery owns untrusted observations, never admission.
package hostdiscovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const Consumer = "core.host-discovery"
const Purpose = "host.discovery.read"
const CollectorID = "debian-discovery-v1"
const CollectorVersion = "1.0.0"
const MaximumDuration = 30 * time.Second
const Freshness = 15 * time.Minute

type Facts []generated.HostDiscoveryFact
type Collection struct {
	Facts   Facts
	Missing []string
}
type Target struct {
	Binding       generated.HostDiscoveryTarget
	Digest        string
	StateRevision int64
	GrantRevision int64
}
type Attempt struct {
	ID          string
	Target      Target
	Request     generated.HostDiscoveryRequest
	PrincipalID string
	Deadline    time.Time
	Observation *generated.HostObservation
}
type BeginRequest struct {
	Request     generated.HostDiscoveryRequest
	Attribution audit.Attribution
}
type CompleteRequest struct {
	Attempt     Attempt
	Collection  Collection
	Attribution audit.Attribution
}
type Repository interface {
	Begin(context.Context, BeginRequest) (Attempt, error)
	Complete(context.Context, CompleteRequest) (generated.HostObservation, error)
	Get(context.Context, string) (generated.HostObservation, error)
	Fail(context.Context, Attempt, string, audit.Attribution) error
}
type Collector interface {
	Collect(context.Context, Target) (Collection, error)
}

func Digest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func Error(code string) error { return failure.New(code, "host-discovery", false) }
func Fact(name, value, operation string) generated.HostDiscoveryFact {
	return generated.HostDiscoveryFact{Schema: generated.SchemaIDHostDiscoveryFact, SchemaVersion: "1.0.0", Name: name, Value: value, Operation: operation}
}
