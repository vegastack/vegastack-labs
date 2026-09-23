//go:build !linux

package backup

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type CustodyJournal interface {
	BeginCustody(context.Context, CustodySession) error
	FinishCustody(context.Context, CustodySession, string) error
}

type CustodyLauncher struct {
	PolicyPath string
	Writer     LeaseVerifier
	Reader     ReadLeaseVerifier
	Retention  RetentionLeaseVerifier
	Mutations  RetainedMutationJournal
	Journal    CustodyJournal
	Clock      func() time.Time
}

type CustodyClient interface {
	RepositoryURL() string
	Inventory(context.Context) ([]ExpectedObject, error)
	InventoryExpected(context.Context, []ExpectedObject) ([]ExpectedObject, error)
	Capacity(context.Context) (uint64, error)
	CapacitySnapshot(context.Context) (RepositoryCapacity, error)
	RunRestic(context.Context, ResticRequest, *credentialref.Value) (ResticResult, error)
	RunOffsiteRestic(context.Context, OffsiteResticRequest, *credentialref.Value, []byte) (OffsiteResticResult, error)
	ResticObservation() ResticObservation
	Close(context.Context) error
}

type RepositoryCapacity struct {
	TotalBytes       uint64 `json:"totalBytes"`
	AvailableBytes   uint64 `json:"availableBytes"`
	QuarantinedBytes uint64 `json:"quarantinedBytes"`
}

func (CustodyLauncher) Start(context.Context, CustodySession) (CustodyClient, error) {
	return nil, errors.New("repository custody requires Linux")
}
func RunCustodyChild(string) error                         { return errors.New("repository custody requires Linux") }
func RunCustodySupervisor(string) error                    { return errors.New("repository custody requires Linux") }
func RunCustodyPolicyCheck(context.Context, io.Reader) int { return 2 }

const (
	CustodySystemdMode     = "__backup-custody-supervisor"
	CustodyPolicyCheckMode = "__backup-custody-policy-check"
)
