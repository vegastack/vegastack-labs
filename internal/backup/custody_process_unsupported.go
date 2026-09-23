//go:build !linux

package backup

import (
	"context"
	"errors"
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
	Journal    CustodyJournal
	Clock      func() time.Time
}

type CustodyClient interface {
	RepositoryURL() string
	Inventory(context.Context) ([]ExpectedObject, error)
	InventoryExpected(context.Context, []ExpectedObject) ([]ExpectedObject, error)
	Capacity(context.Context) (uint64, error)
	RunRestic(context.Context, ResticRequest, *credentialref.Value) (ResticResult, error)
	ResticObservation() ResticObservation
	Close(context.Context) error
}

func (CustodyLauncher) Start(context.Context, CustodySession) (CustodyClient, error) {
	return nil, errors.New("repository custody requires Linux")
}
func RunCustodyChild(string) error      { return errors.New("repository custody requires Linux") }
func RunCustodySupervisor(string) error { return errors.New("repository custody requires Linux") }

const CustodySystemdMode = "__backup-custody-supervisor"
