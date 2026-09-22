//go:build !linux && !darwin

package recovery

import "context"

type unavailableReceiptStore struct{}

func (unavailableReceiptStore) Consume(_ context.Context, _, _ string) error {
	return ErrWitnessUnavailable
}
func NewSystemReceiptStore() ReceiptStore { return unavailableReceiptStore{} }
