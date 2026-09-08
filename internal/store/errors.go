package store

import (
	"errors"
	"fmt"
)

// StoreError exposes only stable, generated-contract information. cause is
// retained for internal classification and never rendered or serialized.
type StoreError struct {
	code      string
	target    string
	retryable bool
	cause     error
}

func newStoreError(code, target string, retryable bool, cause error) *StoreError {
	return &StoreError{code: code, target: target, retryable: retryable, cause: cause}
}

func (err *StoreError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s (retryable=%t)", err.code, err.target, err.retryable)
}

func (err *StoreError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *StoreError) Target() string {
	if err == nil {
		return ""
	}
	return err.target
}

func (err *StoreError) Retryable() bool {
	return err != nil && err.retryable
}

func Code(err error) string {
	var storeError *StoreError
	if errors.As(err, &storeError) {
		return storeError.code
	}
	return ""
}
