// Package failure provides stable, sanitized errors for control-service boundaries.
package failure

import (
	"errors"
	"fmt"
)

type Error struct {
	Code      string
	Target    string
	Retryable bool
}

func New(code, target string, retryable bool) *Error {
	return &Error{Code: code, Target: target, Retryable: retryable}
}

func (err *Error) Error() string {
	return fmt.Sprintf("%s: %s", err.Code, err.Target)
}

func As(err error) (*Error, bool) {
	var stable *Error
	if !errors.As(err, &stable) {
		return nil, false
	}
	return stable, true
}
