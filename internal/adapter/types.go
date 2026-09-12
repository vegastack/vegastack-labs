// Package adapter defines the provider-neutral execution boundary. It carries
// only exact plan fields, logical secret references, and sanitized digests.
package adapter

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

var adapterToken = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
var adapterDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type SecretReference struct {
	ID       string
	Consumer string
}

type Operation struct {
	OperationID      string
	OperationType    string
	AdapterID        string
	ExecutorID       string
	TargetID         string
	InputDigest      string
	ArtifactDigest   string
	Idempotent       bool
	SecretReferences []SecretReference
}

type Effect struct {
	Status         string
	ResultDigest   string
	Changed        bool
	EffectObserved bool
}

type Verification struct {
	Verified bool
	Digest   string
}

type Adapter interface {
	Execute(context.Context, Operation) (Effect, error)
	Verify(context.Context, Operation, Effect) (Verification, error)
}

type Error struct {
	code      string
	target    string
	retryable bool
}

func (err *Error) Error() string   { return fmt.Sprintf("%s: %s", err.code, err.target) }
func (err *Error) Code() string    { return err.code }
func (err *Error) Target() string  { return err.target }
func (err *Error) Retryable() bool { return err.retryable }

func Code(err error) string {
	var stable *Error
	if errors.As(err, &stable) {
		return stable.code
	}
	return ""
}

func ValidateOperation(operation Operation) error {
	for _, value := range []string{operation.OperationID, operation.OperationType, operation.AdapterID, operation.ExecutorID, operation.TargetID} {
		if !adapterToken.MatchString(value) {
			return &Error{code: generated.ErrorCodeInputInvalid, target: "adapter-operation"}
		}
	}
	if !adapterDigest.MatchString(operation.InputDigest) || !adapterDigest.MatchString(operation.ArtifactDigest) || strings.ContainsAny(operation.TargetID, "/\\") {
		return &Error{code: generated.ErrorCodeInputInvalid, target: "adapter-operation"}
	}
	seen := map[string]bool{}
	for _, reference := range operation.SecretReferences {
		if !adapterToken.MatchString(reference.ID) || reference.Consumer != operation.AdapterID || seen[reference.ID] {
			return &Error{code: generated.ErrorCodeAuthorizationDenied, target: "adapter-secret-reference"}
		}
		seen[reference.ID] = true
	}
	return nil
}

func ValidateEffect(effect Effect) error {
	if (effect.Status != "succeeded" && effect.Status != "failed" && effect.Status != "partial") || !adapterDigest.MatchString(effect.ResultDigest) {
		return &Error{code: generated.ErrorCodeIntegrityFailure, target: "adapter-effect"}
	}
	if effect.Status == "succeeded" && !effect.EffectObserved {
		return &Error{code: generated.ErrorCodeIntegrityFailure, target: "adapter-effect"}
	}
	return nil
}

func ValidateVerification(verification Verification) error {
	if !adapterDigest.MatchString(verification.Digest) {
		return &Error{code: generated.ErrorCodeIntegrityFailure, target: "adapter-verification"}
	}
	return nil
}
