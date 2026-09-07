// Package credentialref defines the metadata-only boundary used to verify a
// logical credential reference without exposing credential material.
package credentialref

import (
	"context"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// State describes whether the referenced credential may currently be used.
type State string

const (
	Current     State = "current"
	Unavailable State = "unavailable"
	Stale       State = "stale"
	Revoked     State = "revoked"
)

// Reference identifies a credential logically and binds it to one consumer.
// It intentionally contains no credential material.
type Reference struct {
	ID       string
	Consumer string
}

// Metadata is the complete information exposed by credential inspection.
// MaterialVersion is an opaque version identifier, not secret material.
type Metadata struct {
	Reference       Reference
	MaterialVersion string
	State           State
}

// Inspector retrieves metadata for a logical credential reference.
type Inspector interface {
	Inspect(context.Context, Reference) (Metadata, error)
}

// Error reports a stable error code and a non-sensitive logical target.
type Error struct {
	Code   string
	Target string
}

func (err *Error) Error() string {
	return fmt.Sprintf("%s: %s", err.Code, err.Target)
}

// Verify confirms that reference is valid, authorized for requestedConsumer,
// and currently backed by matching inspector metadata.
func Verify(ctx context.Context, inspector Inspector, reference Reference, requestedConsumer string) (Metadata, error) {
	if ctx == nil {
		return Metadata{}, newError(generated.ErrorCodeInputInvalid, "context")
	}
	if err := ctx.Err(); err != nil {
		return Metadata{}, newError(generated.ErrorCodeInterrupted, "credential-reference")
	}
	if !validIdentifier(reference.ID) {
		return Metadata{}, newError(generated.ErrorCodeInputInvalid, "credential-reference")
	}
	if !validIdentifier(reference.Consumer) || !validIdentifier(requestedConsumer) {
		return Metadata{}, newError(generated.ErrorCodeInputInvalid, "credential-consumer")
	}
	if reference.Consumer != requestedConsumer {
		return Metadata{}, newError(generated.ErrorCodeAuthorizationDenied, "credential-consumer")
	}
	if inspector == nil {
		return Metadata{}, newError(generated.ErrorCodeInputInvalid, "credential-inspector")
	}

	metadata, inspectErr := inspector.Inspect(ctx, reference)
	if ctx.Err() != nil {
		return Metadata{}, newError(generated.ErrorCodeInterrupted, "credential-reference")
	}
	if inspectErr != nil {
		return Metadata{}, newError(generated.ErrorCodeDependencyUnavailable, "credential-inspector")
	}
	if metadata.Reference != reference || !validIdentifier(metadata.MaterialVersion) {
		return Metadata{}, newError(generated.ErrorCodeDependencyUnavailable, "credential-metadata")
	}

	switch metadata.State {
	case Current:
		return metadata, nil
	case Unavailable, Stale, Revoked:
		return Metadata{}, newError(generated.ErrorCodeDependencyUnavailable, "credential-state")
	default:
		return Metadata{}, newError(generated.ErrorCodeDependencyUnavailable, "credential-metadata")
	}
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 255 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func newError(code, target string) *Error {
	return &Error{Code: code, Target: target}
}
