// Package inventoryops composes the closed inventory operation services used
// by the protected API. It has no persistence or provider implementation.
package inventoryops

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/inventory"
	"github.com/vegastack/vegastack-labs/internal/profiles/labsinventory"
)

const FormatTypedJSON = "typed-json"

type DecoderRequest struct {
	Format         string
	SourceRevision string
	CapturedAt     time.Time
	Content        []byte
}

type DecoderRegistry interface {
	Decode(context.Context, DecoderRequest) (inventory.DecodedCandidate, error)
}

type decoderRegistry struct{}

func NewDecoderRegistry() DecoderRegistry { return decoderRegistry{} }

func (decoderRegistry) Decode(ctx context.Context, request DecoderRequest) (inventory.DecodedCandidate, error) {
	_, offset := request.CapturedAt.Zone()
	if ctx.Err() != nil {
		return inventory.DecodedCandidate{}, failure.New(generated.ErrorCodeInterrupted, "inventory-candidate", false)
	}
	if strings.TrimSpace(request.SourceRevision) == "" || len(request.SourceRevision) > inventory.MaxTokenBytes || !utf8.ValidString(request.SourceRevision) ||
		request.CapturedAt.IsZero() || offset != 0 || len(request.Content) == 0 || len(request.Content) > inventory.MaxInputBytes || !utf8.Valid(request.Content) {
		return inventory.DecodedCandidate{}, failure.New(generated.ErrorCodeInputInvalid, "inventory-candidate", false)
	}
	content := bytes.Clone(request.Content)
	var decoded inventory.DecodedCandidate
	var err error
	switch request.Format {
	case FormatTypedJSON:
		decoded, err = (inventory.JSONDecoder{}).Decode(ctx, bytes.NewReader(content))
	case labsinventory.Format:
		var decoder *labsinventory.Decoder
		decoder, err = labsinventory.NewDecoder(labsinventory.Config{SourceRevision: request.SourceRevision, CapturedAt: request.CapturedAt})
		if err == nil {
			decoded, err = decoder.Decode(ctx, bytes.NewReader(content))
		}
	default:
		return inventory.DecodedCandidate{}, failure.New(generated.ErrorCodeInputInvalid, "inventory-format", false)
	}
	if err != nil {
		return inventory.DecodedCandidate{}, sanitizeDecodeError(err)
	}
	if decoded.Candidate.Source.SourceRevision != request.SourceRevision || !decoded.Candidate.Source.CapturedAt.Equal(request.CapturedAt) {
		return inventory.DecodedCandidate{}, failure.New(generated.ErrorCodeInputInvalid, "inventory-provenance", false)
	}
	return decoded, nil
}

func sanitizeDecodeError(err error) error {
	var inventoryError *inventory.Error
	if errors.As(err, &inventoryError) {
		switch inventoryError.Code {
		case generated.ErrorCodeInputInvalid, generated.ErrorCodeSchemaUnsupported, generated.ErrorCodeInterrupted:
			return failure.New(inventoryError.Code, "inventory-candidate", false)
		}
	}
	var csvError *labsinventory.DecodeError
	if errors.As(err, &csvError) && csvError.Code == labsinventory.ErrorInterrupted {
		return failure.New(generated.ErrorCodeInterrupted, "inventory-candidate", false)
	}
	return failure.New(generated.ErrorCodeInputInvalid, "inventory-candidate", false)
}
