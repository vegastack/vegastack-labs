// Package strictjson validates one unambiguous JSON value without retaining it.
package strictjson

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
)

var (
	ErrInvalid     = errors.New("invalid strict JSON")
	ErrInterrupted = errors.New("strict JSON scan interrupted")
)

type Limits struct{ MaxDepth int }

func Scan(ctx context.Context, raw []byte, limits Limits) error {
	if limits.MaxDepth < 1 {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanValue(ctx, decoder, 0, limits.MaxDepth); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if ctx.Err() != nil {
			return ErrInterrupted
		}
		return ErrInvalid
	}
	return nil
}

func scanValue(ctx context.Context, decoder *json.Decoder, depth, maxDepth int) error {
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	if depth > maxDepth {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			if ctx.Err() != nil {
				return ErrInterrupted
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return ErrInvalid
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalid
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalid
			}
			seen[key] = struct{}{}
			if err := scanValue(ctx, decoder, depth+1, maxDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for decoder.More() {
			if err := scanValue(ctx, decoder, depth+1, maxDepth); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
