// Package clientfile reads one explicit inventory candidate without following
// filesystem indirection or exposing rejected paths in errors.
package clientfile

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const MaxInventoryBytes = 4 << 20

type Reader interface {
	Read(context.Context, string, int64) ([]byte, error)
}

type protectedReader struct{}

func NewReader() Reader { return protectedReader{} }

func (protectedReader) Read(ctx context.Context, path string, maximum int64) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, readError(generated.ErrorCodeInterrupted)
	}
	if path == "" || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum < 1 || maximum > MaxInventoryBytes {
		return nil, readError(generated.ErrorCodeInputInvalid)
	}
	content, err := readPlatform(ctx, path, maximum)
	if err != nil {
		return nil, err
	}
	if len(content) == 0 || !utf8.Valid(content) {
		return nil, readError(generated.ErrorCodeInputInvalid)
	}
	return content, nil
}

func readBounded(ctx context.Context, reader io.Reader, maximum int64) ([]byte, error) {
	content := make([]byte, 0, min(int64(64*1024), maximum))
	buffer := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return nil, readError(generated.ErrorCodeInterrupted)
		}
		read, err := reader.Read(buffer)
		if read > 0 {
			if int64(len(content)+read) > maximum {
				return nil, readError(generated.ErrorCodeInputInvalid)
			}
			content = append(content, buffer[:read]...)
		}
		if err == io.EOF {
			return content, nil
		}
		if err != nil {
			return nil, readError(generated.ErrorCodeInputInvalid)
		}
	}
}

func readError(code string) error { return failure.New(code, "inventory-file", false) }
