package strictjson

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestScanRejectsDuplicateTrailingAndExcessDepth(t *testing.T) {
	t.Parallel()
	for _, input := range []string{`{"a":1,"a":2}`, `{"a":1}{}`, strings.Repeat(`[`, 34) + strings.Repeat(`]`, 34)} {
		if err := Scan(context.Background(), []byte(input), Limits{MaxDepth: 32}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Scan(%q) = %v, want ErrInvalid", input, err)
		}
	}
}

func TestScanHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Scan(ctx, []byte(`{"a":1}`), Limits{MaxDepth: 32}); !errors.Is(err, ErrInterrupted) {
		t.Fatalf("cancelled scan error = %v", err)
	}
}
