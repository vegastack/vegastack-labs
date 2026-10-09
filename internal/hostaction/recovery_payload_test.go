package hostaction

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestRecoveryPayloadSegmentBoundariesAndFailures(t *testing.T) {
	candidate := []byte("candidate\x00database\xff")
	journal := []byte("journal")
	wire := bytes.NewReader(append(append([]byte{}, candidate...), journal...))
	var first, second bytes.Buffer
	if err := CopyRecoveryPayload(context.Background(), &first, wire, int64(len(candidate)), MaximumRecoveryCandidateBytes, BytesDigest(candidate)); err != nil {
		t.Fatal(err)
	}
	if wire.Len() != len(journal) {
		t.Fatal("candidate consumed journal bytes")
	}
	if err := CopyRecoveryPayload(context.Background(), &second, wire, int64(len(journal)), MaximumRecoveryJournalBytes, BytesDigest(journal)); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadByte(); err != io.EOF || !bytes.Equal(first.Bytes(), candidate) || !bytes.Equal(second.Bytes(), journal) {
		t.Fatal("stream changed")
	}
	for _, tc := range []struct {
		name            string
		raw             []byte
		length, maximum int64
		digest          string
	}{
		{"truncated", candidate[:len(candidate)-1], int64(len(candidate)), MaximumRecoveryCandidateBytes, BytesDigest(candidate)},
		{"wrong-hash", candidate, int64(len(candidate)), MaximumRecoveryCandidateBytes, BytesDigest(journal)},
		{"oversize", candidate, int64(len(candidate)), 1, BytesDigest(candidate)},
		{"zero", candidate, 0, MaximumRecoveryCandidateBytes, BytesDigest(candidate)},
		{"unbounded", candidate, 1, MaximumRecoveryCandidateBytes + 1, BytesDigest(candidate)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if CopyRecoveryPayload(context.Background(), io.Discard, bytes.NewReader(tc.raw), tc.length, tc.maximum, tc.digest) == nil {
				t.Fatal("invalid payload accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var untouched bytes.Buffer
	if CopyRecoveryPayload(ctx, &untouched, bytes.NewReader(candidate), int64(len(candidate)), MaximumRecoveryCandidateBytes, BytesDigest(candidate)) == nil || untouched.Len() != 0 {
		t.Fatal("canceled transfer wrote data")
	}
}
