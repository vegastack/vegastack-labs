package recovery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type testReceipts struct {
	mu   sync.Mutex
	used map[string]bool
}

func (r *testReceipts) Consume(_ context.Context, receiptID, challengeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used == nil {
		r.used = map[string]bool{}
	}
	key := receiptID + "/" + challengeID
	if r.used[key] {
		return errors.New("used")
	}
	r.used[key] = true
	return nil
}

type trackedCustody struct {
	io.Reader
	closed bool
}

func (r *trackedCustody) Close() error { r.closed = true; return nil }

func TestCustodyOneUseBoundedAndRedacted(t *testing.T) {
	canary := []byte("synthetic-independent-material")
	binding := WitnessBinding{ReceiptID: "receipt-1", ChallengeID: "challenge-1"}
	receipts := &testReceipts{}
	reader := &trackedCustody{Reader: bytes.NewReader(canary)}
	stream := CustodyStream{Reader: reader, MaxBytes: 4096, ReceiptID: binding.ReceiptID}
	compare := func(r io.ReadCloser) error {
		defer r.Close()
		value, err := io.ReadAll(r)
		if err != nil || !bytes.Equal(value, canary) {
			return errors.New("mismatch")
		}
		return nil
	}
	if err := VerifyCustody(context.Background(), binding, stream, receipts, compare); err != nil {
		t.Fatal(err)
	}
	if !reader.closed {
		t.Fatal("custody stream not closed")
	}
	replay := &trackedCustody{Reader: bytes.NewReader(canary)}
	if err := VerifyCustody(context.Background(), binding, CustodyStream{Reader: replay, MaxBytes: 4096, ReceiptID: binding.ReceiptID}, receipts, compare); err == nil || !replay.closed {
		t.Fatal("replayed receipt accepted or stream left open")
	}
	for name, change := range map[string]func(*CustodyStream){
		"wrong-receipt":  func(s *CustodyStream) { s.ReceiptID = "other" },
		"overflow":       func(s *CustodyStream) { s.MaxBytes = 8 },
		"missing-reader": func(s *CustodyStream) { s.Reader = nil },
	} {
		t.Run(name, func(t *testing.T) {
			s := CustodyStream{Reader: &trackedCustody{Reader: bytes.NewReader(canary)}, MaxBytes: 4096, ReceiptID: binding.ReceiptID}
			change(&s)
			err := VerifyCustody(context.Background(), binding, s, &testReceipts{}, compare)
			if err == nil || strings.Contains(err.Error(), string(canary)) {
				t.Fatal("invalid custody accepted or leaked")
			}
		})
	}
	failed := &trackedCustody{Reader: bytes.NewReader(canary)}
	err := VerifyCustody(context.Background(), binding, CustodyStream{Reader: failed, MaxBytes: 4096, ReceiptID: binding.ReceiptID}, &testReceipts{}, func(io.ReadCloser) error { return errors.New(string(canary)) })
	if err == nil || strings.Contains(err.Error(), string(canary)) || !failed.closed {
		t.Fatal("compare failure leaked or stream open")
	}
	panicked := &trackedCustody{Reader: bytes.NewReader(canary)}
	err = VerifyCustody(context.Background(), binding, CustodyStream{Reader: panicked, MaxBytes: 4096, ReceiptID: binding.ReceiptID}, &testReceipts{}, func(io.ReadCloser) error { panic(string(canary)) })
	if err == nil || strings.Contains(err.Error(), string(canary)) || !panicked.closed {
		t.Fatal("panic leaked or stream open")
	}
}

type cancelCustodyReader struct {
	started, closed chan struct{}
	once            sync.Once
}

func (r *cancelCustodyReader) Read([]byte) (int, error) {
	close(r.started)
	<-r.closed
	return 0, io.ErrClosedPipe
}
func (r *cancelCustodyReader) Close() error { r.once.Do(func() { close(r.closed) }); return nil }

func TestCustodyCancellationClosesBlockedStream(t *testing.T) {
	binding := WitnessBinding{ReceiptID: "receipt-1", ChallengeID: "challenge-1"}
	reader := &cancelCustodyReader{started: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- VerifyCustody(ctx, binding, CustodyStream{Reader: reader, MaxBytes: 4096, ReceiptID: binding.ReceiptID}, &testReceipts{}, func(io.ReadCloser) error { return nil })
	}()
	select {
	case <-reader.started:
	case <-time.After(time.Second):
		t.Fatal("read did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled custody accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not close stream")
	}
}
