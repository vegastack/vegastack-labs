package recovery

import (
	"bytes"
	"context"
	"io"
)

// ProtectedEnvelope is an opaque encrypted transport artifact. Its recipient
// key must be authenticated separately from both controllers. This package
// has no production recipient or custodian implementation.
type ProtectedEnvelope struct {
	RecipientKeyID string
	Ciphertext     []byte
	ReceiptID      string
}

// ProtectedRecipient opens one envelope only after independently checking the
// ephemeral replacement recipient and exact recovery binding. The returned
// reader is owned by VerifyCustody; no plaintext is persisted by this seam.
type ProtectedRecipient interface {
	Open(context.Context, ProtectedEnvelope, WitnessBinding) (CustodyStream, error)
}

type CustodyStream struct {
	Reader    io.ReadCloser
	MaxBytes  int64
	ReceiptID string
}

// Consume atomically claims a receipt and challenge before material can be
// compared. Production needs a durable implementation outside restored state;
// the interface and fixture alone do not provide replay protection.
type ReceiptStore interface {
	Consume(context.Context, string, string) error
}

// VerifyCustody is a bounded, single-use stream handoff to a trusted exact
// ciphertext-inode comparator such as #144's VerifyRecoveredDraft. It does not
// verify the recipient transport or grant recovery authority by itself.
func VerifyCustody(ctx context.Context, binding WitnessBinding, stream CustodyStream, receipts ReceiptStore, compare func(io.ReadCloser) error) (err error) {
	var private [4097]byte
	defer func() {
		wipePrivate(private[:])
		if recover() != nil {
			err = ErrWitnessUnavailable
		}
	}()
	if stream.Reader != nil {
		defer stream.Reader.Close()
	}
	if ctx == nil || ctx.Err() != nil || stream.Reader == nil || receipts == nil || compare == nil || !validWitnessToken(binding.ReceiptID) || !validWitnessToken(binding.ChallengeID) || stream.ReceiptID != binding.ReceiptID || stream.MaxBytes < 8 || stream.MaxBytes > 4096 {
		return ErrWitnessUnavailable
	}
	stopClose := context.AfterFunc(ctx, func() { _ = stream.Reader.Close() })
	defer stopClose()
	if receipts.Consume(ctx, binding.ReceiptID, binding.ChallengeID) != nil || ctx.Err() != nil {
		return ErrWitnessUnavailable
	}
	length, readErr := readCustodyBounded(stream.Reader, private[:stream.MaxBytes+1], int(stream.MaxBytes))
	if readErr != nil || ctx.Err() != nil {
		return ErrWitnessUnavailable
	}
	// bytes.Reader retains only a view of our owned array. The comparator
	// must not retain or copy the private bytes after it returns.
	if compare(io.NopCloser(bytes.NewReader(private[:length]))) != nil || ctx.Err() != nil {
		return ErrWitnessUnavailable
	}
	return nil
}

func readCustodyBounded(reader io.Reader, owned []byte, maximum int) (int, error) {
	count, emptyReads := 0, 0
	for {
		n, err := reader.Read(owned[count:])
		if n < 0 || n > len(owned)-count {
			return count, ErrWitnessUnavailable
		}
		count += n
		if count > maximum {
			return count, ErrWitnessUnavailable
		}
		if err == io.EOF {
			if count < 8 {
				return count, ErrWitnessUnavailable
			}
			return count, nil
		}
		if err != nil {
			return count, ErrWitnessUnavailable
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return count, ErrWitnessUnavailable
			}
		} else {
			emptyReads = 0
		}
	}
}

func wipePrivate(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
