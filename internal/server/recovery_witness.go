package server

import (
	"context"
	"io"
	"time"

	"github.com/vegastack/vegastack-labs/internal/recovery"
)

// RecoveryWitnessCandidate composes one separately supplied witness, current
// server-derived requirement set, authenticated recipient, and one-use receipt.
// No production constructor or registration exists: #108 must establish
// current recovery-required authority before any recover action can use it.
type RecoveryWitnessCandidate struct {
	Pin       recovery.PinnedWitness
	Expected  recovery.WitnessBinding
	Signed    recovery.SignedWitness
	Required  []recovery.BoundaryRequirement
	Qualified recovery.QualifiedAdapters
	Envelope  recovery.ProtectedEnvelope
	Recipient recovery.ProtectedRecipient
	Receipts  recovery.ReceiptStore
}

func (candidate RecoveryWitnessCandidate) Verify(ctx context.Context, compare func(io.ReadCloser) error) (err error) {
	defer func() {
		if recover() != nil {
			err = recovery.ErrWitnessUnavailable
		}
	}()
	if ctx == nil || ctx.Err() != nil || candidate.Recipient == nil || candidate.Receipts == nil || compare == nil || candidate.Envelope.RecipientKeyID == "" || len(candidate.Envelope.Ciphertext) == 0 || candidate.Envelope.ReceiptID != candidate.Expected.ReceiptID {
		return recovery.ErrWitnessUnavailable
	}
	if err := recovery.VerifyWitnessBundle(ctx, candidate.Pin, candidate.Expected, candidate.Signed, candidate.Required, candidate.Qualified, time.Now().UTC()); err != nil {
		return recovery.ErrWitnessUnavailable
	}
	stream, err := candidate.Recipient.Open(ctx, candidate.Envelope, candidate.Expected)
	if err != nil {
		if stream.Reader != nil {
			_ = stream.Reader.Close()
		}
		return recovery.ErrWitnessUnavailable
	}
	return recovery.VerifyCustody(ctx, candidate.Expected, stream, candidate.Receipts, compare)
}
