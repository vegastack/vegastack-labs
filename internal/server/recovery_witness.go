package server

import (
	"context"
	"io"
	"time"

	"github.com/vegastack/vegastack-labs/internal/recovery"
)

// recoveryWitnessCandidate composes one separately supplied witness, current
// server-derived requirement set, authenticated recipient, and one-use receipt.
// It is private so a caller cannot substitute an arbitrary parsed admin root.
type recoveryWitnessCandidate struct {
	Pin       recovery.PinnedWitness
	Expected  recovery.WitnessBinding
	Signed    recovery.SignedWitness
	Required  []recovery.BoundaryRequirement
	Qualified recovery.QualifiedAdapters
	Envelope  recovery.ProtectedEnvelope
	Recipient recovery.ProtectedRecipient
	Receipts  recovery.ReceiptStore
}

// VerifySystemRecoveryWitness always loads the admin root from the fixed
// protected OS path. No production operation invokes it until #108 supplies
// current recovery-required authority and server-derived requirements.
func VerifySystemRecoveryWitness(ctx context.Context, expected recovery.WitnessBinding, signed recovery.SignedWitness, required []recovery.BoundaryRequirement, qualified recovery.QualifiedAdapters, envelope recovery.ProtectedEnvelope, recipient recovery.ProtectedRecipient, receipts recovery.ReceiptStore, compare func(io.ReadCloser) error) error {
	pin, err := recovery.LoadSystemWitnessManifest(expected)
	if err != nil {
		return recovery.ErrWitnessUnavailable
	}
	return (recoveryWitnessCandidate{Pin: pin, Expected: expected, Signed: signed, Required: required, Qualified: qualified, Envelope: envelope, Recipient: recipient, Receipts: receipts}).verify(ctx, compare)
}

func (candidate recoveryWitnessCandidate) verify(ctx context.Context, compare func(io.ReadCloser) error) (err error) {
	defer func() {
		if recover() != nil {
			err = recovery.ErrWitnessUnavailable
		}
	}()
	if ctx == nil || ctx.Err() != nil || candidate.Recipient == nil || candidate.Receipts == nil || compare == nil || candidate.Envelope.RecipientKeyID != candidate.Pin.RecipientKeyID || len(candidate.Envelope.Ciphertext) == 0 || candidate.Envelope.ReceiptID != candidate.Expected.ReceiptID {
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
