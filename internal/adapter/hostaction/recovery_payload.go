package hostaction

import (
	"context"
	"encoding/json"
	"io"

	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
)

// RecoveryPayloadSource opens only the server-owned candidate selected by the
// exact signed action. It is invoked after a fresh authorization, never from a
// caller-provided path or standalone upload request.
type RecoveryPayloadSource func(context.Context, generated.HostActionBundle) (*RecoveryPayload, error)
type RecoveryPayload struct {
	Descriptor         generated.ControlRecoveryReceiveInput
	Candidate, Journal io.ReadCloser
}

func (p *RecoveryPayload) Close() {
	if p == nil {
		return
	}
	if p.Candidate != nil {
		_ = p.Candidate.Close()
	}
	if p.Journal != nil {
		_ = p.Journal.Close()
	}
}

// SetRecoveryPayloadSource configures the finite optional source once during
// server composition, before the adapter is published to the execution engine.
func (a *Adapter) SetRecoveryPayloadSource(source RecoveryPayloadSource) error {
	if a == nil || source == nil || a.recoveryPayload != nil {
		return denied()
	}
	a.recoveryPayload = source
	return nil
}
func (a *Adapter) writeRecoveryPayload(ctx context.Context, dst io.Writer, b generated.HostActionBundle) error {
	if b.ActionID != protocol.RecoveryReceiveAction || a.recoveryPayload == nil || ctx.Err() != nil {
		return denied()
	}
	raw := []byte(b.ActionInput)
	var input generated.ControlRecoveryReceiveInput
	if generated.ValidateContractJSON(generated.SchemaIDControlRecoveryReceiveInput, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &input) != nil || protocol.BytesDigest(raw) != b.ActionInputDigest {
		return denied()
	}
	payload, err := a.recoveryPayload(ctx, b)
	if payload != nil {
		defer payload.Close()
	}
	if err != nil || payload == nil || payload.Candidate == nil || payload.Journal == nil || protocol.Digest(payload.Descriptor) != protocol.Digest(input) {
		return denied()
	}
	// Cancellation interrupts server-owned file/pipe sources as well as SSH.
	stop := context.AfterFunc(ctx, payload.Close)
	defer stop()
	if protocol.CopyRecoveryPayload(ctx, dst, payload.Candidate, input.CandidateBytes, protocol.MaximumRecoveryCandidateBytes, input.CandidateBytesDigest) != nil {
		return denied()
	}
	var trailing [1]byte
	if n, err := payload.Candidate.Read(trailing[:]); n != 0 || err != io.EOF {
		return denied()
	}
	if protocol.CopyRecoveryPayload(ctx, dst, payload.Journal, input.JournalBytes, protocol.MaximumRecoveryJournalBytes, input.JournalDigest) != nil {
		return denied()
	}
	if n, err := payload.Journal.Read(trailing[:]); n != 0 || err != io.EOF {
		return denied()
	}
	return nil
}

// RecoveryReceiveFinalizer persists the source-authority suspension only after
// the authenticated receiver returned a verified successful result. A failed
// finalizer leaves the effect explicitly observed and never claims completion.
type RecoveryReceiveFinalizer func(context.Context, generated.HostActionBundle, generated.ControlRecoveryReceiveInput, generated.HostActionResult) error

func (a *Adapter) SetRecoveryReceiveFinalizer(finalizer RecoveryReceiveFinalizer) error {
	if a == nil || finalizer == nil || a.recoveryFinalizer != nil {
		return denied()
	}
	a.recoveryFinalizer = finalizer
	return nil
}
