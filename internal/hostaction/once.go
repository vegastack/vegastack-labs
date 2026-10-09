package hostaction

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type closedDispatcher struct{}

func (closedDispatcher) Lookup(string, string) (Handler, bool) { return nil, false }
func ProductionDispatcher() Dispatcher                         { return closedDispatcher{} }
func WriteFrame(w io.Writer, value any, maximum int) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maximum {
		return blocked()
	}
	raw = append(raw, '\n')
	n, err := w.Write(raw)
	if err != nil || n != len(raw) {
		return blocked()
	}
	return nil
}
func ReadFrame(r *bufio.Reader, maximum int) ([]byte, error) {
	raw, err := r.ReadSlice('\n')
	if err != nil || len(raw) < 2 || len(raw) > maximum+1 {
		return nil, blocked()
	}
	return raw[:len(raw)-1], nil
}

// RunOnce has no trust/configuration discovery. Production supplies a root-owned
// policy and fixed dispatcher; tests can supply harmless handlers explicitly.
func RunOnce(ctx context.Context, input io.Reader, output io.Writer, policy Policy, receipts *Receipts, dispatcher Dispatcher, now func() time.Time, random io.Reader) (runErr error) {
	if ctx == nil || input == nil || output == nil || receipts == nil || dispatcher == nil || now == nil || random == nil {
		return blocked()
	}
	// Prepare real inherited pipes as pollable handles before any blocking I/O.
	// Tests with in-memory streams exercise the same framing without OS handles.
	if file, ok := input.(*os.File); ok {
		wrapped, cleanup, err := interruptiblePipe(file)
		if err != nil {
			return blocked()
		}
		defer cleanup()
		input = wrapped
	}
	if file, ok := output.(*os.File); ok {
		wrapped, cleanup, err := interruptiblePipe(file)
		if err != nil {
			return blocked()
		}
		defer cleanup()
		output = wrapped
	}
	parentContext := ctx
	denial := generated.HostActionDenial{Schema: generated.SchemaIDHostActionDenial, SchemaVersion: "1.0.0", Code: generated.ErrorCodeAuthorizationDenied, Phase: "envelope"}
	defer func() {
		if runErr != nil && parentContext.Err() == nil {
			deadline, cancel := context.WithTimeout(context.Background(), time.Second)
			stop := context.AfterFunc(deadline, func() {
				if closer, ok := output.(io.Closer); ok {
					_ = closer.Close()
				}
			})
			_ = WriteFrame(output, denial, MaximumFrame)
			stop()
			cancel()
		}
	}()
	// Production input is a pipe. Closing it on cancellation interrupts blocked
	// reads without spawning a goroutine for each frame.
	operationContext := ctx
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		if closer, ok := input.(io.Closer); ok {
			_ = closer.Close()
		}
		if closer, ok := output.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	defer stop()
	reader := bufio.NewReaderSize(input, MaximumEnvelope+2)
	raw, err := ReadFrame(reader, MaximumEnvelope)
	if err != nil || ctx.Err() != nil {
		return blocked()
	}
	bundle, err := VerifyEnvelope(raw, policy, now())
	if err != nil {
		return err
	}
	denial.Phase = "dispatch"
	denial.BundleDigest, _ = BundleDigest(bundle)
	denial.ExecutionDigest = ExecutionDigest(bundle)
	handler, ok := dispatcher.Lookup(bundle.ActionID, bundle.ActionVersion)
	if !ok || handler == nil {
		return blocked()
	}
	digest, _ := BundleDigest(bundle)
	denial.Phase = "authorization"
	nonce := make([]byte, 32)
	if _, err = io.ReadFull(random, nonce); err != nil {
		return blocked()
	}
	challenge := generated.HostActionChallenge{Schema: generated.SchemaIDHostActionChallenge, SchemaVersion: "1.0.0", BundleDigest: digest, Nonce: base64.StdEncoding.EncodeToString(nonce), HostID: bundle.HostID, StartedAt: now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	if WriteFrame(output, challenge, MaximumFrame) != nil {
		return blocked()
	}
	raw, err = ReadFrame(reader, MaximumFrame)
	if err != nil || ctx.Err() != nil || VerifyAuthorization(raw, challenge, bundle, policy, now()) != nil {
		return blocked()
	}
	// The sender closes stdin after the one authorization; extra frames deny.
	if _, err = reader.ReadByte(); err != io.EOF || ctx.Err() != nil {
		return blocked()
	}
	if VerifyAuthorization(raw, challenge, bundle, policy, now()) != nil {
		return blocked()
	}
	denial.Phase = "execution-claim"
	if err = receipts.ClaimExecution(ExecutionDigest(bundle), digest); err != nil {
		if reader, ok := any(receipts).(interface {
			inspectExecution(generated.HostActionBundle) (NativeExecutionObservation, error)
		}); ok {
			if observed, e := reader.inspectExecution(bundle); e == nil {
				denial.ClaimDigest = observed.ClaimDigest
				denial.ResultDigest = observed.ResultDigest
			}
		}
		return err
	}
	denial.Phase = "handler"
	if ctx.Err() != nil {
		return blocked()
	}
	// Handshake budget ends here. The action retains its signed deadline;
	// closing either pipe on parent/deadline cancellation also bounds final writes.
	if !stop() {
		return blocked()
	}
	cancel()
	expiry, _ := time.Parse(time.RFC3339, bundle.ExpiresAt)
	actionContext, actionCancel := context.WithTimeout(operationContext, expiry.Sub(now()))
	defer actionCancel()
	actionStop := context.AfterFunc(actionContext, func() {
		if c, ok := input.(io.Closer); ok {
			_ = c.Close()
		}
		if c, ok := output.(io.Closer); ok {
			_ = c.Close()
		}
	})
	defer actionStop()
	ctx = actionContext
	denial.Phase = "handler"
	result, err := handler.Execute(ctx, bundle)
	if err != nil || ctx.Err() != nil || result.BundleDigest != digest || handler.Verify(ctx, bundle, result) != nil {
		return blocked()
	}
	denial.Phase = "result"
	if receipts.FinishExecution(ExecutionDigest(bundle), digest, result) != nil {
		return blocked()
	}
	return WriteFrame(output, result, MaximumResultFrame)
}
