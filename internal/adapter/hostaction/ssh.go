package hostaction

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	protocol "github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/crypto/ssh"
)

const command = "/usr/bin/sudo -n -- /usr/local/bin/vsk-labs host-action-once"

func (a *Adapter) exchangeOne(ctx context.Context, target Target, envelope generated.HostActionEnvelope, digest string, value *credentialref.Value, ready chan<- struct{}, release <-chan struct{}, refusal *generated.HostActionDenial, negative string) (generated.HostActionResult, bool, error) {
	fail := func(observed bool) (generated.HostActionResult, bool, error) {
		return generated.HostActionResult{}, observed, denied()
	}
	hostKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(target.HostKey))
	if err != nil || len(rest) != 0 {
		return fail(false)
	}
	signer, err := ssh.ParsePrivateKey(value.Bytes())
	if err != nil {
		return fail(false)
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(target.Address, strconv.Itoa(int(target.Port))))
	if err != nil {
		return fail(false)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	handshakeDeadline := time.Now().Add(10 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(handshakeDeadline) {
		handshakeDeadline = deadline
	}
	if conn.SetDeadline(handshakeDeadline) != nil {
		return fail(false)
	}
	config := &ssh.ClientConfig{User: target.User, HostKeyCallback: ssh.FixedHostKey(hostKey), Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}}
	secure, chans, requests, err := ssh.NewClientConn(conn, conn.RemoteAddr().String(), config)
	if err != nil {
		return fail(false)
	}
	client := ssh.NewClient(secure, chans, requests)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return fail(false)
	}
	defer session.Close()
	input, err := session.StdinPipe()
	if err != nil {
		return fail(false)
	}
	output, err := session.StdoutPipe()
	if err != nil {
		return fail(false)
	}
	session.Stderr = &boundedDiscard{remaining: protocol.MaximumFrame, close: conn.Close}
	if session.Start(command) != nil {
		return fail(false)
	}
	if negative != "" {
		mutated := envelope
		switch negative {
		case "malformed-envelope":
		case "wrong-host":
			mutated.Bundle.HostID = "native-unbound-host"
		case "wrong-plan":
			mutated.Bundle.PlanID = "native-unbound-plan"
		case "wrong-epoch":
			mutated.Bundle.RecoveryEpoch++
		case "invalid-signature":
			mutated.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
		default:
			return fail(false)
		}
		if negative == "malformed-envelope" {
			if _, err = input.Write([]byte("{\n")); err != nil {
				return fail(false)
			}
		} else if protocol.WriteFrame(input, mutated, protocol.MaximumEnvelope) != nil {
			return fail(false)
		}
		if input.Close() != nil {
			return fail(false)
		}
	} else if protocol.WriteFrame(input, envelope, protocol.MaximumEnvelope) != nil {
		return fail(false)
	}
	reader := bufio.NewReaderSize(output, protocol.MaximumResultFrame+2)
	raw, err := protocol.ReadFrame(reader, protocol.MaximumFrame)
	if negative != "" {
		var d generated.HostActionDenial
		if refusal == nil || err != nil || generated.ValidateContractJSON(generated.SchemaIDHostActionDenial, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &d) != nil || d.Code != generated.ErrorCodeAuthorizationDenied || d.Phase != "envelope" || d.BundleDigest != "" || d.ExecutionDigest != "" {
			return fail(false)
		}
		if _, e := reader.ReadByte(); e != io.EOF || ctx.Err() != nil {
			return fail(false)
		}
		if e := session.Wait(); e != nil {
			if exit, ok := e.(*ssh.ExitError); ok && exit.ExitStatus() == 1 {
				*refusal = d
				return generated.HostActionResult{}, false, nil
			}
		}
		return fail(false)
	}
	var challenge generated.HostActionChallenge
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDHostActionChallenge, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &challenge) != nil || challenge.BundleDigest != digest || challenge.HostID != target.HostID {
		return fail(false)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	started, timeErr := time.Parse(time.RFC3339, challenge.StartedAt)
	now := time.Now()
	if err != nil || len(nonce) != 32 || timeErr != nil || started.After(now) || now.Sub(started) > protocol.AuthorizationWindow {
		return fail(false)
	}
	current, err := a.targets.Resolve(ctx, envelope.Bundle)
	if err != nil || current != target {
		return fail(false)
	}
	authorization, err := a.authority.Authorize(ctx, envelope, challenge)
	if err != nil || ctx.Err() != nil {
		return fail(false)
	}
	authRaw, err := json.Marshal(authorization)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDHostActionAuthorization, authRaw, generated.ContractExact) != nil || authorization.BundleDigest != digest || authorization.ChallengeDigest != protocol.Digest(challenge) || authorization.KeyID != envelope.KeyID || authorization.StateRevision != envelope.Bundle.StateRevision || authorization.RecoveryEpoch != envelope.Bundle.RecoveryEpoch {
		return fail(false)
	}
	// The bounded handshake does not shorten the independently signed action
	// deadline. Cancellation still closes the connection at every protocol stage.
	actionDeadline, err := time.Parse(time.RFC3339, envelope.Bundle.ExpiresAt)
	if err != nil || !time.Now().Before(actionDeadline) {
		return fail(false)
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(actionDeadline) {
		actionDeadline = deadline
	}
	if conn.SetDeadline(actionDeadline) != nil {
		return fail(false)
	}
	if ready != nil {
		select {
		case ready <- struct{}{}:
		case <-ctx.Done():
			return fail(false)
		}
		select {
		case <-release:
		case <-ctx.Done():
			return fail(false)
		}
	}
	// From the first authorization byte onward the remote action may have started.
	if protocol.WriteFrame(input, authorization, protocol.MaximumFrame) != nil || input.Close() != nil {
		return fail(true)
	}
	raw, err = protocol.ReadFrame(reader, protocol.MaximumResultFrame)
	if refusal != nil && err == nil && generated.ValidateContractJSON(generated.SchemaIDHostActionDenial, raw, generated.ContractExact) == nil {
		var deniedResult generated.HostActionDenial
		if json.Unmarshal(raw, &deniedResult) == nil && deniedResult.Code == generated.ErrorCodeAuthorizationDenied && deniedResult.Phase == "execution-claim" && deniedResult.BundleDigest == digest && deniedResult.ExecutionDigest == protocol.ExecutionDigest(envelope.Bundle) {
			if _, e := reader.ReadByte(); e == io.EOF && ctx.Err() == nil {
				if e = session.Wait(); e != nil {
					if exit, ok := e.(*ssh.ExitError); ok && exit.ExitStatus() == 1 {
						*refusal = deniedResult
						return generated.HostActionResult{}, false, nil
					}
				}
			}
		}
		return fail(true)
	}
	var result generated.HostActionResult
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDHostActionResult, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &result) != nil || result.BundleDigest != digest || protocol.ValidateResult(result) != nil {
		return fail(true)
	}
	if _, err = reader.ReadByte(); err != io.EOF || ctx.Err() != nil {
		return fail(true)
	}
	if session.Wait() != nil {
		return fail(true)
	}
	return result, true, nil
}

// Discard diagnostics without retaining potentially sensitive text. Exceeding
// the finite stderr budget closes the transport instead of draining forever.
type boundedDiscard struct {
	remaining int
	close     func() error
}

func (w *boundedDiscard) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		_ = w.close()
		return 0, denied()
	}
	w.remaining -= len(p)
	return len(p), nil
}
