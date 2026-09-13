// Package sshtransport carries the existing HTTP local-API frame through a
// constrained SSH forced command. It supplies no remote command or shell text.
package sshtransport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/apissh"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
)

var (
	ErrInvalid     = errors.New("invalid constrained SSH transport request")
	ErrUnavailable = errors.New("constrained SSH transport unavailable")
)

type Request struct {
	Executable     string
	Arguments      []string
	RequestID      string
	SSHPrincipalID string
	DeviceID       string
	RecoveryEpoch  int64
	OperationArgs  []string
	Method         localtransport.Method
	Path           string
	Body           []byte
	Timeout        time.Duration
	ResponseLimit  int64
}

type commandFactory func(context.Context, string, []string) *exec.Cmd

const (
	maximumResponseBytes = 24 << 20
	maximumTimeout       = 30 * time.Second
)

var destinationPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9._:-]+$`)

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int64
	full   bool
}

func (writer *boundedBuffer) Write(content []byte) (int, error) {
	remaining := writer.limit - int64(writer.buffer.Len())
	if remaining <= 0 || int64(len(content)) > remaining {
		writer.full = true
		return 0, ErrInvalid
	}
	return writer.buffer.Write(content)
}

func RoundTrip(ctx context.Context, input Request) (localtransport.Response, error) {
	return roundTrip(ctx, input, func(ctx context.Context, executable string, arguments []string) *exec.Cmd {
		return exec.CommandContext(ctx, executable, arguments...)
	})
}

func roundTrip(ctx context.Context, input Request, command commandFactory) (localtransport.Response, error) {
	if ctx == nil || command == nil || (input.Executable != "ssh" && input.Executable != "ssh.exe") || !validArguments(input.Arguments) ||
		input.Timeout <= 0 || input.Timeout > maximumTimeout || input.ResponseLimit <= 0 || input.ResponseLimit > maximumResponseBytes {
		return localtransport.Response{}, ErrInvalid
	}
	header, err := apissh.NewRequestHeader(input.RequestID, input.SSHPrincipalID, input.DeviceID, string(input.Method)+" "+input.Path, input.OperationArgs, input.RecoveryEpoch, input.Body)
	if err != nil {
		return localtransport.Response{}, ErrInvalid
	}
	var framed bytes.Buffer
	if apissh.WriteRequest(&framed, header, input.Body) != nil {
		return localtransport.Response{}, ErrInvalid
	}
	requestCtx, cancel := context.WithTimeout(ctx, input.Timeout)
	defer cancel()
	process := command(requestCtx, input.Executable, append([]string(nil), input.Arguments...))
	process.Stdin = bytes.NewReader(framed.Bytes())
	stdout := boundedBuffer{limit: input.ResponseLimit + 16*1024}
	process.Stdout = &stdout
	process.Stderr = io.Discard
	if err := process.Run(); err != nil {
		if stdout.full {
			return localtransport.Response{}, ErrInvalid
		}
		if requestCtx.Err() != nil {
			return localtransport.Response{}, requestCtx.Err()
		}
		return localtransport.Response{}, ErrUnavailable
	}
	response, err := apissh.ReadResponse(&stdout.buffer, input.RequestID)
	if err != nil || len(response.RawEnvelope) == 0 || int64(len(response.RawEnvelope)) > input.ResponseLimit {
		return localtransport.Response{}, ErrInvalid
	}
	return localtransport.Response{StatusCode: statusForEnvelope(response.Envelope), ContentType: "application/json", Body: response.RawEnvelope}, nil
}

func statusForEnvelope(envelope generated.RunResult) int {
	if len(envelope.Errors) == 0 {
		return localtransport.StatusOK
	}
	return map[string]int{
		generated.ErrorCodeAuthenticationRequired: localtransport.StatusUnauthorized,
		generated.ErrorCodeAuthorizationDenied:    localtransport.StatusForbidden,
		generated.ErrorCodeInputInvalid:           localtransport.StatusBadRequest,
		generated.ErrorCodeSchemaUnsupported:      localtransport.StatusBadRequest,
		generated.ErrorCodeStateConflict:          localtransport.StatusConflict,
		generated.ErrorCodeRecoveryEpochMismatch:  localtransport.StatusConflict,
		generated.ErrorCodeResourceNotFound:       localtransport.StatusNotFound,
		generated.ErrorCodePrerequisiteBlocked:    localtransport.StatusPreconditionFailed,
		generated.ErrorCodeInterrupted:            localtransport.StatusRequestTimeout,
		generated.ErrorCodeDependencyUnavailable:  localtransport.StatusServiceUnavailable,
		generated.ErrorCodeIntegrityFailure:       localtransport.StatusServiceUnavailable,
		generated.ErrorCodeApprovalRequired:       localtransport.StatusPreconditionFailed,
		generated.ErrorCodePlanStale:              localtransport.StatusConflict,
		generated.ErrorCodeExecutionFailed:        localtransport.StatusBadGateway,
		generated.ErrorCodeExecutionPartial:       localtransport.StatusConflict,
		generated.ErrorCodeRecoveryRequired:       localtransport.StatusConflict,
	}[envelope.Errors[0].Code]
}

func validArguments(arguments []string) bool {
	if len(arguments) < 5 {
		return false
	}
	knownHostsArgument := arguments[len(arguments)-4]
	destination := arguments[len(arguments)-1]
	if !strings.HasPrefix(knownHostsArgument, "UserKnownHostsFile=") || !destinationPattern.MatchString(destination) || len(destination) > 255 {
		return false
	}
	knownHosts := strings.TrimPrefix(knownHostsArgument, "UserKnownHostsFile=")
	if knownHosts == "" {
		return false
	}
	expected := constrainedArguments(knownHosts, destination)
	if len(arguments) != len(expected) {
		return false
	}
	for index := range expected {
		if arguments[index] != expected[index] {
			return false
		}
	}
	return true
}

func constrainedArguments(knownHosts, destination string) []string {
	return []string{
		"-F", "none", "-T",
		"-o", "AddKeysToAgent=no", "-o", "BatchMode=yes", "-o", "CanonicalizeHostname=no", "-o", "CheckHostIP=yes",
		"-o", "ClearAllForwardings=yes", "-o", "ControlMaster=no", "-o", "EscapeChar=none", "-o", "ExitOnForwardFailure=yes",
		"-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "GatewayPorts=no", "-o", "GlobalKnownHostsFile=none",
		"-o", "HostbasedAuthentication=no", "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "KbdInteractiveAuthentication=no",
		"-o", "PasswordAuthentication=no", "-o", "PermitLocalCommand=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
		"-o", "RemoteCommand=none", "-o", "RequestTTY=no", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
		"-o", "UserKnownHostsFile=" + knownHosts, "-o", "VerifyHostKeyDNS=no", destination,
	}
}
