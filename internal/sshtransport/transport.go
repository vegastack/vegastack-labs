// Package sshtransport carries the existing HTTP local-API frame through a
// constrained SSH forced command. It supplies no remote command or shell text.
package sshtransport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/localtransport"
)

var (
	ErrInvalid     = errors.New("invalid constrained SSH transport request")
	ErrUnavailable = errors.New("constrained SSH transport unavailable")
)

type Request struct {
	Executable    string
	Arguments     []string
	Method        localtransport.Method
	Path          string
	Body          []byte
	Timeout       time.Duration
	ResponseLimit int64
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
	request, err := http.NewRequest(input.Method, "http://local"+input.Path, bytes.NewReader(input.Body))
	if err != nil {
		return localtransport.Response{}, ErrInvalid
	}
	request.Close = true
	if input.Method == localtransport.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	var framed bytes.Buffer
	if request.Write(&framed) != nil {
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
	response, err := http.ReadResponse(bufio.NewReader(&stdout.buffer), request)
	if err != nil || response == nil || response.Body == nil {
		return localtransport.Response{}, ErrInvalid
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, input.ResponseLimit+1))
	if err != nil || len(body) == 0 || int64(len(body)) > input.ResponseLimit {
		return localtransport.Response{}, ErrInvalid
	}
	return localtransport.Response{StatusCode: response.StatusCode, ContentType: response.Header.Get("Content-Type"), Body: body}, nil
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
