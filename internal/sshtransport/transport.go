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
	if ctx == nil || command == nil || (input.Executable != "ssh" && input.Executable != "ssh.exe") || len(input.Arguments) != 12 ||
		input.Arguments[0] != "-T" || input.Arguments[1] != "-o" || input.Arguments[2] != "BatchMode=yes" ||
		input.Arguments[3] != "-o" || input.Arguments[4] != "ClearAllForwardings=yes" || input.Arguments[5] != "-o" || input.Arguments[6] != "ExitOnForwardFailure=yes" ||
		input.Arguments[7] != "-o" || input.Arguments[8] != "StrictHostKeyChecking=yes" || input.Arguments[9] != "-o" ||
		!strings.HasPrefix(input.Arguments[10], "UserKnownHostsFile=") || input.Arguments[11] == "" ||
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
