package sshtransport

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/localtransport"
)

func TestRoundTripUsesDirectArgumentsAndExactHTTPFrame(t *testing.T) {
	if os.Getenv("VSK_SSH_HELPER") == "1" {
		content, _ := io.ReadAll(os.Stdin)
		_ = os.WriteFile(os.Getenv("VSK_SSH_CAPTURE"), content, 0o600)
		_, _ = os.Stdout.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 3\r\nConnection: close\r\n\r\n{}\n"))
		os.Exit(0)
	}
	directory := t.TempDir()
	capture := filepath.Join(directory, "capture")
	t.Setenv("VSK_SSH_CAPTURE", capture)

	var gotExecutable string
	var gotArguments []string
	response, err := roundTrip(context.Background(), Request{
		Executable: "ssh", Arguments: []string{"-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/literal path", "operator@host"},
		Method: localtransport.MethodPost, Path: "/api/v1/test", Body: []byte(`{"value":"$(literal)"}`), Timeout: 5 * time.Second, ResponseLimit: 32,
	}, func(ctx context.Context, executable string, arguments []string) *exec.Cmd {
		gotExecutable = executable
		gotArguments = append([]string(nil), arguments...)
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestRoundTripUsesDirectArgumentsAndExactHTTPFrame")
		command.Env = append(os.Environ(), "VSK_SSH_HELPER=1")
		return command
	})
	if err != nil || response.StatusCode != 200 || string(response.Body) != "{}\n" {
		t.Fatalf("RoundTrip() = %#v, %v", response, err)
	}
	captured, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	wantArguments := []string{"-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/literal path", "operator@host"}
	if gotExecutable != "ssh" || fmt.Sprint(gotArguments) != fmt.Sprint(wantArguments) {
		t.Fatalf("invocation = %q %#v", gotExecutable, gotArguments)
	}
	wantFrame := "POST /api/v1/test HTTP/1.1\r\nHost: local\r\nUser-Agent: Go-http-client/1.1\r\nConnection: close\r\nContent-Length: 22\r\nContent-Type: application/json\r\n\r\n{\"value\":\"$(literal)\"}"
	if string(captured) != wantFrame {
		t.Fatalf("captured bytes = %q", captured)
	}
}

func TestRoundTripRejectsAnyRemoteCommandArgument(t *testing.T) {
	arguments := []string{"-T", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=/known", "operator@host", "uname"}
	_, err := RoundTrip(context.Background(), Request{Executable: "ssh", Arguments: arguments, Method: localtransport.MethodGet, Path: "/api/v1/health", Timeout: time.Second, ResponseLimit: 32})
	if err != ErrInvalid {
		t.Fatalf("remote command error = %v", err)
	}
}
