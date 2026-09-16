package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

const privateCredentialCanary = "private-credential-canary"

type stubCredentialOperations struct {
	response localapi.TypedResponse[generated.CredentialImportSubmission]
	err      error
	config   string
	request  generated.CredentialImportRequest
	private  []byte
	calls    int
}

func (stub *stubCredentialOperations) ImportCredential(_ context.Context, config string, request generated.CredentialImportRequest, source io.Reader) (localapi.TypedResponse[generated.CredentialImportSubmission], error) {
	stub.calls++
	stub.config, stub.request = config, request
	private, err := io.ReadAll(source)
	stub.private = append([]byte(nil), private...)
	if err != nil {
		return localapi.TypedResponse[generated.CredentialImportSubmission]{}, failure.New(generated.ErrorCodeInterrupted, "credential-import", false)
	}
	return stub.response, stub.err
}

type trackedCredentialDescriptor struct {
	*bytes.Reader
	closed bool
}

func (descriptor *trackedCredentialDescriptor) Close() error {
	descriptor.closed = true
	return nil
}

type failingCredentialReader struct{}

func (failingCredentialReader) Read([]byte) (int, error) { return 0, errors.New("private-read-canary") }

func credentialImportArguments() []string {
	return []string{
		"credential", "import", "--config", "profile.json",
		"--reference-id", "reference-a", "--consumer-id", "consumer-a",
		"--purpose-id", "purpose-a", "--target-id", "target-a",
		"--resolver-id", "native-systemd", "--material-version", "version-a",
		"--idempotency-key", "import-a", "--expected-state-revision", "7",
		"--recovery-epoch", "2",
	}
}

func successfulCredentialOperations(t *testing.T) *stubCredentialOperations {
	t.Helper()
	data := generated.CredentialImportSubmission{
		Schema: generated.SchemaIDCredentialImportSubmission, SchemaVersion: "1.1.0",
		DraftID: "credential-draft-a", ReferenceID: "reference-a",
		CiphertextFingerprint: "sha256:" + strings.Repeat("b", 64), Status: "draft",
		StateRevision: 8, RecoveryEpoch: 2,
	}
	return &stubCredentialOperations{response: operationResponse(t, "api.v1.credential-references.import-stream", true, 2, 8, data)}
}

func TestCredentialImportReadsStdinAndRendersOnlySanitizedFields(t *testing.T) {
	operations := successfulCredentialOperations(t)
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), credentialImportArguments(), nil,
		WithInput(strings.NewReader(privateCredentialCanary)),
		WithCredentialControlOperations(operations),
	)
	want, err := os.ReadFile(filepath.Join("testdata", "credential-import-human.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || stdout != string(want) || stderr != "" {
		t.Fatalf("credential import = code %d stdout %q stderr %q", code, stdout, stderr)
	}
	if operations.calls != 1 || operations.config != "profile.json" || string(operations.private) != privateCredentialCanary {
		t.Fatalf("credential operation = calls %d config %q private %q", operations.calls, operations.config, operations.private)
	}
	if operations.request.Schema != generated.SchemaIDCredentialImportRequest || operations.request.SchemaVersion != generated.RegistrySchemaVersion || operations.request.ExpectedStateRevision != 7 || operations.request.RecoveryEpoch != 2 || operations.request.TargetDigest != credentialref.ImportTargetDigest(operations.request) {
		t.Fatalf("credential request = %#v", operations.request)
	}
	if strings.Contains(stdout+stderr, privateCredentialCanary) {
		t.Fatal("private credential appeared in command output")
	}
}

func TestCredentialImportJSONPreservesSanitizedRemoteEnvelope(t *testing.T) {
	operations := successfulCredentialOperations(t)
	args := append(credentialImportArguments(), "--output", "json")
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), args, nil,
		WithInput(strings.NewReader(privateCredentialCanary)),
		WithCredentialControlOperations(operations),
	)
	if code != 0 || stdout != string(operations.response.Raw) || stderr != "" || strings.Contains(stdout+stderr, privateCredentialCanary) {
		t.Fatalf("credential JSON = code %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestCredentialImportUsesAndClosesExplicitDescriptor(t *testing.T) {
	operations := successfulCredentialOperations(t)
	descriptor := &trackedCredentialDescriptor{Reader: bytes.NewReader([]byte(privateCredentialCanary))}
	args := append(credentialImportArguments(), "--input-fd", "7")
	opened := 0
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), args, nil,
		WithInput(failingCredentialReader{}),
		WithCredentialControlOperations(operations),
		WithCredentialDescriptorOpener(func(fd int) (io.ReadCloser, error) {
			opened++
			if fd != 7 {
				t.Fatalf("descriptor = %d, want 7", fd)
			}
			return descriptor, nil
		}),
	)
	if code != 0 || stderr != "" || stdout == "" || opened != 1 || !descriptor.closed || string(operations.private) != privateCredentialCanary {
		t.Fatalf("descriptor import = code %d stdout %q stderr %q opened %d closed %t private %q", code, stdout, stderr, opened, descriptor.closed, operations.private)
	}
}

func TestCredentialImportRejectsUnopenedDescriptorWithoutReadingStdin(t *testing.T) {
	operations := successfulCredentialOperations(t)
	args := append(credentialImportArguments(), "--input-fd", "7")
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), args, nil,
		WithInput(failingCredentialReader{}),
		WithCredentialControlOperations(operations),
		WithCredentialDescriptorOpener(func(int) (io.ReadCloser, error) {
			return nil, errors.New("private-descriptor-canary")
		}),
	)
	if code != 2 || stdout != "" || stderr != "vsk-labs: INPUT_INVALID (arguments)\n" || operations.calls != 0 || strings.Contains(stdout+stderr, "private-descriptor-canary") {
		t.Fatalf("unopened descriptor = code %d stdout %q stderr %q calls %d", code, stdout, stderr, operations.calls)
	}
}

func TestCredentialImportRejectsInvalidInputBeforePrivateRead(t *testing.T) {
	tests := [][]string{
		append(credentialImportArguments(), "--input-fd", "2"),
		append(credentialImportArguments(), "--input-fd", "1048576"),
		append(credentialImportArguments(), "--input-fd", "not-a-number"),
		append(credentialImportArguments(), "--value", privateCredentialCanary),
	}
	for _, args := range tests {
		operations := successfulCredentialOperations(t)
		code, stdout, stderr := runTestAppWithOptions(t, context.Background(), args, nil,
			WithInput(failingCredentialReader{}), WithCredentialControlOperations(operations))
		if code != 2 || stdout != "" || stderr != "vsk-labs: INPUT_INVALID (arguments)\n" || operations.calls != 0 || strings.Contains(stdout+stderr, privateCredentialCanary) {
			t.Fatalf("invalid args %v = code %d stdout %q stderr %q calls %d", args, code, stdout, stderr, operations.calls)
		}
	}
}

func TestCredentialImportSanitizesReadAndTransportFailures(t *testing.T) {
	tests := []struct {
		name   string
		input  io.Reader
		err    error
		code   int
		stderr string
	}{
		{name: "interrupted read", input: failingCredentialReader{}, code: 9, stderr: "vsk-labs: INTERRUPTED (credential-import)\n"},
		{name: "constrained ssh", input: strings.NewReader(privateCredentialCanary), err: failure.New(generated.ErrorCodeAuthorizationDenied, "credential-import-local-only", false), code: 4, stderr: "vsk-labs: AUTHORIZATION_DENIED (credential-import-local-only)\n"},
		{name: "over limit", input: strings.NewReader(privateCredentialCanary), err: failure.New(generated.ErrorCodeInputInvalid, "credential-import-stream", false), code: 2, stderr: "vsk-labs: INPUT_INVALID (credential-import-stream)\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operations := successfulCredentialOperations(t)
			operations.err = test.err
			code, stdout, stderr := runTestAppWithOptions(t, context.Background(), credentialImportArguments(), nil,
				WithInput(test.input), WithCredentialControlOperations(operations))
			if code != test.code || stdout != "" || stderr != test.stderr || strings.Contains(stdout+stderr, privateCredentialCanary) || strings.Contains(stdout+stderr, "private-read-canary") {
				t.Fatalf("failure = code %d stdout %q stderr %q", code, stdout, stderr)
			}
		})
	}
}

func TestCredentialImportDoesNotReadPrivateEnvironment(t *testing.T) {
	t.Setenv("VSK_LABS_CREDENTIAL_VALUE", privateCredentialCanary)
	operations := successfulCredentialOperations(t)
	code, stdout, stderr := runTestAppWithOptions(t, context.Background(), credentialImportArguments(), nil,
		WithInput(strings.NewReader("encrypted-fixture")), WithCredentialControlOperations(operations))
	if code != 0 || stderr != "" || strings.Contains(stdout+stderr, privateCredentialCanary) || string(operations.private) != "encrypted-fixture" {
		t.Fatalf("environment isolation = code %d stdout %q stderr %q private %q", code, stdout, stderr, operations.private)
	}
}
