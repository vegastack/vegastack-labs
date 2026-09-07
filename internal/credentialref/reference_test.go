package credentialref

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type inspectorFunc func(context.Context, Reference) (Metadata, error)

func (fn inspectorFunc) Inspect(ctx context.Context, reference Reference) (Metadata, error) {
	return fn(ctx, reference)
}

func TestVerifyCurrentMatchingReference(t *testing.T) {
	reference := Reference{ID: "backup-key", Consumer: "backup"}
	want := Metadata{Reference: reference, MaterialVersion: "version-2", State: Current}
	inspector := inspectorFunc(func(_ context.Context, got Reference) (Metadata, error) {
		if got != reference {
			t.Fatalf("inspector reference = %#v, want %#v", got, reference)
		}
		return want, nil
	})

	got, err := Verify(context.Background(), inspector, reference, "backup")
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if got != want {
		t.Fatalf("Verify() metadata = %#v, want %#v", got, want)
	}
}

func TestVerifyRejectsMalformedInputBeforeInspection(t *testing.T) {
	tooLong := strings.Repeat("a", 256)
	tests := []struct {
		name              string
		reference         Reference
		requestedConsumer string
	}{
		{name: "empty id", reference: Reference{Consumer: "backup"}, requestedConsumer: "backup"},
		{name: "whitespace id", reference: Reference{ID: " backup-key ", Consumer: "backup"}, requestedConsumer: "backup"},
		{name: "control id", reference: Reference{ID: "backup\nkey", Consumer: "backup"}, requestedConsumer: "backup"},
		{name: "invalid utf8 id", reference: Reference{ID: string([]byte{0xff}), Consumer: "backup"}, requestedConsumer: "backup"},
		{name: "overlong id", reference: Reference{ID: tooLong, Consumer: "backup"}, requestedConsumer: "backup"},
		{name: "empty consumer", reference: Reference{ID: "backup-key"}, requestedConsumer: "backup"},
		{name: "whitespace consumer", reference: Reference{ID: "backup-key", Consumer: " backup "}, requestedConsumer: "backup"},
		{name: "control requested consumer", reference: Reference{ID: "backup-key", Consumer: "backup"}, requestedConsumer: "back\u0000up"},
		{name: "overlong requested consumer", reference: Reference{ID: "backup-key", Consumer: "backup"}, requestedConsumer: tooLong},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			inspector := inspectorFunc(func(context.Context, Reference) (Metadata, error) {
				called = true
				return Metadata{}, nil
			})
			_, err := Verify(context.Background(), inspector, test.reference, test.requestedConsumer)
			assertCredentialCode(t, err, generated.ErrorCodeInputInvalid)
			if called {
				t.Fatal("inspector called for malformed input")
			}
		})
	}
}

func TestVerifyRejectsWrongConsumerBeforeInspection(t *testing.T) {
	called := false
	inspector := inspectorFunc(func(context.Context, Reference) (Metadata, error) {
		called = true
		return Metadata{}, nil
	})
	_, err := Verify(context.Background(), inspector, Reference{ID: "backup-key", Consumer: "backup"}, "deploy")
	assertCredentialCode(t, err, generated.ErrorCodeAuthorizationDenied)
	if called {
		t.Fatal("inspector called before consumer authorization")
	}
}

func TestVerifyRejectsInvalidReturnedMetadata(t *testing.T) {
	reference := Reference{ID: "backup-key", Consumer: "backup"}
	tests := []struct {
		name     string
		metadata Metadata
	}{
		{name: "reference id mismatch", metadata: Metadata{Reference: Reference{ID: "other-key", Consumer: "backup"}, MaterialVersion: "v1", State: Current}},
		{name: "consumer mismatch", metadata: Metadata{Reference: Reference{ID: "backup-key", Consumer: "deploy"}, MaterialVersion: "v1", State: Current}},
		{name: "empty material version", metadata: Metadata{Reference: reference, State: Current}},
		{name: "malformed material version", metadata: Metadata{Reference: reference, MaterialVersion: " secret ", State: Current}},
		{name: "unknown state", metadata: Metadata{Reference: reference, MaterialVersion: "v1", State: State("unknown")}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inspector := inspectorFunc(func(context.Context, Reference) (Metadata, error) {
				return test.metadata, nil
			})
			_, err := Verify(context.Background(), inspector, reference, "backup")
			assertCredentialCode(t, err, generated.ErrorCodeDependencyUnavailable)
		})
	}
}

func TestVerifyMapsNonCurrentStatesToUnavailable(t *testing.T) {
	reference := Reference{ID: "backup-key", Consumer: "backup"}
	for _, state := range []State{Unavailable, Stale, Revoked} {
		t.Run(string(state), func(t *testing.T) {
			inspector := inspectorFunc(func(context.Context, Reference) (Metadata, error) {
				return Metadata{Reference: reference, MaterialVersion: "v1", State: state}, nil
			})
			_, err := Verify(context.Background(), inspector, reference, "backup")
			assertCredentialCode(t, err, generated.ErrorCodeDependencyUnavailable)
		})
	}
}

func TestVerifyMapsCancellationToInterrupted(t *testing.T) {
	reference := Reference{ID: "backup-key", Consumer: "backup"}

	t.Run("before inspection", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		called := false
		inspector := inspectorFunc(func(context.Context, Reference) (Metadata, error) {
			called = true
			return Metadata{}, nil
		})
		_, err := Verify(ctx, inspector, reference, "backup")
		assertCredentialCode(t, err, generated.ErrorCodeInterrupted)
		if called {
			t.Fatal("inspector called after cancellation")
		}
	})

	t.Run("during inspection", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		inspector := inspectorFunc(func(context.Context, Reference) (Metadata, error) {
			cancel()
			return Metadata{}, errors.New("private-credential-canary")
		})
		_, err := Verify(ctx, inspector, reference, "backup")
		assertCredentialCode(t, err, generated.ErrorCodeInterrupted)
		if strings.Contains(err.Error(), "private-credential-canary") {
			t.Fatalf("credential failure was not sanitized: %v", err)
		}
	})
}

func TestVerifyNeverRevealsResolverMaterial(t *testing.T) {
	inspector := inspectorFunc(func(context.Context, Reference) (Metadata, error) {
		return Metadata{}, errors.New("private-credential-canary")
	})
	_, err := Verify(context.Background(), inspector, Reference{ID: "backup-key", Consumer: "backup"}, "backup")
	if err == nil || strings.Contains(err.Error(), "private-credential-canary") {
		t.Fatalf("credential failure was not sanitized: %v", err)
	}
	assertCredentialCode(t, err, generated.ErrorCodeDependencyUnavailable)
}

func TestVerifyRejectsMissingInspector(t *testing.T) {
	_, err := Verify(context.Background(), nil, Reference{ID: "backup-key", Consumer: "backup"}, "backup")
	assertCredentialCode(t, err, generated.ErrorCodeInputInvalid)
}

func assertCredentialCode(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want code %q", want)
	}
	var credentialError *Error
	if !errors.As(err, &credentialError) {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if credentialError.Code != want {
		t.Fatalf("error code = %q, want %q", credentialError.Code, want)
	}
}
