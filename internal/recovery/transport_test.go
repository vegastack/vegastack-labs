package recovery

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"testing"
	"time"
)

type syntheticPrivateKeySource struct {
	key    []byte
	closed bool
	opens  int
}

func TestProtectedEnvelopeSealCancellationClosesMaterial(t *testing.T) {
	pin, binding, _, _ := witnessFixture(t)
	blocked := &cancelCustodyReader{started: make(chan struct{}), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := SealProtectedEnvelope(ctx, pin, binding, blocked); result <- err }()
	select {
	case <-blocked.started:
	case <-time.After(time.Second):
		t.Fatal("seal did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled seal accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled seal did not close material")
	}
}

func (s *syntheticPrivateKeySource) OpenPrivate(context.Context, string) (io.ReadCloser, error) {
	s.opens++
	return &trackedPrivateKey{Reader: bytes.NewReader(s.key), source: s}, nil
}

type trackedPrivateKey struct {
	io.Reader
	source *syntheticPrivateKeySource
}

func (s *trackedPrivateKey) Close() error { s.source.closed = true; return nil }

func TestProtectedRecipientEnvelopeBindsExactRecoveryAndWipes(t *testing.T) {
	pin, binding, _, _ := witnessFixture(t)
	recipientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin.RecipientPublicKey = recipientKey.PublicKey().Bytes()
	pin.pinSeal = pin.seal()
	canary := []byte("synthetic-independent-protected-material")
	envelope, err := SealProtectedEnvelope(context.Background(), pin, binding, io.NopCloser(bytes.NewReader(canary)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope.Ciphertext, canary) {
		t.Fatal("protected envelope exposed material")
	}
	source := &syntheticPrivateKeySource{key: recipientKey.Bytes()}
	recipient := NewProtectedRecipient(pin, source)
	stream, err := recipient.Open(context.Background(), envelope, binding)
	if err != nil || !source.closed {
		t.Fatalf("recipient open=%v closed=%v", err, source.closed)
	}
	material, err := io.ReadAll(stream.Reader)
	if err != nil || !bytes.Equal(material, canary) {
		t.Fatal("recipient material mismatch")
	}
	backing, ok := stream.Reader.(*wipingReadCloser)
	if !ok {
		t.Fatal("private stream not wipe-owned")
	}
	if err := stream.Reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backing.data, make([]byte, len(backing.data))) {
		t.Fatal("private stream not wiped")
	}
	changed := binding
	changed.DraftID = "other"
	source = &syntheticPrivateKeySource{key: recipientKey.Bytes()}
	if _, err := NewProtectedRecipient(pin, source).Open(context.Background(), envelope, changed); err == nil {
		t.Fatal("changed draft accepted")
	}
	if source.opens != 0 && !source.closed {
		t.Fatal("failed open leaked private key stream")
	}
	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	if _, err := NewProtectedRecipient(pin, &syntheticPrivateKeySource{key: recipientKey.Bytes()}).Open(context.Background(), tampered, binding); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	other, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewProtectedRecipient(pin, &syntheticPrivateKeySource{key: other.Bytes()}).Open(context.Background(), envelope, binding); err == nil {
		t.Fatal("wrong recipient key accepted")
	}
}
