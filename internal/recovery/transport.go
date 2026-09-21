package recovery

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
)

const transportDomain = "vegastack-labs.dev/recovery-custody-x25519-aes256gcm/v1\x00"

func transportBinding(pin PinnedWitness, binding WitnessBinding) (string, []byte, string, error) {
	if !pin.matchesBinding(binding) {
		return "", nil, "", ErrWitnessUnavailable
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return "", nil, "", ErrWitnessUnavailable
	}
	sum := sha256.Sum256(append([]byte(transportDomain), encoded...))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	aad := []byte(transportDomain + pin.ManifestDigest + "\x00" + pin.RecipientKeyID + "\x00" + digest + "\x00" + binding.ReceiptID)
	return digest, aad, transportDomain + pin.ManifestDigest + "/" + digest, nil
}

// SealProtectedEnvelope is a finite custodian-side operation. The recipient
// public key comes only from the independently signed manifest. It owns and
// closes the material reader, never placing plaintext in the envelope.
func SealProtectedEnvelope(ctx context.Context, pin PinnedWitness, binding WitnessBinding, material io.ReadCloser) (envelope ProtectedEnvelope, err error) {
	var private [4097]byte
	defer func() {
		wipePrivate(private[:])
		if recover() != nil {
			envelope = ProtectedEnvelope{}
			err = ErrWitnessUnavailable
		}
	}()
	if material != nil {
		defer material.Close()
	}
	if ctx == nil || ctx.Err() != nil || material == nil {
		return envelope, ErrWitnessUnavailable
	}
	stopClose := context.AfterFunc(ctx, func() { _ = material.Close() })
	defer stopClose()
	digest, aad, info, err := transportBinding(pin, binding)
	if err != nil {
		return envelope, ErrWitnessUnavailable
	}
	length, err := readCustodyBounded(material, private[:], 4096)
	if err != nil || ctx.Err() != nil {
		return envelope, ErrWitnessUnavailable
	}
	recipientPublic, err := ecdh.X25519().NewPublicKey(pin.RecipientPublicKey)
	if err != nil {
		return envelope, ErrWitnessUnavailable
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return envelope, ErrWitnessUnavailable
	}
	shared, err := ephemeral.ECDH(recipientPublic)
	if err != nil {
		return envelope, ErrWitnessUnavailable
	}
	defer wipePrivate(shared)
	key, err := hkdf.Key(sha256.New, shared, []byte(pin.ManifestDigest), info, 32)
	if err != nil {
		return envelope, ErrWitnessUnavailable
	}
	defer wipePrivate(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return envelope, ErrWitnessUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return envelope, ErrWitnessUnavailable
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return envelope, ErrWitnessUnavailable
	}
	ciphertext := aead.Seal(nil, nonce, private[:length], aad)
	if ctx.Err() != nil {
		return envelope, ErrWitnessUnavailable
	}
	return ProtectedEnvelope{Version: 1, RecipientKeyID: pin.RecipientKeyID, EphemeralPublicKey: ephemeral.PublicKey().Bytes(), Nonce: nonce, BindingDigest: digest, Ciphertext: ciphertext, ReceiptID: binding.ReceiptID}, nil
}

type protectedRecipient struct {
	pin    PinnedWitness
	source RecipientPrivateKeySource
}

func NewProtectedRecipient(pin PinnedWitness, source RecipientPrivateKeySource) ProtectedRecipient {
	return protectedRecipient{pin: pin, source: source}
}

func (recipient protectedRecipient) Open(ctx context.Context, envelope ProtectedEnvelope, binding WitnessBinding) (CustodyStream, error) {
	var seed [33]byte
	defer wipePrivate(seed[:])
	if ctx == nil || ctx.Err() != nil || recipient.source == nil {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	digest, aad, info, err := transportBinding(recipient.pin, binding)
	if err != nil || envelope.Version != 1 || envelope.RecipientKeyID != recipient.pin.RecipientKeyID || envelope.BindingDigest != digest || envelope.ReceiptID != binding.ReceiptID || len(envelope.EphemeralPublicKey) != 32 || len(envelope.Nonce) != 12 || len(envelope.Ciphertext) < 24 || len(envelope.Ciphertext) > 4112 {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	reader, err := recipient.source.OpenPrivate(ctx, recipient.pin.RecipientKeyID)
	if err != nil {
		if reader != nil {
			_ = reader.Close()
		}
		return CustodyStream{}, ErrWitnessUnavailable
	}
	if reader == nil {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	defer reader.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = reader.Close() })
	defer stopClose()
	length, err := readCustodyBounded(reader, seed[:], 32)
	if err != nil || length != 32 || ctx.Err() != nil {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	keyPair, err := ecdh.X25519().NewPrivateKey(seed[:32])
	if err != nil || subtle.ConstantTimeCompare(keyPair.PublicKey().Bytes(), recipient.pin.RecipientPublicKey) != 1 {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	ephemeral, err := ecdh.X25519().NewPublicKey(envelope.EphemeralPublicKey)
	if err != nil {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	shared, err := keyPair.ECDH(ephemeral)
	if err != nil {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	defer wipePrivate(shared)
	key, err := hkdf.Key(sha256.New, shared, []byte(recipient.pin.ManifestDigest), info, 32)
	if err != nil {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	defer wipePrivate(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return CustodyStream{}, ErrWitnessUnavailable
	}
	owned := make([]byte, 4096)
	plaintext, err := aead.Open(owned[:0], envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil || len(plaintext) < 8 || len(plaintext) > 4096 || ctx.Err() != nil {
		wipePrivate(owned)
		return CustodyStream{}, ErrWitnessUnavailable
	}
	return CustodyStream{Reader: &wipingReadCloser{data: plaintext}, MaxBytes: 4096, ReceiptID: binding.ReceiptID}, nil
}

type wipingReadCloser struct {
	data     []byte
	position int
	closed   bool
}

func (reader *wipingReadCloser) Read(into []byte) (int, error) {
	if reader.closed {
		return 0, io.ErrClosedPipe
	}
	if reader.position >= len(reader.data) {
		return 0, io.EOF
	}
	n := copy(into, reader.data[reader.position:])
	reader.position += n
	return n, nil
}
func (reader *wipingReadCloser) Close() error {
	if !reader.closed {
		wipePrivate(reader.data[:cap(reader.data)])
		reader.closed = true
	}
	return nil
}
