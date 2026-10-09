//go:build linux

package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type protectedActionSigner struct {
	path, keyID string
	owner       uint32
	public      ed25519.PublicKey
}

func newProtectedActionSigner(ctx context.Context, path, keyID string, owner uint32) (ActionSigner, error) {
	if _, err := credentialref.ParseID(keyID); err != nil || owner == 0 {
		return nil, actionFailure()
	}
	s := &protectedActionSigner{path: path, keyID: keyID, owner: owner}
	key, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	s.public = append(ed25519.PublicKey(nil), key[32:]...)
	return s, nil
}
func (s *protectedActionSigner) load(ctx context.Context) (ed25519.PrivateKey, error) {
	raw, err := readLocalSetupProtected(ctx, s.path, s.owner, 128)
	if err != nil {
		return nil, actionFailure()
	}
	defer clear(raw)
	key, err := base64.StdEncoding.Strict().DecodeString(string(raw))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		return nil, actionFailure()
	}
	return ed25519.PrivateKey(key), nil
}
func (s *protectedActionSigner) KeyID() string { return s.keyID }
func (s *protectedActionSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.public...)
}
func (s *protectedActionSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	key, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if !ed25519.PublicKey(key[32:]).Equal(s.public) || ctx.Err() != nil {
		return nil, actionFailure()
	}
	return ed25519.Sign(key, message), nil
}
