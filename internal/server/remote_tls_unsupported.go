//go:build !linux

package server

import (
	"crypto/tls"
	"errors"
	"io"
	"os"
)

func loadProtectedTLSKeyPair(certificatePath, privateKeyPath string) (tls.Certificate, error) {
	certificatePEM, err := readPortableTLSMaterial(certificatePath, false)
	if err != nil {
		return tls.Certificate{}, err
	}
	privateKeyPEM, err := readPortableTLSMaterial(privateKeyPath, true)
	if err != nil {
		return tls.Certificate{}, err
	}
	defer clear(privateKeyPEM)
	return tls.X509KeyPair(certificatePEM, privateKeyPEM)
}

// Non-Linux builds exist for portable client commands and development tests;
// server Run still rejects them. Keep this fallback bounded and fail closed on
// the final path component while Linux owns the race-resistant production read.
func readPortableTLSMaterial(materialPath string, private bool) ([]byte, error) {
	linkStatus, err := os.Lstat(materialPath)
	if err != nil || !linkStatus.Mode().IsRegular() || linkStatus.Size() <= 0 || linkStatus.Size() > maxTLSMaterialBytes {
		return nil, errors.New("invalid TLS material")
	}
	permissions := linkStatus.Mode().Perm()
	if (private && permissions != 0o600) || (!private && permissions != 0o600 && permissions != 0o640 && permissions != 0o644) {
		return nil, errors.New("invalid TLS material")
	}
	file, err := os.Open(materialPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedStatus, err := file.Stat()
	if err != nil || !os.SameFile(linkStatus, openedStatus) {
		return nil, errors.New("TLS material changed")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxTLSMaterialBytes+1))
	if err != nil || len(content) == 0 || len(content) > maxTLSMaterialBytes {
		return nil, errors.New("invalid TLS material")
	}
	return content, nil
}
