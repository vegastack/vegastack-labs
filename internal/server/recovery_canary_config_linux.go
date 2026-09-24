//go:build linux

package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const recoveryCanaryClientCertificateName = "recovery-canary-client.crt"
const recoveryCanaryClientKeyName = "recovery-canary-client.key"

func readSystemRecoveryCanaryCapabilityConfig() (recoveryCanaryCapabilityConfig, error) {
	blocked := func() (recoveryCanaryCapabilityConfig, error) {
		return recoveryCanaryCapabilityConfig{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capability", false)
	}
	path := systemRecoveryCanaryConfigPath
	parentFD, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return blocked()
	}
	defer unix.Close(parentFD)
	var parent unix.Stat_t
	if unix.Fstat(parentFD, &parent) != nil || parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Uid != 0 || parent.Mode&0o022 != 0 {
		return blocked()
	}
	fd, err := unix.Openat(parentFD, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return blocked()
	}
	file := os.NewFile(uintptr(fd), "recovery-canary-capabilities")
	if file == nil {
		_ = unix.Close(fd)
		return blocked()
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0o022 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > 64*1024 {
		return blocked()
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(raw) != int(stat.Size) {
		return blocked()
	}
	var config recoveryCanaryCapabilityConfig
	if json.Unmarshal(raw, &config) != nil {
		return blocked()
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, raw) {
		return blocked()
	}
	certificatePEM, err := readRecoveryCanaryCredential(recoveryCanaryClientCertificateName, 32*1024)
	if err != nil {
		return blocked()
	}
	keyPEM, err := readRecoveryCanaryCredential(recoveryCanaryClientKeyName, 32*1024)
	if err != nil {
		return blocked()
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	for index := range keyPEM {
		keyPEM[index] = 0
	}
	if err != nil || len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return blocked()
	}
	config.ClientCertificate = certificate
	return config, nil
}

func readRecoveryCanaryCredential(name string, max int) ([]byte, error) {
	directoryPath := os.Getenv("CREDENTIALS_DIRECTORY")
	if !filepath.IsAbs(directoryPath) || filepath.Clean(directoryPath) != directoryPath || filepath.Base(name) != name || max < 1 {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capability", false)
	}
	directoryFD, err := unix.Open(directoryPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(directoryFD)
	var directory unix.Stat_t
	uid := uint32(os.Geteuid())
	if unix.Fstat(directoryFD, &directory) != nil || directory.Mode&unix.S_IFMT != unix.S_IFDIR || directory.Uid != uid || directory.Mode&0o077 != 0 {
		return nil, failure.New(generated.ErrorCodeAuthorizationDenied, "recovery-canary-capability", false)
	}
	fd, err := unix.Openat(directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "recovery-canary-client-credential")
	if file == nil {
		_ = unix.Close(fd)
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capability", false)
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uid || stat.Mode&0o077 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > int64(max) {
		return nil, failure.New(generated.ErrorCodeAuthorizationDenied, "recovery-canary-capability", false)
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil || len(raw) != int(stat.Size) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-capability", false)
	}
	return raw, nil
}
