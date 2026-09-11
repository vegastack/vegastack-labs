//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoteListenRejectsLinkedLinuxTLSMaterial(t *testing.T) {
	certificatePath, keyPath := writeRemoteTestCertificate(t)
	hardLink := filepath.Join(filepath.Dir(keyPath), "hard-linked.key")
	if err := os.Link(keyPath, hardLink); err != nil {
		t.Fatal(err)
	}
	if listener, err := RemoteListen(context.Background(), RemoteListenConfig{Address: "127.0.0.1:0", CertificatePath: certificatePath, PrivateKeyPath: keyPath}); err == nil {
		_ = listener.Close()
		t.Fatal("multiply linked private key was accepted")
	}

	targetDirectory := filepath.Dir(keyPath)
	linkedDirectory := filepath.Join(t.TempDir(), "tls-link")
	if err := os.Symlink(targetDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if listener, err := RemoteListen(context.Background(), RemoteListenConfig{Address: "127.0.0.1:0", CertificatePath: filepath.Join(linkedDirectory, filepath.Base(certificatePath)), PrivateKeyPath: filepath.Join(linkedDirectory, filepath.Base(keyPath))}); err == nil {
		_ = listener.Close()
		t.Fatal("symlinked TLS directory was accepted")
	}
}
