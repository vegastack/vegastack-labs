//go:build linux

package server

import (
	"github.com/vegastack/vegastack-labs/internal/adapters/r2"
	"testing"
)

func TestR2RetirementClientsZeroCredentialCopiesOnClose(t *testing.T) {
	rules := &boundR2Rules{bearer: []byte("lock-admin-secret")}
	access := []byte("access-secret")
	secret := []byte("secret-secret")
	token := []byte("token-secret")
	objects := &boundR2Objects{credentials: r2.S3Credentials{AccessKeyID: access, SecretAccessKey: secret, SessionToken: token}}
	ruleCopy := rules.bearer
	if err := rules.Close(); err != nil {
		t.Fatal(err)
	}
	if err := objects.Close(); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{ruleCopy, access, secret, token} {
		for _, b := range value {
			if b != 0 {
				t.Fatal("credential copy was not zeroized")
			}
		}
	}
	if rules.bearer != nil || objects.credentials.AccessKeyID != nil || objects.credentials.SecretAccessKey != nil || objects.credentials.SessionToken != nil {
		t.Fatal("credential references retained after close")
	}
}
