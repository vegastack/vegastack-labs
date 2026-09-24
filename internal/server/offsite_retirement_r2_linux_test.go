//go:build linux

package server

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapters/r2"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
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

func TestR2RetirementVerifierZeroizesParentAndEverySurvivorKey(t *testing.T) {
	parent, _ := credentialref.NewValue([]byte("parent-secret"))
	keyA, _ := credentialref.NewValue([]byte("key-a-secret"))
	keyB, _ := credentialref.NewValue([]byte("key-b-secret"))
	parentCopy, keyACopy, keyBCopy := parent.Bytes(), keyA.Bytes(), keyB.Bytes()
	verifier := &labsR2SurvivorVerifier{parent: parent, repositoryKeys: map[string]*credentialref.Value{"key-a": keyA, "key-b": keyB}}
	if err := verifier.Close(); err != nil {
		t.Fatal(err)
	}
	for _, value := range [][]byte{parentCopy, keyACopy, keyBCopy} {
		for _, b := range value {
			if b != 0 {
				t.Fatal("retirement verifier credential copy was not zeroized")
			}
		}
	}
	if len(verifier.repositoryKeys) != 0 {
		t.Fatal("survivor key references retained after close")
	}
}
