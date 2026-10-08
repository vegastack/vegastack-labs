package hostdiscovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func preloadedTargetRequest(t *testing.T) generated.HostDiscoveryTargetDraftRequest {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	mode, fingerprint := "preloaded-discovery", Digest("public-key")
	target := generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "synthetic", Revision: 1, Address: "127.0.0.1", Port: 2222, User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), ProfileID: "debian-13", CredentialReferenceID: "synthetic-key", MaterialVersion: "v1", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64", CredentialMode: &mode, CredentialPublicKeyDigest: &fingerprint}
	return generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "synthetic", ConsoleConfirmation: &generated.HostDiscoveryConsoleConfirmation{Schema: generated.SchemaIDHostDiscoveryConsoleConfirmation, SchemaVersion: "1.0.0", TargetDigest: Digest(target), Method: "administrator-verified-console"}}
}
func TestPreloadedDiscoveryRequiresExactConsoleBinding(t *testing.T) {
	for _, mutation := range []string{"valid", "changed-target", "missing-confirmation", "missing-key", "wrong-mode", "legacy-extra"} {
		t.Run(mutation, func(t *testing.T) {
			r := preloadedTargetRequest(t)
			switch mutation {
			case "changed-target":
				r.Target.Port++
			case "missing-confirmation":
				r.ConsoleConfirmation = nil
			case "missing-key":
				r.Target.CredentialPublicKeyDigest = nil
			case "wrong-mode":
				*r.Target.CredentialMode = "qualified-reference"
			case "legacy-extra":
				r.Target.CredentialMode = nil
			}
			err := ValidateConsoleConfirmation(r)
			if (err == nil) != (mutation == "valid") {
				t.Fatalf("validation %s: %v", mutation, err)
			}
		})
	}
}
func TestDiscoveryLegacyOptionalFieldsAbsent(t *testing.T) {
	r := preloadedTargetRequest(t)
	r.Target.CredentialMode = nil
	r.Target.CredentialPublicKeyDigest = nil
	r.ConsoleConfirmation = nil
	if err := ValidateConsoleConfirmation(r); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	for _, field := range []string{"credentialMode", "credentialPublicKeyDigest", "consoleConfirmation"} {
		if strings.Contains(string(b), field) {
			t.Fatal(field)
		}
	}
}
func TestDiscoveryRejectsUnknownNestedConfirmation(t *testing.T) {
	r := preloadedTargetRequest(t)
	b, _ := json.Marshal(r)
	b = []byte(strings.Replace(string(b), `"method":"administrator-verified-console"`, `"method":"administrator-verified-console","extra":true`, 1))
	if generated.ValidateContractJSON(generated.SchemaIDHostDiscoveryTargetDraftRequest, b, generated.ContractExact) == nil {
		t.Fatal("unknown confirmation field accepted")
	}
}
