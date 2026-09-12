//go:build linux

package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

func TestSlackAcknowledgementProductionCompositionUsesProtectedReferences(t *testing.T) {
	root := t.TempDir()
	credentials := filepath.Join(root, "credentials")
	if err := os.Mkdir(credentials, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"slack-app-token", "slack-bot-token", "slack-nonce-key"} {
		if err := os.WriteFile(filepath.Join(credentials, name), []byte("fixture-material-without-whitespace"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentials)
	configPath := filepath.Join(root, "slack.json")
	config := `{"workspaceId":"workspace-approved","slackUserId":"user-approved","humanId":"person-operator","authorityId":"authority-slack","channelId":"channel-approval","approveActionId":"action-approve","rejectActionId":"action-reject","appTokenReference":"slack-app-token","botTokenReference":"slack-bot-token","nonceKeyReference":"slack-nonce-key"}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := composeSlackAcknowledgement(context.Background(), configPath, uint32(os.Getuid()), &acknowledgement.Service{})
	if err != nil || runtime.scopes == nil || runtime.publisher == nil || runtime.background == nil {
		t.Fatalf("runtime = %#v, %v", runtime, err)
	}
}

func TestSlackAcknowledgementMappingRejectsLinksAndBroadPermissions(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "adapter.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedPath := filepath.Join(root, "linked.json")
	if err := os.Symlink(configPath, linkedPath); err != nil {
		t.Fatal(err)
	}
	if _, err := openProtectedSlackAcknowledgementProfile(linkedPath, uint32(os.Getuid())); err == nil {
		t.Fatal("linked mapping configuration accepted")
	}
	hardLinkPath := filepath.Join(root, "hard-linked.json")
	if err := os.Link(configPath, hardLinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := openProtectedSlackAcknowledgementProfile(configPath, uint32(os.Getuid())); err == nil {
		t.Fatal("multiply linked mapping configuration accepted")
	}
	broadPath := filepath.Join(root, "broad.json")
	if err := os.WriteFile(broadPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openProtectedSlackAcknowledgementProfile(broadPath, uint32(os.Getuid())); err == nil {
		t.Fatal("broad mapping configuration permissions accepted")
	}
}

func TestSystemdCredentialResolverRejectsLinksAndBroadPermissions(t *testing.T) {
	root := t.TempDir()
	validPath := filepath.Join(root, "valid-token")
	if err := os.WriteFile(validPath, []byte("fixture-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", root)
	resolver, err := newSystemdCredentialResolver(uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	reference := credentialref.Reference{ID: "valid-token", Consumer: "slack-acknowledgement"}
	if value, err := resolver.Resolve(context.Background(), reference); err != nil || string(value) != "fixture-token" {
		t.Fatalf("resolve = %q, %v", value, err)
	}
	if err := os.Symlink(validPath, filepath.Join(root, "linked-token")); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), credentialref.Reference{ID: "linked-token", Consumer: "slack-acknowledgement"}); err == nil {
		t.Fatal("linked credential accepted")
	}
	if err := os.Chmod(validPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(context.Background(), reference); err == nil {
		t.Fatal("broad credential permissions accepted")
	}
}
