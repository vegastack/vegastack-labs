package serverconfig

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/operations"
	"testing"
)

func TestNotificationPolicyRequiresExplicitRecipientsOwnersAndSeparatePurposes(t *testing.T) {
	g := generated.OperationsGithubDestination{ReferenceID: "ordinary-github"}
	p := generated.NotificationReadinessPolicy{Schema: generated.SchemaIDNotificationReadinessPolicy, SchemaVersion: "1.0.0", TargetID: "routes-test", PrimaryHumanID: "human-a", SecondaryHumanID: "human-b", PrimaryCredentialOwnerID: "owner-a", SecondaryCredentialOwnerID: "owner-b", PrimaryCredentialClass: "fine-grained-pat", SecondaryChannelID: "channel-selected", PrimaryReferenceID: "test-github", PrimaryMaterialVersion: "v1", SecondaryReferenceID: "test-slack", SecondaryMaterialVersion: "v1"}
	if _, e := freezeNotificationReadiness(&p, &g); e != nil {
		t.Fatal(e)
	}
	old := operations.NotificationPolicyDigest(p, g)
	p.SecondaryChannelID = "other-selected-channel"
	if operations.NotificationPolicyDigest(p, g) == old {
		t.Fatal("route change retained qualification digest")
	}
	p.PrimaryReferenceID = g.ReferenceID
	if _, e := freezeNotificationReadiness(&p, &g); e == nil {
		t.Fatal("ordinary delivery reference treated as canary purpose")
	}
	p.PrimaryReferenceID = "test-github"
	p.PrimaryHumanID = ""
	if _, e := freezeNotificationReadiness(&p, &g); e == nil {
		t.Fatal("missing named recipient accepted")
	}
}
