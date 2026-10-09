package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapters/slack"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// RunSetup is a finite initial branch of the server owner, not an alternate
// controller. Every ordinary restart goes through Run and OpenExisting.
func (operations *Operations) RunSetup(ctx context.Context, configPath, setupPath string) error {
	if err := rejectLegacyControlDatabase(operations.databasePath); err != nil {
		return err
	}
	platform, err := operations.platformProbe.Current(ctx)
	if err != nil || !supportedPlatform(platform) {
		return setupFailure(generated.ErrorCodeUnsupportedPlatform)
	}
	uid, err := currentServiceOwnerUID()
	if err != nil || uid == 0 {
		return setupFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	review, err := loadLocalSetup(ctx, setupPath, configPath, uid)
	if err != nil {
		return err
	}
	if review.request.DatabasePath != operations.databasePath {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	hostReader := operations.setupHostIdentity
	if hostReader == nil {
		hostReader = localSetupHostIdentity
	}
	host, err := hostReader(ctx)
	if err != nil {
		return err
	}
	if host != review.request.HostIdentityDigest {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	executable := operations.setupExecutable
	if executable == nil {
		executable = openLocalSetupExecutable
	}
	if err = verifyLocalSetupRelease(ctx, review, operations.build.ReleaseBuildID, platform, executable); err != nil {
		return err
	}
	if err = localSetupAbsent(operations.databasePath, uid); err != nil {
		return err
	}
	// A prior receipt is never trusted as an approval; absence must be explicit.
	if err = localSetupAbsent(setupPath+".approval.json", uid); err != nil {
		return err
	}
	resolver, closeResolver, err := newLocalSetupCredentialResolver(uid)
	if err != nil {
		return err
	}
	defer closeResolver.Close()
	transport := operations.acknowledgementTransport
	if transport == nil {
		transport, err = slack.NewHTTPTransport(&http.Client{Timeout: 10 * time.Second})
		if err != nil {
			return err
		}
	}
	pending, err := newPendingSetupApproval(review, time.Now)
	if err != nil {
		return err
	}
	// Receipt durability precedes successful Submit and provider acknowledgement.
	pending.persist = func(receiptCtx context.Context, approval store.InitialSetupApproval) error {
		receipt, err := json.Marshal(struct {
			Review   json.RawMessage            `json:"review"`
			Approval store.InitialSetupApproval `json:"approval"`
		}{review.canonical, approval})
		if err != nil {
			return setupFailure(generated.ErrorCodeIntegrityFailure)
		}
		return writeLocalSetupReceipt(receiptCtx, setupPath+".approval.json", uid, receipt)
	}
	p := review.slack
	adapter, err := slack.NewAdapter(slack.Config{AppTokenReference: credentialref.Reference{ID: p.AppTokenReference, Consumer: "slack-acknowledgement"}, BotTokenReference: credentialref.Reference{ID: p.BotTokenReference, Consumer: "slack-acknowledgement"}, WorkspaceID: p.WorkspaceID, SlackUserID: p.SlackUserID, HumanID: p.HumanID, AuthorityID: p.AuthorityID, ChannelID: p.ChannelID, ApproveActionID: p.ApproveActionID, RejectActionID: p.RejectActionID, ReconnectDelay: 250 * time.Millisecond, MaxReconnectDelay: time.Second}, resolver, transport, pending)
	if err != nil {
		return err
	}
	approvalCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { defer cancel(); done <- adapter.Run(approvalCtx) }()
	if err = adapter.Publish(approvalCtx, pending.Card()); err != nil {
		cancel()
		<-done
		return err
	}
	approval, err := pending.Wait(approvalCtx)
	cancel()
	<-done
	if err != nil {
		return err
	}
	if err = review.recheck(ctx, uid); err != nil {
		return err
	}
	host, err = hostReader(ctx)
	if err != nil {
		return err
	}
	if host != review.request.HostIdentityDigest {
		return setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	if err = verifyLocalSetupRelease(ctx, review, operations.build.ReleaseBuildID, platform, executable); err != nil {
		return err
	}
	if err = localSetupAbsent(operations.databasePath, uid); err != nil {
		return err
	}
	initial, err := review.initialSetup(approval)
	if err != nil {
		return err
	}
	if err = rejectLegacyControlDatabase(operations.databasePath); err != nil {
		return err
	}
	authority, err := operations.openStore(ctx, store.Config{DatabasePath: operations.databasePath, Mode: store.InitializeNew, ExpectedUID: uid, ToolVersion: operations.build.ToolVersion, BuildVersion: operations.build.ReleaseBuildID, InitialSetup: &initial})
	if err != nil {
		return err
	}
	return operations.serveAuthority(ctx, platform, review.profile, authority)
}
func (review localSetupReview) initialSetup(approval store.InitialSetupApproval) (store.InitialSetup, error) {
	var canonical store.InitialSetupReview
	if json.Unmarshal(review.canonical, &canonical) != nil {
		return store.InitialSetup{}, setupFailure(generated.ErrorCodeInputInvalid)
	}
	expiry, err := time.Parse(time.RFC3339Nano, review.request.ExpiresAt)
	if err != nil {
		return store.InitialSetup{}, setupFailure(generated.ErrorCodeInputInvalid)
	}
	result := store.InitialSetup{SetupID: review.request.SetupID, HumanID: review.request.InitialHumanID, ReviewDigest: review.digest, RequestDigest: canonical.RequestDigest, ReviewJSON: append([]byte(nil), review.canonical...), ExpiresAt: expiry, Approval: approval}
	for _, g := range review.request.InitialReadGrants {
		result.ReadGrants = append(result.ReadGrants, store.InitialReadGrant{Capability: g.Capability, ResourceKind: g.ResourceKind, ResourceID: g.ResourceID})
	}
	for _, g := range review.request.InitialEffectiveGrants {
		branch := g.Branch
		if branch == "none" {
			branch = ""
		}
		result.EffectiveGrants = append(result.EffectiveGrants, store.InitialEffectiveGrant{GrantID: g.GrantID, RoleID: g.RoleID, Action: g.Action, Capability: g.Capability, ResourceKind: g.ResourceKind, ResourceID: g.ResourceID, Branch: branch})
	}
	return result, nil
}
