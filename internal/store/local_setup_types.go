package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"time"
)

type InitialReadGrant struct{ Capability, ResourceKind, ResourceID string }
type InitialEffectiveGrant struct{ GrantID, RoleID, Action, Capability, ResourceKind, ResourceID, Branch string }
type InitialSetupApproval struct {
	HumanID, AuthorityID, ReviewDigest, RequestDigest string
	DecidedAt                                         time.Time
}
type InitialSetup struct {
	SetupID, HumanID, ReviewDigest, RequestDigest string
	ReadGrants                                    []InitialReadGrant
	EffectiveGrants                               []InitialEffectiveGrant
	ReviewJSON                                    []byte
	ExpiresAt                                     time.Time
	Approval                                      InitialSetupApproval
}
type InitialSetupReview struct {
	Request            generated.LocalSetupReviewRequest `json:"request"`
	RequestDigest      string                            `json:"requestDigest"`
	SlackProfileDigest string                            `json:"slackProfileDigest"`
	SlackWorkspaceID   string                            `json:"slackWorkspaceId"`
	SlackUserID        string                            `json:"slackUserId"`
	SlackHumanID       string                            `json:"slackHumanId"`
	SlackAuthorityID   string                            `json:"slackAuthorityId"`
	SlackChannelID     string                            `json:"slackChannelId"`
}
