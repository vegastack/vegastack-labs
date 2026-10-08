package store

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"time"
)

type InitialReadGrant struct{ Capability, ResourceKind, ResourceID string }
type InitialEffectiveGrant struct{ GrantID, RoleID, Action, Capability, ResourceKind, ResourceID, Branch string }
type InitialSetupApproval struct {
	HumanID, AuthorityID, Method, ReviewDigest, RequestDigest string
	DecidedAt                                                 time.Time
}
type InitialSetup struct {
	SetupID, HumanID, ReviewDigest, RequestDigest string
	ReadGrants                                    []InitialReadGrant
	EffectiveGrants                               []InitialEffectiveGrant
	ReviewJSON                                    []byte
	ExpiresAt                                     time.Time
	Approval                                      InitialSetupApproval
}

// InitialAcknowledgementBinding preserves the exact reviewed external mapping
// without giving the storage owner provider-specific identifier semantics.
type InitialAcknowledgementBinding struct {
	HumanID           string `json:"humanId"`
	AuthorityID       string `json:"authorityId"`
	Method            string `json:"method"`
	ProfileDigest     string `json:"profileDigest"`
	ExternalScopeID   string `json:"externalScopeId"`
	ExternalSubjectID string `json:"externalSubjectId"`
	DeliveryTargetID  string `json:"deliveryTargetId"`
}
type InitialSetupReview struct {
	Request         generated.LocalSetupReviewRequest `json:"request"`
	RequestDigest   string                            `json:"requestDigest"`
	Acknowledgement InitialAcknowledgementBinding     `json:"acknowledgement"`
}
