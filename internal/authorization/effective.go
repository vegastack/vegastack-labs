package authorization

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/identity"
)

type Action string

const (
	ActionRead        Action = "read"
	ActionAuthor      Action = "author"
	ActionAcknowledge Action = "acknowledge"
	ActionExecute     Action = "execute"
)

type Role string

const (
	RoleReader                Role = "reader"
	RoleAuthor                Role = "author"
	RoleMaintainer            Role = "maintainer"
	RoleInfrastructureAdmin   Role = "infrastructure-admin"
	RoleControlPlaneAdmin     Role = "control-plane-admin"
	RolePreauthorizedExecutor Role = "preauthorized-executor"
)

type Branch string

const (
	BranchHuman         Branch = "human"
	BranchPreauthorized Branch = "preauthorized"
)

type EffectiveStatus string

const (
	EffectiveActive  EffectiveStatus = "active"
	EffectiveRevoked EffectiveStatus = "revoked"
)

type Target struct {
	Capability   string
	ResourceKind string
	ResourceID   string
}

type EffectiveGrant struct {
	Role          Role
	AllowedAction Action
	Capability    string
	ResourceKind  string
	ResourceID    string
	Branch        Branch
}

type EffectivePolicySnapshot struct {
	PrincipalID   string
	PrincipalKind identity.PrincipalKind
	Status        EffectiveStatus
	GrantRevision int64
	StateRevision int64
	RecoveryEpoch int64
	Grants        []EffectiveGrant
}

type EffectiveScope struct {
	PrincipalID   string
	Action        Action
	Capability    string
	ResourceKind  string
	ResourceID    string
	Role          Role
	GrantRevision int64
	StateRevision int64
	RecoveryEpoch int64
	ScopeDigest   string
}

func ValidAction(action Action) bool {
	switch action {
	case ActionRead, ActionAuthor, ActionAcknowledge, ActionExecute:
		return true
	default:
		return false
	}
}

func ValidRole(role Role) bool {
	switch role {
	case RoleReader, RoleAuthor, RoleMaintainer, RoleInfrastructureAdmin, RoleControlPlaneAdmin, RolePreauthorizedExecutor:
		return true
	default:
		return false
	}
}

func ValidBranch(branch Branch) bool { return branch == BranchHuman || branch == BranchPreauthorized }

func ValidIdentifier(value string) bool { return tokenPattern.MatchString(value) }

func ValidAuthorizationTarget(target Target) bool {
	return tokenPattern.MatchString(target.Capability) && tokenPattern.MatchString(target.ResourceKind) && tokenPattern.MatchString(target.ResourceID)
}

func scopeFingerprint(snapshot EffectivePolicySnapshot, grant EffectiveGrant, target Target) string {
	parts := []string{
		"effective-scope-v1", snapshot.PrincipalID, string(snapshot.PrincipalKind),
		string(grant.Role), string(grant.AllowedAction), target.Capability, target.ResourceKind,
		target.ResourceID, strconv.FormatInt(snapshot.GrantRevision, 10),
		strconv.FormatInt(snapshot.StateRevision, 10), strconv.FormatInt(snapshot.RecoveryEpoch, 10),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func BindEffectiveScope(snapshot EffectivePolicySnapshot, grant EffectiveGrant, target Target) (EffectiveScope, bool) {
	if snapshot.Status != EffectiveActive || snapshot.GrantRevision <= 0 || snapshot.StateRevision < 0 || snapshot.RecoveryEpoch < 0 ||
		!ValidIdentifier(snapshot.PrincipalID) || !identity.ValidPrincipalKind(snapshot.PrincipalKind) || !validEffectiveGrant(grant) ||
		!ValidAuthorizationTarget(target) || grant.Capability != target.Capability || grant.ResourceKind != target.ResourceKind || grant.ResourceID != target.ResourceID {
		return EffectiveScope{}, false
	}
	return EffectiveScope{
		PrincipalID: snapshot.PrincipalID, Action: grant.AllowedAction, Capability: target.Capability, ResourceKind: target.ResourceKind,
		ResourceID: target.ResourceID, Role: grant.Role, GrantRevision: snapshot.GrantRevision, StateRevision: snapshot.StateRevision,
		RecoveryEpoch: snapshot.RecoveryEpoch, ScopeDigest: scopeFingerprint(snapshot, grant, target),
	}, true
}

func validEffectiveGrant(grant EffectiveGrant) bool {
	if !ValidRole(grant.Role) || !ValidAction(grant.AllowedAction) || !tokenPattern.MatchString(grant.Capability) || !tokenPattern.MatchString(grant.ResourceKind) || !tokenPattern.MatchString(grant.ResourceID) {
		return false
	}
	if grant.AllowedAction == ActionRead || grant.AllowedAction == ActionAuthor {
		return grant.Branch == "" && grant.Role != RolePreauthorizedExecutor
	}
	if !ValidBranch(grant.Branch) {
		return false
	}
	if grant.Role == RolePreauthorizedExecutor {
		return grant.AllowedAction == ActionExecute && grant.Branch == BranchPreauthorized
	}
	return grant.Branch != BranchPreauthorized
}
