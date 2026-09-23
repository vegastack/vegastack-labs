package recoverydenial

import (
	"context"
	"errors"
	"regexp"
	"time"
)

var ErrDenialUnavailable = errors.New("direct denial unavailable")
var token = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
var digest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// A qualified adapter performs one safe direct operation under the former
// identity against an isolated target. Read-only observation or policy-row
// inspection does not implement this interface's security contract.
type Adapter interface {
	Probe(context.Context, Challenge) (Result, error)
}

type Challenge struct {
	ChallengeID      string
	Kind             string
	SubjectID        string
	TargetID         string
	AdapterID        string
	FormerIdentityID string
	ProbeID          string
	Deadline         time.Time
}

type Result struct {
	ChallengeID      string
	Kind             string
	SubjectID        string
	TargetID         string
	AdapterID        string
	FormerIdentityID string
	ProbeID          string
	ObserverID       string
	ResponseClass    string
	ResponseDigest   string
	ObservedAt       time.Time
	ExpiresAt        time.Time
	SessionExpiry    time.Time
	Denied           bool
}

// ValidateResult checks the public result shape and exact challenge. It does
// not qualify an adapter or assert that a real endpoint was probed.
func ValidateResult(ctx context.Context, challenge Challenge, result Result, now time.Time) error {
	if ctx == nil || ctx.Err() != nil || !token.MatchString(challenge.ChallengeID) || !token.MatchString(challenge.Kind) || !token.MatchString(challenge.SubjectID) || !token.MatchString(challenge.TargetID) || !token.MatchString(challenge.AdapterID) || !token.MatchString(challenge.FormerIdentityID) || !token.MatchString(challenge.ProbeID) || challenge.Deadline.IsZero() || now.After(challenge.Deadline) {
		return ErrDenialUnavailable
	}
	if result.ChallengeID != challenge.ChallengeID || result.Kind != challenge.Kind || result.SubjectID != challenge.SubjectID || result.TargetID != challenge.TargetID || result.AdapterID != challenge.AdapterID || result.FormerIdentityID != challenge.FormerIdentityID || result.ProbeID != challenge.ProbeID || !token.MatchString(result.ObserverID) || result.ObserverID == result.FormerIdentityID || result.ResponseClass != "direct-denial" || !digest.MatchString(result.ResponseDigest) || !result.Denied || result.ObservedAt.IsZero() || result.ObservedAt.After(now) || now.Sub(result.ObservedAt) > 60*time.Second || !now.Before(result.ExpiresAt) || result.ExpiresAt.After(challenge.Deadline) || !now.Before(result.SessionExpiry) || result.SessionExpiry.Before(result.ObservedAt) {
		return ErrDenialUnavailable
	}
	return nil
}
