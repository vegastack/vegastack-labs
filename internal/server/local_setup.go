package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"github.com/vegastack/vegastack-labs/internal/strictjson"
)

const maxLocalSetupBytes = 32 << 10

type localSetupReview struct {
	request          generated.LocalSetupRequest
	profile          serverconfig.Profile
	slack            slackAcknowledgementProfile
	canonical        []byte
	readable, digest string
	frozen           map[string]string
}

func setupFailure(code string) error { return failure.New(code, "local-setup", false) }
func setupSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateLocalSetupRequest(request generated.LocalSetupRequest, now time.Time) error {
	raw, err := json.Marshal(request)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDLocalSetupRequest, raw, generated.ContractExact) != nil {
		return setupFailure(generated.ErrorCodeInputInvalid)
	}
	expires, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil || !expires.After(now) || expires.After(now.Add(24*time.Hour)) || request.ServiceUID != request.InitialAdministratorUID || request.ServiceUID <= 0 || request.ServiceUID > int64(^uint32(0)) {
		return setupFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	if len(request.RequestNonce) < 32 || strings.TrimSpace(request.RequestNonce) != request.RequestNonce {
		return setupFailure(generated.ErrorCodeInputInvalid)
	}
	for _, path := range []string{request.DatabasePath, request.ReleaseManifestPath, request.ReleasePolicyPath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
			return setupFailure(generated.ErrorCodeInputInvalid)
		}
	}
	seen := map[string]bool{}
	for _, g := range request.InitialReadGrants {
		if !authorization.ValidIdentifier(g.Capability) || !authorization.ValidIdentifier(g.ResourceKind) || !authorization.ValidIdentifier(g.ResourceID) {
			return setupFailure(generated.ErrorCodeInputInvalid)
		}
		key := g.Capability + "\x00" + g.ResourceKind + "\x00" + g.ResourceID
		if seen[key] {
			return setupFailure(generated.ErrorCodeInputInvalid)
		}
		seen[key] = true
	}
	seen = map[string]bool{}
	ids := map[string]bool{}
	for _, g := range request.InitialEffectiveGrants {
		if !authorization.ValidAuthorizationTarget(authorization.Target{Capability: g.Capability, ResourceKind: g.ResourceKind, ResourceID: g.ResourceID}) || !authorization.ValidIdentifier(g.GrantID) || ids[g.GrantID] {
			return setupFailure(generated.ErrorCodeInputInvalid)
		}
		if ((g.Action == "read" || g.Action == "author") && g.Branch != "none") || ((g.Action == "acknowledge" || g.Action == "execute") && g.Branch != "human") {
			return setupFailure(generated.ErrorCodeInputInvalid)
		}
		key := g.RoleID + "\x00" + g.Action + "\x00" + g.Capability + "\x00" + g.ResourceKind + "\x00" + g.ResourceID + "\x00" + g.Branch
		if seen[key] {
			return setupFailure(generated.ErrorCodeInputInvalid)
		}
		seen[key] = true
		ids[g.GrantID] = true
	}
	return nil
}

func loadLocalSetup(ctx context.Context, setupPath, profilePath string, uid uint32) (localSetupReview, error) {
	var out localSetupReview
	raw, err := readLocalSetupProtected(ctx, setupPath, uid, maxLocalSetupBytes)
	if err != nil {
		return out, err
	}
	if generated.ValidateContractJSON(generated.SchemaIDLocalSetupRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &out.request) != nil {
		return out, setupFailure(generated.ErrorCodeInputInvalid)
	}
	if err = validateLocalSetupRequest(out.request, time.Now()); err != nil {
		return out, err
	}
	if out.request.ServiceUID != int64(uid) {
		return out, setupFailure(generated.ErrorCodeAuthorizationDenied)
	}
	profileRaw, err := readLocalSetupProtected(ctx, profilePath, uid, 64<<10)
	if err != nil {
		return out, err
	}
	if setupSHA256(profileRaw) != out.request.ProfileSHA256 {
		return out, setupFailure(generated.ErrorCodeIntegrityFailure)
	}
	// The existing loader supplies all ordinary server profile semantics. Recheck
	// the protected bytes afterward so the approved snapshot cannot drift.
	out.profile, err = serverconfig.DecodeProfile(profileRaw, uid)
	if err != nil {
		return out, err
	}
	if out.profile.RemoteRead.Enabled || out.profile.ConstrainedSSH != nil || out.profile.ScheduledRunner != nil || out.profile.LocalBackup != nil || out.profile.OffsiteBackup != nil || out.profile.AcknowledgementAdapterConfigPath == "" {
		return out, setupFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	bound := false
	for _, binding := range out.profile.PrincipalBindings {
		if binding.UID == uid && binding.PrincipalID == out.request.InitialHumanID {
			bound = true
		}
	}
	if !bound {
		return out, setupFailure(generated.ErrorCodeAuthorizationDenied)
	}
	slackPath := out.profile.AcknowledgementAdapterConfigPath
	slackRaw, err := readLocalSetupProtected(ctx, slackPath, uid, maxSlackAcknowledgementConfigBytes)
	if err != nil {
		return out, err
	}
	if strictjson.Scan(ctx, slackRaw, strictjson.Limits{MaxDepth: 8}) != nil {
		return out, setupFailure(generated.ErrorCodeInputInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(slackRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out.slack) != nil || decoder.Decode(&struct{}{}) != io.EOF || out.slack.HumanID != out.request.InitialHumanID {
		return out, setupFailure(generated.ErrorCodeAuthorizationDenied)
	}
	if err = validateSetupSlackProfile(out.slack); err != nil {
		return out, err
	}
	out.frozen = map[string]string{setupPath: setupSHA256(raw), profilePath: setupSHA256(profileRaw), slackPath: setupSHA256(slackRaw)}
	for path, digest := range map[string]string{out.request.ReleaseManifestPath: out.request.ReleaseManifestDigest, out.request.ReleasePolicyPath: out.request.ReleasePolicyDigest} {
		value, e := readLocalSetupProtected(ctx, path, uid, 1<<20)
		if e != nil {
			return out, e
		}
		if setupSHA256(value) != digest {
			return out, setupFailure(generated.ErrorCodeIntegrityFailure)
		}
		out.frozen[path] = digest
	}
	requestRaw, _ := json.Marshal(out.request)
	var reviewRequest generated.LocalSetupReviewRequest
	// The review stores a fingerprint of the local request nonce, never the
	// original nonce or the per-attempt Slack challenge.
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(requestRaw, &fields)
	delete(fields, "requestNonce")
	fields["schema"], _ = json.Marshal(generated.SchemaIDLocalSetupReviewRequest)
	fields["requestNonceDigest"], _ = json.Marshal(setupSHA256([]byte(out.request.RequestNonce)))
	sanitized, _ := json.Marshal(fields)
	if json.Unmarshal(sanitized, &reviewRequest) != nil {
		return out, setupFailure(generated.ErrorCodeInputInvalid)
	}
	review := store.InitialSetupReview{Request: reviewRequest, RequestDigest: setupSHA256(raw), Acknowledgement: store.InitialAcknowledgementBinding{ProfileDigest: setupSHA256(slackRaw), ExternalScopeID: out.slack.WorkspaceID, ExternalSubjectID: out.slack.SlackUserID, HumanID: out.slack.HumanID, AuthorityID: out.slack.AuthorityID, DeliveryTargetID: out.slack.ChannelID, Method: identity.SlackSocketModeMethod}}
	out.canonical, err = json.Marshal(review)
	if err != nil {
		return out, setupFailure(generated.ErrorCodeInputInvalid)
	}
	out.digest = setupSHA256(out.canonical)
	var pretty bytes.Buffer
	if json.Indent(&pretty, out.canonical, "", "  ") != nil {
		return out, setupFailure(generated.ErrorCodeInputInvalid)
	}
	out.readable = fmt.Sprintf("Initialize this local control service only. No host admission or recovery qualification.\nSlack mapping: externalScopeId = workspace; externalSubjectId = user; deliveryTargetId = channel.\nReview digest: %s\n%s", out.digest, pretty.String())
	if len(out.readable) > maxLocalSetupBytes {
		return out, setupFailure(generated.ErrorCodeInputInvalid)
	}
	if err = out.recheck(ctx, uid); err != nil {
		return out, err
	}
	return out, nil
}
func (review localSetupReview) recheck(ctx context.Context, uid uint32) error {
	for path, digest := range review.frozen {
		raw, err := readLocalSetupProtected(ctx, path, uid, 1<<20)
		if err != nil {
			return err
		}
		if setupSHA256(raw) != digest {
			return setupFailure(generated.ErrorCodeIntegrityFailure)
		}
	}
	return validateLocalSetupRequest(review.request, time.Now())
}
func validateSetupSlackProfile(p slackAcknowledgementProfile) error {
	for _, v := range []string{p.WorkspaceID, p.SlackUserID, p.HumanID, p.AuthorityID, p.ChannelID, p.ApproveActionID, p.RejectActionID, p.AppTokenReference, p.BotTokenReference, p.NonceKeyReference} {
		if v == "" || len(v) > 128 || strings.ContainsAny(v, "\x00\r\n") {
			return setupFailure(generated.ErrorCodeInputInvalid)
		}
	}
	if p.ApproveActionID == p.RejectActionID || p.AppTokenReference == p.BotTokenReference || p.NonceKeyReference == p.AppTokenReference || p.NonceKeyReference == p.BotTokenReference {
		return setupFailure(generated.ErrorCodeInputInvalid)
	}
	return nil
}
