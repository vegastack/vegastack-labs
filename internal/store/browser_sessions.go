package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const (
	BrowserSessionIdleLimit     = 15 * time.Minute
	BrowserSessionAbsoluteLimit = 8 * time.Hour
)

type BrowserSessionStatus string

const (
	BrowserSessionActive    BrowserSessionStatus = "active"
	BrowserSessionRotated   BrowserSessionStatus = "rotated"
	BrowserSessionLoggedOut BrowserSessionStatus = "logged-out"
	BrowserSessionRevoked   BrowserSessionStatus = "revoked"
	BrowserSessionExpired   BrowserSessionStatus = "expired"
)

type BrowserSession struct {
	Digest            string
	BindingDigest     string
	PrincipalID       string
	Status            BrowserSessionStatus
	RecoveryEpoch     int64
	GrantRevision     int64
	IssuedAt          time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	ExternalExpiresAt time.Time
}

type BrowserSessionCreate struct {
	Principal         identity.Principal
	BindingDigest     string
	ExternalExpiresAt time.Time
}

type BrowserSessionStore interface {
	ResolveRemoteIdentity(context.Context, string) (identity.Principal, error)
	CreateBrowserSession(context.Context, BrowserSessionCreate) (BrowserSession, string, error)
	ValidateAndTouchBrowserSession(context.Context, string, string, time.Time) (BrowserSession, error)
	RenewBrowserSession(context.Context, string, string, time.Time) (BrowserSession, string, error)
	LogoutBrowserSession(context.Context, string, string) error
}

func BrowserSessionDigest(raw string) (string, error) {
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(raw)
	if decodeErr != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return "", newStoreError(generated.ErrorCodeAuthenticationRequired, "browser-session", false, nil)
	}
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (store *Store) ResolveRemoteIdentity(ctx context.Context, bindingDigest string) (identity.Principal, error) {
	if !validSessionDigest(bindingDigest) {
		return identity.Principal{}, authenticationStoreError()
	}
	principal := identity.Principal{Method: identity.CloudflareAccessMethod}
	err := store.Read(ctx, func(tx ReadTx) error {
		var bindingStatus, principalStatus string
		var revision int64
		if err := tx.queryRow(ctx, `SELECT b.principal_id,b.status,p.status,p.grant_revision FROM remote_identity_bindings b JOIN read_principals p ON p.principal_id=b.principal_id WHERE b.binding_digest=?`, bindingDigest).Scan(&principal.ID, &bindingStatus, &principalStatus, &revision); err != nil {
			return err
		}
		if bindingStatus != "active" || principalStatus != "active" || revision <= 0 || !identity.ValidPrincipal(principal) {
			return sql.ErrNoRows
		}
		return nil
	})
	if err != nil {
		return identity.Principal{}, authenticationStoreError()
	}
	return principal, nil
}

func (store *Store) CreateBrowserSession(ctx context.Context, request BrowserSessionCreate) (BrowserSession, string, error) {
	now := store.config.Clock().UTC()
	if !identity.ValidPrincipal(request.Principal) || request.Principal.Method != identity.CloudflareAccessMethod || !validSessionDigest(request.BindingDigest) || !request.ExternalExpiresAt.After(now) {
		return BrowserSession{}, "", authenticationStoreError()
	}
	raw, digest, err := newBrowserSessionID()
	if err != nil {
		return BrowserSession{}, "", newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-random", false, nil)
	}
	session := BrowserSession{Digest: digest, BindingDigest: request.BindingDigest, PrincipalID: request.Principal.ID, Status: BrowserSessionActive, IssuedAt: now, LastSeenAt: now, ExternalExpiresAt: request.ExternalExpiresAt.UTC()}
	session.AbsoluteExpiresAt = earliestTime(now.Add(BrowserSessionAbsoluteLimit), session.ExternalExpiresAt)
	session.IdleExpiresAt = earliestTime(now.Add(BrowserSessionIdleLimit), session.AbsoluteExpiresAt)
	auditRequest, err := browserSessionAudit("created", request.Principal, digest, nil, audit.Fingerprint(digest))
	if err != nil {
		return BrowserSession{}, "", newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-audit", false, nil)
	}
	result, err := store.executeAuditIntent(ctx, auditRequest, false, func(ctx context.Context, tx *sql.Tx) error {
		var bindingPrincipal, bindingStatus, principalStatus string
		if err := tx.QueryRowContext(ctx, `SELECT b.principal_id,b.status,p.status,p.grant_revision,m.recovery_epoch FROM remote_identity_bindings b JOIN read_principals p ON p.principal_id=b.principal_id CROSS JOIN system_meta m WHERE b.binding_digest=? AND m.id=1`, request.BindingDigest).Scan(&bindingPrincipal, &bindingStatus, &principalStatus, &session.GrantRevision, &session.RecoveryEpoch); err != nil {
			return authenticationStoreError()
		}
		if bindingPrincipal != request.Principal.ID || bindingStatus != "active" || principalStatus != "active" || session.GrantRevision <= 0 {
			return authenticationStoreError()
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO browser_sessions(session_digest,binding_digest,principal_id,status,recovery_epoch,grant_revision,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,external_expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, session.Digest, session.BindingDigest, session.PrincipalID, session.Status, session.RecoveryEpoch, session.GrantRevision, formatSessionTime(session.IssuedAt), formatSessionTime(session.LastSeenAt), formatSessionTime(session.IdleExpiresAt), formatSessionTime(session.AbsoluteExpiresAt), formatSessionTime(session.ExternalExpiresAt))
		return err
	})
	if err != nil || !result.Created {
		return BrowserSession{}, "", sessionOperationError(err)
	}
	return session, raw, nil
}

func (store *Store) ValidateAndTouchBrowserSession(ctx context.Context, raw, bindingDigest string, externalExpiresAt time.Time) (BrowserSession, error) {
	digest, err := BrowserSessionDigest(raw)
	if err != nil || !validSessionDigest(bindingDigest) {
		return BrowserSession{}, authenticationStoreError()
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForTransaction(ctx); err != nil {
		return BrowserSession{}, err
	}
	tx, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return BrowserSession{}, store.transactionError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	session, err := loadActiveBrowserSession(ctx, tx, digest, bindingDigest)
	if err != nil || !sessionCurrent(session, store.config.Clock().UTC(), externalExpiresAt) {
		return BrowserSession{}, authenticationStoreError()
	}
	now := store.config.Clock().UTC()
	session.LastSeenAt = now
	session.IdleExpiresAt = earliestTime(now.Add(BrowserSessionIdleLimit), session.AbsoluteExpiresAt, session.ExternalExpiresAt, externalExpiresAt.UTC())
	result, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET last_seen_at=?,idle_expires_at=? WHERE session_digest=? AND status='active'`, formatSessionTime(session.LastSeenAt), formatSessionTime(session.IdleExpiresAt), digest)
	if err != nil {
		return BrowserSession{}, store.transactionError(ctx, err)
	}
	if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
		return BrowserSession{}, authenticationStoreError()
	}
	if err := store.checkIdentity(ctx); err != nil {
		return BrowserSession{}, err
	}
	if err := tx.Commit(); err != nil {
		return BrowserSession{}, store.transactionError(ctx, err)
	}
	return session, nil
}

func (store *Store) RenewBrowserSession(ctx context.Context, raw, bindingDigest string, externalExpiresAt time.Time) (BrowserSession, string, error) {
	oldDigest, err := BrowserSessionDigest(raw)
	if err != nil || !validSessionDigest(bindingDigest) {
		return BrowserSession{}, "", authenticationStoreError()
	}
	nextRaw, nextDigest, err := newBrowserSessionID()
	if err != nil {
		return BrowserSession{}, "", newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-random", false, nil)
	}
	resolved, resolveErr := store.ResolveRemoteIdentity(ctx, bindingDigest)
	if resolveErr != nil {
		return BrowserSession{}, "", authenticationStoreError()
	}
	principal := resolved
	auditRequest, err := browserSessionAudit("renewed", principal, oldDigest, auditFingerprintPointer(oldDigest), audit.Fingerprint(nextDigest))
	if err != nil {
		return BrowserSession{}, "", newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-audit", false, nil)
	}
	var replacement BrowserSession
	result, err := store.executeAuditIntent(ctx, auditRequest, false, func(ctx context.Context, tx *sql.Tx) error {
		current, err := loadActiveBrowserSession(ctx, tx, oldDigest, bindingDigest)
		if err != nil || current.PrincipalID != principal.ID || !sessionCurrent(current, store.config.Clock().UTC(), externalExpiresAt) {
			return authenticationStoreError()
		}
		now := store.config.Clock().UTC()
		replacement = current
		replacement.Digest = nextDigest
		replacement.Status = BrowserSessionActive
		replacement.LastSeenAt = now
		replacement.ExternalExpiresAt = externalExpiresAt.UTC()
		replacement.IdleExpiresAt = earliestTime(now.Add(BrowserSessionIdleLimit), current.AbsoluteExpiresAt, replacement.ExternalExpiresAt)
		updated, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET status='rotated',replaced_by_digest=?,ended_at=?,end_reason='renewed' WHERE session_digest=? AND status='active'`, nextDigest, formatSessionTime(now), oldDigest)
		if err != nil {
			return err
		}
		if rows, rowsErr := updated.RowsAffected(); rowsErr != nil || rows != 1 {
			return authenticationStoreError()
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO browser_sessions(session_digest,binding_digest,principal_id,status,recovery_epoch,grant_revision,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,external_expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, replacement.Digest, replacement.BindingDigest, replacement.PrincipalID, replacement.Status, replacement.RecoveryEpoch, replacement.GrantRevision, formatSessionTime(replacement.IssuedAt), formatSessionTime(replacement.LastSeenAt), formatSessionTime(replacement.IdleExpiresAt), formatSessionTime(replacement.AbsoluteExpiresAt), formatSessionTime(replacement.ExternalExpiresAt))
		return err
	})
	if err != nil || !result.Created {
		return BrowserSession{}, "", sessionOperationError(err)
	}
	return replacement, nextRaw, nil
}

func (store *Store) LogoutBrowserSession(ctx context.Context, raw, bindingDigest string) error {
	digest, err := BrowserSessionDigest(raw)
	if err != nil || !validSessionDigest(bindingDigest) {
		return authenticationStoreError()
	}
	principal, err := store.ResolveRemoteIdentity(ctx, bindingDigest)
	if err != nil {
		return authenticationStoreError()
	}
	request, err := browserSessionAudit("logged-out", principal, digest, auditFingerprintPointer(digest), audit.Fingerprint(digest))
	if err != nil {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-audit", false, nil)
	}
	_, err = store.executeAuditIntent(ctx, request, false, func(ctx context.Context, tx *sql.Tx) error {
		now := formatSessionTime(store.config.Clock().UTC())
		result, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET status='logged-out',ended_at=?,end_reason='local-logout' WHERE session_digest=? AND binding_digest=? AND principal_id=? AND status='active'`, now, digest, bindingDigest, principal.ID)
		if err != nil {
			return err
		}
		if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
			return authenticationStoreError()
		}
		return nil
	})
	return sessionOperationError(err)
}

func (store *Store) RevokeBrowserSessions(ctx context.Context, principal identity.Principal, reason string) error {
	if !identity.ValidPrincipal(principal) || principal.Method != identity.CloudflareAccessMethod || (reason != "principal-revoked" && reason != "grant-revoked" && reason != "emergency-revocation") {
		return newStoreError(generated.ErrorCodeInputInvalid, "browser-session-revocation", false, nil)
	}
	target := sessionFingerprint("principal", principal.ID)
	request, err := browserSessionAudit("revoked", principal, target, nil, audit.Fingerprint(target))
	if err != nil {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-audit", false, nil)
	}
	_, err = store.executeAuditIntent(ctx, request, false, func(ctx context.Context, tx *sql.Tx) error {
		now := formatSessionTime(store.config.Clock().UTC())
		_, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET status='revoked',ended_at=?,end_reason=? WHERE principal_id=? AND status='active'`, now, reason, principal.ID)
		return err
	})
	return sessionOperationError(err)
}

func (store *Store) AuditBrowserSessionDenial(ctx context.Context, principal identity.Principal, reason string) error {
	if !identity.ValidPrincipal(principal) || reason != "session-invalid" {
		return newStoreError(generated.ErrorCodeInputInvalid, "browser-session-denial", false, nil)
	}
	_, target, err := newBrowserSessionID()
	if err != nil {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-random", false, nil)
	}
	after := audit.Fingerprint(sessionFingerprint("browser-session-denial", reason))
	request, err := browserSessionAudit("denied", principal, target, nil, after)
	if err != nil {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-audit", false, nil)
	}
	_, err = store.executeAuditIntent(ctx, request, false, func(context.Context, *sql.Tx) error { return nil })
	return sessionOperationError(err)
}

func (store *Store) InvalidateBrowserSessionsForRecoveryEpoch(ctx context.Context, actor identity.Principal) error {
	if !identity.ValidPrincipal(actor) {
		return newStoreError(generated.ErrorCodeInputInvalid, "browser-session-invalidation", false, nil)
	}
	health, err := store.Health(ctx)
	if err != nil {
		return err
	}
	target := sessionFingerprint("recovery-epoch", strconv.FormatInt(health.Revision.RecoveryEpoch, 10))
	request, err := browserSessionAudit("invalidated", actor, target, nil, audit.Fingerprint(target))
	if err != nil {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-audit", false, nil)
	}
	_, err = store.executeAuditIntent(ctx, request, false, func(ctx context.Context, tx *sql.Tx) error {
		now := formatSessionTime(store.config.Clock().UTC())
		_, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET status='revoked',ended_at=?,end_reason='recovery-epoch' WHERE status='active' AND recovery_epoch != (SELECT recovery_epoch FROM system_meta WHERE id=1)`, now)
		return err
	})
	return sessionOperationError(err)
}

func loadActiveBrowserSession(ctx context.Context, tx *sql.Tx, digest, bindingDigest string) (BrowserSession, error) {
	var session BrowserSession
	var issued, seen, idle, absolute, external string
	var bindingStatus, principalStatus string
	var currentEpoch, currentGrant int64
	err := tx.QueryRowContext(ctx, `SELECT s.session_digest,s.binding_digest,s.principal_id,s.status,s.recovery_epoch,s.grant_revision,s.issued_at,s.last_seen_at,s.idle_expires_at,s.absolute_expires_at,s.external_expires_at,b.status,p.status,p.grant_revision,m.recovery_epoch FROM browser_sessions s JOIN remote_identity_bindings b ON b.binding_digest=s.binding_digest JOIN read_principals p ON p.principal_id=s.principal_id CROSS JOIN system_meta m WHERE s.session_digest=? AND s.binding_digest=? AND m.id=1`, digest, bindingDigest).Scan(&session.Digest, &session.BindingDigest, &session.PrincipalID, &session.Status, &session.RecoveryEpoch, &session.GrantRevision, &issued, &seen, &idle, &absolute, &external, &bindingStatus, &principalStatus, &currentGrant, &currentEpoch)
	if err != nil || session.Status != BrowserSessionActive || bindingStatus != "active" || principalStatus != "active" || currentGrant != session.GrantRevision || currentEpoch != session.RecoveryEpoch {
		return BrowserSession{}, authenticationStoreError()
	}
	values := []struct {
		encoded string
		target  *time.Time
	}{{issued, &session.IssuedAt}, {seen, &session.LastSeenAt}, {idle, &session.IdleExpiresAt}, {absolute, &session.AbsoluteExpiresAt}, {external, &session.ExternalExpiresAt}}
	for _, value := range values {
		parsed, parseErr := time.Parse(time.RFC3339Nano, value.encoded)
		if parseErr != nil {
			return BrowserSession{}, newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-time", false, nil)
		}
		*value.target = parsed.UTC()
	}
	return session, nil
}

func sessionCurrent(session BrowserSession, now, externalExpiry time.Time) bool {
	return session.Status == BrowserSessionActive && externalExpiry.After(now) && now.Before(session.IdleExpiresAt) && now.Before(session.AbsoluteExpiresAt) && now.Before(session.ExternalExpiresAt)
}

func newBrowserSessionID() (string, string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", err
	}
	raw := base64.RawURLEncoding.EncodeToString(bytes)
	digest, err := BrowserSessionDigest(raw)
	return raw, digest, err
}

func browserSessionAudit(action string, principal identity.Principal, target string, before *audit.Fingerprint, after audit.Fingerprint) (intentRequest, error) {
	attribution, err := audit.NewAttribution(principal, &principal, nil)
	if err != nil {
		return intentRequest{}, err
	}
	afterCopy := after
	key := sessionFingerprint("audit", action, target)
	return intentRequest{
		Idempotency: audit.IntentKey{Scope: "browser-session", KeyDigest: audit.Fingerprint(key), RequestDigest: audit.Fingerprint(key)},
		Event:       audit.EventDraft{Type: audit.EventType("identity.session-" + action), CorrelationID: "browser-session-" + strings.TrimPrefix(key, "sha256:")[:32], Attribution: attribution, Target: audit.Target{Kind: "browser-session", ID: target}, Before: before, After: &afterCopy},
	}, nil
}

func sessionFingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func auditFingerprintPointer(value string) *audit.Fingerprint {
	result := audit.Fingerprint(value)
	return &result
}

func earliestTime(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result.UTC()
}

func formatSessionTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func validSessionDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func authenticationStoreError() error {
	return newStoreError(generated.ErrorCodeAuthenticationRequired, "browser-session", false, sql.ErrNoRows)
}

func sessionOperationError(err error) error {
	if err == nil {
		return nil
	}
	if Code(err) != "" {
		return err
	}
	if errors.Is(err, sql.ErrNoRows) {
		return authenticationStoreError()
	}
	return databaseError(generated.ErrorCodeIntegrityFailure, err)
}

var _ BrowserSessionStore = (*Store)(nil)
