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
	ResolveExternalIdentity(context.Context, string) (identity.Principal, error)
	CreateBrowserSession(context.Context, BrowserSessionCreate) (BrowserSession, string, error)
	ValidateAndTouchBrowserSession(context.Context, string, string, time.Time) (BrowserSession, error)
	RenewBrowserSession(context.Context, string, string, time.Time) (BrowserSession, string, error)
	LogoutBrowserSession(context.Context, string, string) error
}

// ResolveExternalIdentity requires the remote binding to have a current,
// explicit non-human effective principal. Browser identity resolution remains
// backward-compatible and cannot accidentally upgrade a human session.
func (store *Store) ResolveExternalIdentity(ctx context.Context, bindingDigest string) (identity.Principal, error) {
	if !validSessionDigest(bindingDigest) {
		return identity.Principal{}, authenticationStoreError()
	}
	principal := identity.Principal{Method: identity.CloudflareAccessMethod}
	var kind string
	err := store.Read(ctx, func(tx ReadTx) error {
		var bindingStatus, readStatus, effectiveStatus string
		var readRevision, effectiveRevision int64
		if err := tx.queryRow(ctx, `SELECT b.principal_id,b.status,r.status,r.grant_revision,e.principal_kind,e.status,e.grant_revision FROM remote_identity_bindings b JOIN read_principals r ON r.principal_id=b.principal_id JOIN effective_authorization_principals e ON e.principal_id=b.principal_id WHERE b.binding_digest=?`, bindingDigest).Scan(&principal.ID, &bindingStatus, &readStatus, &readRevision, &kind, &effectiveStatus, &effectiveRevision); err != nil {
			return err
		}
		principal.Kind = identity.PrincipalKind(kind)
		if bindingStatus != "active" || readStatus != "active" || effectiveStatus != "active" || readRevision <= 0 || effectiveRevision <= 0 ||
			(identity.EffectivePrincipalKind(principal) != identity.PrincipalAgent && identity.EffectivePrincipalKind(principal) != identity.PrincipalPolicy) || !identity.ValidPrincipal(principal) {
			return sql.ErrNoRows
		}
		return nil
	})
	if err != nil {
		return identity.Principal{}, authenticationStoreError()
	}
	return principal, nil
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
	if err != nil {
		return BrowserSession{}, "", sessionOperationError(err)
	}
	if !result.Created {
		return BrowserSession{}, "", authenticationStoreError()
	}
	return session, raw, nil
}

func (store *Store) ValidateAndTouchBrowserSession(ctx context.Context, raw, bindingDigest string, externalExpiresAt time.Time) (BrowserSession, error) {
	digest, err := BrowserSessionDigest(raw)
	if err != nil || !validSessionDigest(bindingDigest) {
		return BrowserSession{}, authenticationStoreError()
	}
	var session BrowserSession
	var expired bool
	_, err = store.executePreparedBrowserSessionAudit(ctx, func(ctx context.Context, tx *sql.Tx) (preparedBrowserSessionAudit, error) {
		current, err := loadActiveBrowserSession(ctx, tx, digest, bindingDigest)
		if err != nil {
			return preparedBrowserSessionAudit{}, err
		}
		now := store.config.Clock().UTC()
		if reason, isExpired := browserSessionExpiryReason(current, now, externalExpiresAt); isExpired {
			expired = true
			return prepareBrowserSessionExpiry(current, digest, bindingDigest, reason, now)
		}
		session = current
		session.LastSeenAt = now
		session.IdleExpiresAt = earliestTime(now.Add(BrowserSessionIdleLimit), session.AbsoluteExpiresAt, session.ExternalExpiresAt, externalExpiresAt.UTC())
		return preparedBrowserSessionAudit{Business: func(ctx context.Context, tx *sql.Tx) error {
			result, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET last_seen_at=?,idle_expires_at=? WHERE session_digest=? AND status='active'`, formatSessionTime(session.LastSeenAt), formatSessionTime(session.IdleExpiresAt), digest)
			if err != nil {
				return err
			}
			if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
				return authenticationStoreError()
			}
			return nil
		}}, nil
	})
	if err != nil {
		return BrowserSession{}, sessionOperationError(err)
	}
	if expired {
		return BrowserSession{}, authenticationStoreError()
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
	var replacement BrowserSession
	var expired bool
	result, err := store.executePreparedBrowserSessionAudit(ctx, func(ctx context.Context, tx *sql.Tx) (preparedBrowserSessionAudit, error) {
		current, err := loadActiveBrowserSession(ctx, tx, oldDigest, bindingDigest)
		if err != nil || current.PrincipalID != principal.ID {
			return preparedBrowserSessionAudit{}, authenticationStoreError()
		}
		now := store.config.Clock().UTC()
		if reason, isExpired := browserSessionExpiryReason(current, now, externalExpiresAt); isExpired {
			expired = true
			return prepareBrowserSessionExpiry(current, oldDigest, bindingDigest, reason, now)
		}
		auditRequest, err := browserSessionAudit("renewed", principal, oldDigest, auditFingerprintPointer(oldDigest), audit.Fingerprint(nextDigest))
		if err != nil {
			return preparedBrowserSessionAudit{}, newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-audit", false, nil)
		}
		replacement = current
		replacement.Digest = nextDigest
		replacement.Status = BrowserSessionActive
		replacement.LastSeenAt = now
		replacement.ExternalExpiresAt = externalExpiresAt.UTC()
		replacement.IdleExpiresAt = earliestTime(now.Add(BrowserSessionIdleLimit), current.AbsoluteExpiresAt, replacement.ExternalExpiresAt)
		return preparedBrowserSessionAudit{Request: &auditRequest, Business: func(ctx context.Context, tx *sql.Tx) error {
			if _, insertErr := tx.ExecContext(ctx, `INSERT INTO browser_sessions(session_digest,binding_digest,principal_id,status,recovery_epoch,grant_revision,issued_at,last_seen_at,idle_expires_at,absolute_expires_at,external_expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, replacement.Digest, replacement.BindingDigest, replacement.PrincipalID, replacement.Status, replacement.RecoveryEpoch, replacement.GrantRevision, formatSessionTime(replacement.IssuedAt), formatSessionTime(replacement.LastSeenAt), formatSessionTime(replacement.IdleExpiresAt), formatSessionTime(replacement.AbsoluteExpiresAt), formatSessionTime(replacement.ExternalExpiresAt)); insertErr != nil {
				return insertErr
			}
			updated, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET status='rotated',replaced_by_digest=?,ended_at=?,end_reason='renewed' WHERE session_digest=? AND status='active'`, nextDigest, formatSessionTime(now), oldDigest)
			if err != nil {
				return err
			}
			if rows, rowsErr := updated.RowsAffected(); rowsErr != nil || rows != 1 {
				return authenticationStoreError()
			}
			return nil
		}}, nil
	})
	if err != nil {
		return BrowserSession{}, "", sessionOperationError(err)
	}
	if expired {
		return BrowserSession{}, "", authenticationStoreError()
	}
	if !result.Created {
		return BrowserSession{}, "", authenticationStoreError()
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
	_, err := store.executePreparedBrowserSessionAudit(ctx, func(ctx context.Context, tx *sql.Tx) (preparedBrowserSessionAudit, error) {
		generation, err := browserSessionGeneration(ctx, tx, principal.ID)
		if err != nil {
			return preparedBrowserSessionAudit{}, store.transactionError(ctx, err)
		}
		requestIdentity := sessionFingerprint("principal-revocation", principal.ID, strconv.FormatInt(generation, 10), reason)
		request, err := browserSessionAuditForRequest("revoked", principal, target, requestIdentity, nil, audit.Fingerprint(target))
		if err != nil {
			return preparedBrowserSessionAudit{}, newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-audit", false, nil)
		}
		return preparedBrowserSessionAudit{
			Request: &request,
			Business: func(ctx context.Context, tx *sql.Tx) error {
				now := formatSessionTime(store.config.Clock().UTC())
				_, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET status='revoked',ended_at=?,end_reason=? WHERE principal_id=? AND status='active'`, now, reason, principal.ID)
				return err
			},
			Postcondition: func(ctx context.Context, tx *sql.Tx) error {
				var active int
				if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM browser_sessions WHERE principal_id=? AND status='active'`, principal.ID).Scan(&active); err != nil {
					return err
				}
				if active != 0 {
					return newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-revocation-postcondition", false, nil)
				}
				return nil
			},
		}, nil
	})
	return sessionOperationError(err)
}

type preparedBrowserSessionAudit struct {
	Request       *intentRequest
	Business      func(context.Context, *sql.Tx) error
	Postcondition func(context.Context, *sql.Tx) error
}

type prepareBrowserSessionAudit func(context.Context, *sql.Tx) (preparedBrowserSessionAudit, error)

// executePreparedBrowserSessionAudit derives the idempotency request while the
// store write lock and transaction are already held. Session generations
// cannot change between dedupe selection and the guarded business mutation.
func (store *Store) executePreparedBrowserSessionAudit(ctx context.Context, prepare prepareBrowserSessionAudit) (intentResult, error) {
	if store == nil || prepare == nil {
		return intentResult{}, newStoreError(generated.ErrorCodeInputInvalid, "browser-session-audit", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForTransaction(ctx); err != nil {
		return intentResult{}, err
	}
	tx, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return intentResult{}, store.transactionError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()

	prepared, err := prepare(ctx, tx)
	if err != nil {
		return intentResult{}, store.preparedBrowserSessionAuditError(ctx, err)
	}
	var result intentResult
	if prepared.Request == nil {
		if prepared.Business == nil {
			return intentResult{}, newStoreError(generated.ErrorCodeInputInvalid, "browser-session-business", false, nil)
		}
		if err := prepared.Business(ctx, tx); err != nil {
			return intentResult{}, store.preparedBrowserSessionAuditError(ctx, err)
		}
	} else {
		if audit.ValidateIntentKey(prepared.Request.Idempotency) != nil || audit.ValidateEventDraft(prepared.Request.Event) != nil || audit.ValidateOutboxRequirements(prepared.Request.Destinations) != nil {
			return intentResult{}, newStoreError(generated.ErrorCodeInputInvalid, "browser-session-audit", false, nil)
		}
		result, err = store.appendAuditInTx(ctx, tx, *prepared.Request, false, prepared.Business)
		if err != nil {
			return intentResult{}, store.preparedBrowserSessionAuditError(ctx, err)
		}
	}
	if prepared.Postcondition != nil {
		if err := prepared.Postcondition(ctx, tx); err != nil {
			return intentResult{}, store.preparedBrowserSessionAuditError(ctx, err)
		}
	}
	if err := store.checkIdentity(ctx); err != nil {
		return intentResult{}, err
	}
	if prepared.Request != nil {
		if err := store.runAuditFault(auditBeforeCommit); err != nil {
			return intentResult{}, err
		}
		if store.beforeCommit != nil {
			if err := store.beforeCommit(); err != nil {
				store.enterSafeMode("commit-failure")
				return intentResult{}, databaseError(generated.ErrorCodeIntegrityFailure, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		store.enterSafeMode("commit-failure")
		return intentResult{}, store.transactionError(ctx, err)
	}
	if result.Created {
		store.events.signal()
	}
	if prepared.Request != nil {
		if err := store.runAuditFault(auditAfterCommit); err != nil {
			store.enterSafeMode("commit-uncertain")
			return intentResult{}, err
		}
	}
	return result, nil
}

func (store *Store) preparedBrowserSessionAuditError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return interruptedError("browser-session-audit", ctx.Err())
	}
	if Code(err) == generated.ErrorCodeIntegrityFailure {
		store.enterSafeMode("browser-session-audit-failure")
		return err
	}
	if Code(err) != "" {
		return err
	}
	return classifySQLiteError(ctx, err)
}

func prepareBrowserSessionExpiry(session BrowserSession, digest, bindingDigest, reason string, now time.Time) (preparedBrowserSessionAudit, error) {
	principal := identity.Principal{ID: session.PrincipalID, Method: identity.CloudflareAccessMethod}
	request, err := browserSessionAudit("expired", principal, digest, auditFingerprintPointer(digest), audit.Fingerprint(sessionFingerprint("expired", digest)))
	if err != nil {
		return preparedBrowserSessionAudit{}, newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-audit", false, nil)
	}
	return preparedBrowserSessionAudit{
		Request: &request,
		Business: func(ctx context.Context, tx *sql.Tx) error {
			result, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET status='expired',ended_at=?,end_reason=? WHERE session_digest=? AND binding_digest=? AND status='active'`, formatSessionTime(now), reason, digest, bindingDigest)
			if err != nil {
				return err
			}
			if rows, rowsErr := result.RowsAffected(); rowsErr != nil || rows != 1 {
				return authenticationStoreError()
			}
			return nil
		},
		Postcondition: func(ctx context.Context, tx *sql.Tx) error {
			var status, endedAt, storedReason string
			if err := tx.QueryRowContext(ctx, `SELECT status,ended_at,end_reason FROM browser_sessions WHERE session_digest=? AND binding_digest=?`, digest, bindingDigest).Scan(&status, &endedAt, &storedReason); err != nil {
				return err
			}
			if status != string(BrowserSessionExpired) || endedAt != formatSessionTime(now) || storedReason != reason {
				return newStoreError(generated.ErrorCodeIntegrityFailure, "browser-session-expiry-postcondition", false, nil)
			}
			return nil
		},
	}, nil
}

func browserSessionGeneration(ctx context.Context, tx *sql.Tx, principalID string) (int64, error) {
	var generation int64
	// Every supported session birth is paired atomically with one of these
	// append-only events. A later created or renewed session therefore always
	// advances the generation used by principal-wide revocation idempotency.
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(event_id),0) FROM (
SELECT e.event_id FROM audit_events e JOIN browser_sessions s ON s.session_digest=e.target_id WHERE e.event_type='identity.session-created' AND s.principal_id=?
UNION ALL
SELECT e.event_id FROM audit_events e JOIN browser_sessions s ON s.session_digest=e.after_fingerprint WHERE e.event_type='identity.session-renewed' AND s.principal_id=?
)`, principalID, principalID).Scan(&generation)
	return generation, err
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
	var recoveryEpoch int64
	if err := store.conn.QueryRowContext(ctx, `SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&recoveryEpoch); err != nil {
		return sessionOperationError(err)
	}
	target := sessionFingerprint("recovery-epoch", strconv.FormatInt(recoveryEpoch, 10))
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

func browserSessionExpiryReason(session BrowserSession, now, externalExpiry time.Time) (string, bool) {
	deadline := session.IdleExpiresAt
	reason := "idle-timeout"
	for _, candidate := range []struct {
		at     time.Time
		reason string
	}{
		{at: session.AbsoluteExpiresAt, reason: "absolute-timeout"},
		{at: session.ExternalExpiresAt, reason: "external-expiry"},
		{at: externalExpiry.UTC(), reason: "external-expiry"},
	} {
		if !candidate.at.After(deadline) {
			deadline = candidate.at
			reason = candidate.reason
		}
	}
	return reason, !now.Before(deadline)
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
	return browserSessionAuditForRequest(action, principal, target, target, before, after)
}

func browserSessionAuditForRequest(action string, principal identity.Principal, target, requestIdentity string, before *audit.Fingerprint, after audit.Fingerprint) (intentRequest, error) {
	attribution, err := audit.NewAttribution(principal, &principal, nil)
	if err != nil {
		return intentRequest{}, err
	}
	afterCopy := after
	key := sessionFingerprint("audit", action, requestIdentity)
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
