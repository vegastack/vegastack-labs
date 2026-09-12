CREATE TABLE acknowledgement_requests (
    acknowledgement_id TEXT PRIMARY KEY CHECK (length(acknowledgement_id) BETWEEN 1 AND 128),
    plan_id TEXT NOT NULL UNIQUE,
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND substr(plan_digest, 1, 7) = 'sha256:'),
    target_digest TEXT NOT NULL CHECK (length(target_digest) = 71 AND substr(target_digest, 1, 7) = 'sha256:'),
    reason_digest TEXT NOT NULL CHECK (length(reason_digest) = 71 AND substr(reason_digest, 1, 7) = 'sha256:'),
    human_id TEXT NOT NULL CHECK (length(human_id) BETWEEN 1 AND 128),
    authority_id TEXT NOT NULL CHECK (length(authority_id) BETWEEN 1 AND 128),
    nonce_digest TEXT NOT NULL UNIQUE CHECK (length(nonce_digest) = 71 AND substr(nonce_digest, 1, 7) = 'sha256:'),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    expires_at TEXT NOT NULL CHECK (length(expires_at) BETWEEN 1 AND 64),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
    request_bytes BLOB NOT NULL,
    pending_bytes BLOB NOT NULL,
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    decided_at TEXT CHECK (decided_at IS NULL OR length(decided_at) BETWEEN 1 AND 64),
    consumed_at TEXT CHECK (consumed_at IS NULL OR length(consumed_at) BETWEEN 1 AND 64),
    FOREIGN KEY (plan_id) REFERENCES immutable_plans(plan_id) ON DELETE RESTRICT,
    CHECK ((status = 'pending' AND decided_at IS NULL) OR (status != 'pending' AND decided_at IS NOT NULL)),
    CHECK (consumed_at IS NULL OR status = 'approved')
) STRICT;

CREATE INDEX acknowledgement_requests_status_idx
ON acknowledgement_requests(status, expires_at, recovery_epoch);

CREATE TABLE acknowledgement_proofs (
    acknowledgement_id TEXT PRIMARY KEY,
    proof_digest TEXT NOT NULL UNIQUE CHECK (length(proof_digest) = 71 AND substr(proof_digest, 1, 7) = 'sha256:'),
    status TEXT NOT NULL CHECK (status IN ('approved', 'rejected', 'expired')),
    canonical_bytes BLOB NOT NULL,
    received_at TEXT NOT NULL CHECK (length(received_at) BETWEEN 1 AND 64),
    FOREIGN KEY (acknowledgement_id) REFERENCES acknowledgement_requests(acknowledgement_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER acknowledgement_requests_no_delete BEFORE DELETE ON acknowledgement_requests
BEGIN SELECT RAISE(ABORT, 'acknowledgement request is durable'); END;

CREATE TRIGGER acknowledgement_requests_terminal BEFORE UPDATE ON acknowledgement_requests
WHEN NEW.acknowledgement_id != OLD.acknowledgement_id
  OR NEW.plan_id != OLD.plan_id
  OR NEW.plan_digest != OLD.plan_digest
  OR NEW.target_digest != OLD.target_digest
  OR NEW.reason_digest != OLD.reason_digest
  OR NEW.human_id != OLD.human_id
  OR NEW.authority_id != OLD.authority_id
  OR NEW.nonce_digest != OLD.nonce_digest
  OR NEW.state_revision != OLD.state_revision
  OR NEW.recovery_epoch != OLD.recovery_epoch
  OR NEW.expires_at != OLD.expires_at
  OR NEW.request_bytes != OLD.request_bytes
  OR NEW.pending_bytes != OLD.pending_bytes
  OR NEW.created_at != OLD.created_at
  OR NOT (
    (OLD.status = 'pending' AND NEW.status IN ('approved', 'rejected', 'expired') AND OLD.decided_at IS NULL AND NEW.decided_at IS NOT NULL AND OLD.consumed_at IS NULL AND NEW.consumed_at IS NULL)
    OR
    (OLD.status = 'approved' AND NEW.status = 'approved' AND NEW.decided_at = OLD.decided_at AND OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL)
  )
BEGIN SELECT RAISE(ABORT, 'invalid acknowledgement transition'); END;

CREATE TRIGGER acknowledgement_proofs_no_update BEFORE UPDATE ON acknowledgement_proofs
BEGIN SELECT RAISE(ABORT, 'acknowledgement proof is immutable'); END;

CREATE TRIGGER acknowledgement_proofs_no_delete BEFORE DELETE ON acknowledgement_proofs
BEGIN SELECT RAISE(ABORT, 'acknowledgement proof is durable'); END;
