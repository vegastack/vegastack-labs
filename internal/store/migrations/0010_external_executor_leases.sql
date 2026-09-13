-- Issue #69: exact external-executor lease renewal and nonce replay denial.
ALTER TABLE target_execution_leases
ADD COLUMN lease_kind TEXT NOT NULL DEFAULT 'central'
CHECK (lease_kind IN ('central','external'));

ALTER TABLE target_execution_leases
ADD COLUMN last_renewed_at TEXT;

ALTER TABLE target_execution_leases
ADD COLUMN renewal_count INTEGER NOT NULL DEFAULT 0
CHECK (renewal_count >= 0);

CREATE UNIQUE INDEX target_execution_leases_active_step_idx
ON target_execution_leases(step_id) WHERE status = 'active';

CREATE TABLE executor_lease_nonce_history (
    lease_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    nonce_digest TEXT NOT NULL UNIQUE
        CHECK (length(nonce_digest) = 71 AND substr(nonce_digest, 1, 7) = 'sha256:'),
    accepted_at TEXT NOT NULL,
    PRIMARY KEY (lease_id, sequence),
    FOREIGN KEY (lease_id) REFERENCES target_execution_leases(lease_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX executor_lease_nonce_history_lease_idx
ON executor_lease_nonce_history(lease_id, sequence);

-- External progress and terminal receipts are untrusted observations. They are
-- separate from the one-terminal-receipt central execution table from 0009.
CREATE TABLE external_execution_observations (
    receipt_id TEXT PRIMARY KEY CHECK (length(receipt_id) BETWEEN 1 AND 128),
    lease_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed','partial')),
    result_digest TEXT NOT NULL
        CHECK (length(result_digest) = 71 AND substr(result_digest, 1, 7) = 'sha256:'),
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (lease_id) REFERENCES target_execution_leases(lease_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES plan_runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (step_id) REFERENCES plan_run_steps(step_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX external_execution_observations_lease_idx
ON external_execution_observations(lease_id, recorded_at, receipt_id);

CREATE TRIGGER external_executor_lease_binding_immutable
BEFORE UPDATE ON target_execution_leases
WHEN NEW.lease_id != OLD.lease_id
  OR NEW.run_id != OLD.run_id
  OR NEW.step_id != OLD.step_id
  OR NEW.target_id != OLD.target_id
  OR NEW.binding_digest != OLD.binding_digest
  OR NEW.recovery_epoch != OLD.recovery_epoch
  OR NEW.claimed_at != OLD.claimed_at
  OR NEW.expires_at != OLD.expires_at
  OR NEW.maximum_expires_at != OLD.maximum_expires_at
  OR NEW.lease_kind != OLD.lease_kind
BEGIN
    SELECT RAISE(ABORT, 'executor lease binding is immutable');
END;

CREATE TRIGGER external_executor_lease_terminal
BEFORE UPDATE ON target_execution_leases
WHEN OLD.status != 'active'
  OR (OLD.status = 'active' AND NEW.status NOT IN ('active','released','expired','revoked'))
BEGIN
    SELECT RAISE(ABORT, 'invalid executor lease transition');
END;

CREATE TRIGGER executor_lease_nonce_history_no_update
BEFORE UPDATE ON executor_lease_nonce_history
BEGIN
    SELECT RAISE(ABORT, 'executor lease nonce history is append-only');
END;

CREATE TRIGGER external_execution_observations_no_update
BEFORE UPDATE ON external_execution_observations
BEGIN
    SELECT RAISE(ABORT, 'external execution observations are append-only');
END;
