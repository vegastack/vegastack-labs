-- Issue #74: durable plan runs, steps, leases, receipts, and detail retention.
CREATE TABLE plan_runs (
    run_id TEXT PRIMARY KEY CHECK (length(run_id) BETWEEN 1 AND 128),
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND substr(plan_digest, 1, 7) = 'sha256:'),
    authorization_decision_id TEXT NOT NULL CHECK (length(authorization_decision_id) BETWEEN 1 AND 128),
    acknowledgement_id TEXT CHECK (acknowledgement_id IS NULL OR length(acknowledgement_id) BETWEEN 1 AND 128),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 32),
    executor_mode TEXT NOT NULL CHECK (executor_mode IN ('central','external')),
    executor_id TEXT NOT NULL CHECK (length(executor_id) BETWEEN 1 AND 128),
    executor_binding_digest TEXT NOT NULL CHECK (length(executor_binding_digest) = 71 AND substr(executor_binding_digest, 1, 7) = 'sha256:'),
    status TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed','partial','interrupted','cancelled')),
    cancellation_requested INTEGER NOT NULL CHECK (cancellation_requested IN (0,1)),
    rollback_status TEXT NOT NULL CHECK (rollback_status IN ('not-requested','required','separate-plan')),
    verification_status TEXT NOT NULL CHECK (verification_status IN ('pending','verified','failed','incomplete')),
    verification_digest TEXT CHECK (verification_digest IS NULL OR (length(verification_digest) = 71 AND substr(verification_digest, 1, 7) = 'sha256:')),
    changed INTEGER NOT NULL CHECK (changed IN (0,1)),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    submit_key_digest TEXT NOT NULL UNIQUE CHECK (length(submit_key_digest) = 71 AND substr(submit_key_digest, 1, 7) = 'sha256:'),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71 AND substr(request_digest, 1, 7) = 'sha256:'),
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (plan_id) REFERENCES immutable_plans(plan_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE plan_run_steps (
    step_id TEXT PRIMARY KEY CHECK (length(step_id) BETWEEN 1 AND 128),
    run_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    operation_type TEXT NOT NULL CHECK (length(operation_type) BETWEEN 1 AND 128),
    adapter_id TEXT NOT NULL CHECK (length(adapter_id) BETWEEN 1 AND 128),
    executor_id TEXT NOT NULL CHECK (length(executor_id) BETWEEN 1 AND 128),
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 128),
    input_digest TEXT NOT NULL CHECK (length(input_digest) = 71 AND substr(input_digest, 1, 7) = 'sha256:'),
    artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 71 AND substr(artifact_digest, 1, 7) = 'sha256:'),
    idempotent INTEGER NOT NULL CHECK (idempotent IN (0,1)),
    status TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed','partial','interrupted','cancelled')),
    effect_state TEXT NOT NULL CHECK (effect_state IN ('not-started','intent-recorded','receipt-recorded','verified','effect-unknown')),
    active_lease_id TEXT,
    result_digest TEXT CHECK (result_digest IS NULL OR (length(result_digest) = 71 AND substr(result_digest, 1, 7) = 'sha256:')),
    started_at TEXT,
    finished_at TEXT,
    UNIQUE (run_id, sequence),
    UNIQUE (run_id, operation_id),
    FOREIGN KEY (run_id) REFERENCES plan_runs(run_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE target_execution_leases (
    lease_id TEXT PRIMARY KEY CHECK (length(lease_id) BETWEEN 1 AND 128),
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 128),
    binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 71 AND substr(binding_digest, 1, 7) = 'sha256:'),
    nonce_digest TEXT NOT NULL CHECK (length(nonce_digest) = 71 AND substr(nonce_digest, 1, 7) = 'sha256:'),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    claimed_at TEXT NOT NULL,
    renew_after TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    maximum_expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','released','expired','revoked')),
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0),
    FOREIGN KEY (run_id) REFERENCES plan_runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (step_id) REFERENCES plan_run_steps(step_id) ON DELETE CASCADE
) STRICT;

CREATE UNIQUE INDEX target_execution_leases_active_target_idx
ON target_execution_leases(target_id) WHERE status = 'active';

CREATE TABLE execution_receipts (
    receipt_id TEXT PRIMARY KEY CHECK (length(receipt_id) BETWEEN 1 AND 128),
    lease_id TEXT NOT NULL UNIQUE,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running','succeeded','failed','partial')),
    result_digest TEXT NOT NULL CHECK (length(result_digest) = 71 AND substr(result_digest, 1, 7) = 'sha256:'),
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0),
    recorded_at TEXT NOT NULL,
    FOREIGN KEY (lease_id) REFERENCES target_execution_leases(lease_id) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES plan_runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (step_id) REFERENCES plan_run_steps(step_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE run_detail_events (
    detail_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    event_digest TEXT NOT NULL CHECK (length(event_digest) = 71 AND substr(event_digest, 1, 7) = 'sha256:'),
    occurred_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES plan_runs(run_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX run_detail_events_retention_idx ON run_detail_events(occurred_at, detail_event_id);
CREATE INDEX plan_runs_retention_idx ON plan_runs(updated_at, run_id);
CREATE INDEX plan_run_steps_run_idx ON plan_run_steps(run_id, sequence);

CREATE TRIGGER execution_receipts_no_update BEFORE UPDATE ON execution_receipts BEGIN SELECT RAISE(ABORT, 'execution receipts are append-only'); END;
