-- Issue #108: inert, exact restore plans and append-only recovery history.
ALTER TABLE system_meta ADD COLUMN instance_id TEXT NOT NULL DEFAULT 'instance-uninitialized'
    CHECK (length(instance_id) BETWEEN 10 AND 128);
ALTER TABLE system_meta ADD COLUMN authority_mode TEXT NOT NULL DEFAULT 'ready'
    CHECK (authority_mode IN ('ready','recovery-required'));

UPDATE system_meta
SET instance_id = (SELECT instance_id FROM audit_instances WHERE id = 1)
WHERE id = 1;

CREATE TABLE restore_sessions (
    plan_id TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL UNIQUE CHECK (plan_digest GLOB 'sha256:[0-9a-f]*' AND length(plan_digest) = 71),
    declaration_id TEXT NOT NULL,
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    human_acknowledgement_id TEXT NOT NULL UNIQUE,
    point_id TEXT NOT NULL,
    point_digest TEXT NOT NULL CHECK (point_digest GLOB 'sha256:[0-9a-f]*' AND length(point_digest) = 71),
    dependency_digest TEXT NOT NULL CHECK (dependency_digest GLOB 'sha256:[0-9a-f]*' AND length(dependency_digest) = 71),
    fence_set_digest TEXT NOT NULL CHECK (fence_set_digest GLOB 'sha256:[0-9a-f]*' AND length(fence_set_digest) = 71),
    audit_decision_digest TEXT NOT NULL CHECK (audit_decision_digest GLOB 'sha256:[0-9a-f]*' AND length(audit_decision_digest) = 71),
    target_digest TEXT NOT NULL CHECK (target_digest GLOB 'sha256:[0-9a-f]*' AND length(target_digest) = 71),
    candidate_digest TEXT NOT NULL CHECK (candidate_digest GLOB 'sha256:[0-9a-f]*' AND length(candidate_digest) = 71),
    prior_instance_id TEXT NOT NULL,
    new_instance_id TEXT NOT NULL CHECK (new_instance_id <> prior_instance_id),
    prior_recovery_epoch INTEGER NOT NULL CHECK (prior_recovery_epoch >= 0),
    next_recovery_epoch INTEGER NOT NULL CHECK (next_recovery_epoch = prior_recovery_epoch + 1),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes) > 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY(plan_id) REFERENCES immutable_plans(plan_id) ON DELETE RESTRICT,
    FOREIGN KEY(human_acknowledgement_id) REFERENCES acknowledgement_requests(acknowledgement_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE restore_transitions (
    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL,
    from_status TEXT NOT NULL CHECK (from_status IN ('planned','fenced','restoring','verification-required','verified','failed','uncertain')),
    to_status TEXT NOT NULL CHECK (to_status IN ('fenced','restoring','verification-required','verified','failed','uncertain')),
    plan_digest TEXT NOT NULL CHECK (plan_digest GLOB 'sha256:[0-9a-f]*' AND length(plan_digest) = 71),
    evidence_digest TEXT NOT NULL CHECK (evidence_digest GLOB 'sha256:[0-9a-f]*' AND length(evidence_digest) = 71),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    UNIQUE(plan_id, from_status),
    FOREIGN KEY(plan_id) REFERENCES restore_sessions(plan_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE recovery_candidates (
    candidate_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL UNIQUE,
    candidate_digest TEXT NOT NULL UNIQUE CHECK (candidate_digest GLOB 'sha256:[0-9a-f]*' AND length(candidate_digest) = 71),
    preserved_authority_digest TEXT NOT NULL CHECK (preserved_authority_digest GLOB 'sha256:[0-9a-f]*' AND length(preserved_authority_digest) = 71),
    fence_set_digest TEXT NOT NULL CHECK (fence_set_digest GLOB 'sha256:[0-9a-f]*' AND length(fence_set_digest) = 71),
    audit_decision_digest TEXT NOT NULL CHECK (audit_decision_digest GLOB 'sha256:[0-9a-f]*' AND length(audit_decision_digest) = 71),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY(plan_id) REFERENCES restore_sessions(plan_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX restore_transitions_plan_sequence ON restore_transitions(plan_id, transition_id);

CREATE TRIGGER restore_sessions_no_update BEFORE UPDATE ON restore_sessions BEGIN SELECT RAISE(ABORT, 'restore sessions are immutable'); END;
CREATE TRIGGER restore_sessions_no_delete BEFORE DELETE ON restore_sessions BEGIN SELECT RAISE(ABORT, 'restore sessions are append-only'); END;
CREATE TRIGGER restore_transitions_no_update BEFORE UPDATE ON restore_transitions BEGIN SELECT RAISE(ABORT, 'restore transitions are immutable'); END;
CREATE TRIGGER restore_transitions_no_delete BEFORE DELETE ON restore_transitions BEGIN SELECT RAISE(ABORT, 'restore transitions are append-only'); END;
CREATE TRIGGER recovery_candidates_no_update BEFORE UPDATE ON recovery_candidates BEGIN SELECT RAISE(ABORT, 'recovery candidates are immutable'); END;
CREATE TRIGGER recovery_candidates_no_delete BEFORE DELETE ON recovery_candidates BEGIN SELECT RAISE(ABORT, 'recovery candidates are append-only'); END;
