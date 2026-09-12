CREATE TABLE declaration_revisions (
    declaration_id TEXT NOT NULL,
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    declaration_type TEXT NOT NULL,
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    content_digest TEXT NOT NULL CHECK (content_digest GLOB 'sha256:[0-9a-f]*' AND length(content_digest) = 71),
    reason_digest TEXT NOT NULL CHECK (reason_digest GLOB 'sha256:[0-9a-f]*' AND length(reason_digest) = 71),
    status TEXT NOT NULL CHECK (status IN ('draft','committed','superseded')),
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    agent_session_id TEXT NOT NULL,
    PRIMARY KEY (declaration_id, declaration_revision)
) STRICT;

CREATE TABLE immutable_plans (
    plan_id TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL UNIQUE CHECK (plan_digest GLOB 'sha256:[0-9a-f]*' AND length(plan_digest) = 71),
    declaration_id TEXT NOT NULL,
    declaration_revision INTEGER NOT NULL,
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    observation_fingerprint TEXT NOT NULL CHECK (observation_fingerprint GLOB 'sha256:[0-9a-f]*' AND length(observation_fingerprint) = 71),
    idempotency_key_digest TEXT NOT NULL UNIQUE CHECK (idempotency_key_digest GLOB 'sha256:[0-9a-f]*' AND length(idempotency_key_digest) = 71),
    request_digest TEXT NOT NULL CHECK (request_digest GLOB 'sha256:[0-9a-f]*' AND length(request_digest) = 71),
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0),
    readable_plan TEXT NOT NULL CHECK (length(readable_plan) > 0),
    readable_digest TEXT NOT NULL CHECK (readable_digest GLOB 'sha256:[0-9a-f]*' AND length(readable_digest) = 71),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK (expires_at > created_at),
    FOREIGN KEY (declaration_id, declaration_revision) REFERENCES declaration_revisions(declaration_id, declaration_revision)
) STRICT;

CREATE TRIGGER declaration_revisions_no_update BEFORE UPDATE ON declaration_revisions BEGIN SELECT RAISE(ABORT, 'declaration revisions are append-only'); END;
CREATE TRIGGER declaration_revisions_no_delete BEFORE DELETE ON declaration_revisions BEGIN SELECT RAISE(ABORT, 'declaration revisions are append-only'); END;
CREATE TRIGGER immutable_plans_no_update BEFORE UPDATE ON immutable_plans BEGIN SELECT RAISE(ABORT, 'plans are immutable'); END;
CREATE TRIGGER immutable_plans_no_delete BEFORE DELETE ON immutable_plans BEGIN SELECT RAISE(ABORT, 'plans are immutable'); END;
