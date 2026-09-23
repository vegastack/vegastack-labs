-- #163 durable write-ahead custody journal. The server owns both tables; the
-- short-lived filesystem custodian never opens SQLite. Attempts and terminal
-- outcomes are append-only, and a missing outcome remains explicitly unresolved.
CREATE TABLE backup_custody_attempts (
    attempt_id TEXT PRIMARY KEY CHECK (length(attempt_id) BETWEEN 1 AND 128),
    role TEXT NOT NULL CHECK (role IN ('writer','verifier')),
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL CHECK (length(plan_digest)=71 AND substr(plan_digest,1,7)='sha256:'),
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    repository_class TEXT NOT NULL CHECK (repository_class IN ('standard','critical')),
    point_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    maximum_expires_at TEXT NOT NULL,
    nonce_digest TEXT NOT NULL UNIQUE CHECK (length(nonce_digest)=71 AND substr(nonce_digest,1,7)='sha256:'),
    created_at TEXT NOT NULL
) STRICT;
CREATE INDEX backup_custody_attempts_lease_idx ON backup_custody_attempts(lease_id,repository_class,recovery_epoch);
CREATE TRIGGER backup_custody_attempts_no_update BEFORE UPDATE ON backup_custody_attempts BEGIN SELECT RAISE(ABORT,'backup custody attempts are append-only'); END;
CREATE TRIGGER backup_custody_attempts_no_delete BEFORE DELETE ON backup_custody_attempts BEGIN SELECT RAISE(ABORT,'backup custody attempts are append-only'); END;

CREATE TABLE backup_custody_outcomes (
    attempt_id TEXT PRIMARY KEY REFERENCES backup_custody_attempts(attempt_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded','failed','uncertain')),
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER backup_custody_outcomes_no_update BEFORE UPDATE ON backup_custody_outcomes BEGIN SELECT RAISE(ABORT,'backup custody outcomes are append-only'); END;
CREATE TRIGGER backup_custody_outcomes_no_delete BEFORE DELETE ON backup_custody_outcomes BEGIN SELECT RAISE(ABORT,'backup custody outcomes are append-only'); END;
