-- #114 stores only sanitized, append-only off-site generation receipts and
-- proofs. Credentials, bearer tokens, repository passwords, and signing
-- material never enter these tables.
CREATE TABLE backup_offsite_run_specs (
    generation_id TEXT PRIMARY KEY CHECK (length(generation_id) BETWEEN 1 AND 128),
    source_point_id TEXT NOT NULL REFERENCES recovery_points(point_id),
    snapshot_path TEXT NOT NULL CHECK (length(snapshot_path) BETWEEN 2 AND 4096),
    repository_url TEXT NOT NULL CHECK (length(repository_url) BETWEEN 12 AND 4096),
    parent_reference_id TEXT NOT NULL CHECK (length(parent_reference_id) BETWEEN 1 AND 128),
    repository_key_reference_id TEXT NOT NULL CHECK (length(repository_key_reference_id) BETWEEN 1 AND 128),
    observer_reference_id TEXT NOT NULL CHECK (length(observer_reference_id) BETWEEN 1 AND 128),
    rule_digest TEXT NOT NULL CHECK (length(rule_digest)=71 AND substr(rule_digest,1,7)='sha256:'),
    g008_evidence_digest TEXT NOT NULL CHECK (length(g008_evidence_digest)=71 AND substr(g008_evidence_digest,1,7)='sha256:'),
    maximum_bytes INTEGER NOT NULL CHECK (maximum_bytes > 0),
    maximum_puts INTEGER NOT NULL CHECK (maximum_puts > 0),
    maximum_lists INTEGER NOT NULL CHECK (maximum_lists > 0),
    maximum_retained_generations INTEGER NOT NULL CHECK (maximum_retained_generations > 0),
    rule_limit INTEGER NOT NULL CHECK (rule_limit > 0),
    retention_seconds INTEGER NOT NULL CHECK (retention_seconds > 0),
    session_ttl_seconds INTEGER NOT NULL CHECK (session_ttl_seconds BETWEEN 1 AND 900),
    canonical_json TEXT NOT NULL CHECK (length(canonical_json) BETWEEN 2 AND 1048576),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    CHECK (parent_reference_id <> repository_key_reference_id AND parent_reference_id <> observer_reference_id AND repository_key_reference_id <> observer_reference_id)
) STRICT;
CREATE TRIGGER backup_offsite_run_specs_no_update BEFORE UPDATE ON backup_offsite_run_specs BEGIN SELECT RAISE(ABORT,'offsite run specs are append-only'); END;
CREATE TRIGGER backup_offsite_run_specs_no_delete BEFORE DELETE ON backup_offsite_run_specs BEGIN SELECT RAISE(ABORT,'offsite run specs are append-only'); END;

CREATE TABLE backup_offsite_execution_leases (
    lease_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    generation_id TEXT NOT NULL REFERENCES backup_offsite_run_specs(generation_id),
    source_point_id TEXT NOT NULL REFERENCES recovery_points(point_id),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_revision INTEGER NOT NULL,
    recovery_epoch INTEGER NOT NULL,
    maximum_expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER backup_offsite_execution_leases_no_update BEFORE UPDATE ON backup_offsite_execution_leases BEGIN SELECT RAISE(ABORT,'offsite execution leases are append-only'); END;
CREATE TRIGGER backup_offsite_execution_leases_no_delete BEFORE DELETE ON backup_offsite_execution_leases BEGIN SELECT RAISE(ABORT,'offsite execution leases are append-only'); END;

CREATE TABLE backup_offsite_custody_attempts (
    attempt_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    lease_id TEXT NOT NULL REFERENCES backup_offsite_execution_leases(lease_id),
    role TEXT NOT NULL CHECK(role IN ('offsite-writer','offsite-verifier')),
    generation_id TEXT NOT NULL REFERENCES backup_offsite_run_specs(generation_id),
    source_point_id TEXT NOT NULL REFERENCES recovery_points(point_id),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_revision INTEGER NOT NULL,
    recovery_epoch INTEGER NOT NULL,
    maximum_expires_at TEXT NOT NULL,
    nonce_digest TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER backup_offsite_custody_attempts_no_update BEFORE UPDATE ON backup_offsite_custody_attempts BEGIN SELECT RAISE(ABORT,'offsite custody attempts are append-only'); END;
CREATE TRIGGER backup_offsite_custody_attempts_no_delete BEFORE DELETE ON backup_offsite_custody_attempts BEGIN SELECT RAISE(ABORT,'offsite custody attempts are append-only'); END;
CREATE TABLE backup_offsite_custody_outcomes (
    attempt_id TEXT PRIMARY KEY REFERENCES backup_offsite_custody_attempts(attempt_id),
    outcome TEXT NOT NULL CHECK(outcome IN ('succeeded','failed','uncertain')),
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER backup_offsite_custody_outcomes_no_update BEFORE UPDATE ON backup_offsite_custody_outcomes BEGIN SELECT RAISE(ABORT,'offsite custody outcomes are append-only'); END;
CREATE TRIGGER backup_offsite_custody_outcomes_no_delete BEFORE DELETE ON backup_offsite_custody_outcomes BEGIN SELECT RAISE(ABORT,'offsite custody outcomes are append-only'); END;

CREATE TABLE backup_offsite_cleanup_obligations (
    obligation_id TEXT PRIMARY KEY CHECK (length(obligation_id) BETWEEN 1 AND 128),
    generation_id TEXT NOT NULL REFERENCES backup_offsite_run_specs(generation_id),
    object_key TEXT NOT NULL CHECK (length(object_key) BETWEEN 1 AND 1024),
    credential_reference_id TEXT NOT NULL CHECK (length(credential_reference_id) BETWEEN 1 AND 128),
    credential_fingerprint TEXT NOT NULL CHECK (length(credential_fingerprint)=71 AND substr(credential_fingerprint,1,7)='sha256:'),
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL,
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER backup_offsite_cleanup_obligations_no_update BEFORE UPDATE ON backup_offsite_cleanup_obligations BEGIN SELECT RAISE(ABORT,'offsite cleanup obligations are append-only'); END;
CREATE TRIGGER backup_offsite_cleanup_obligations_no_delete BEFORE DELETE ON backup_offsite_cleanup_obligations BEGIN SELECT RAISE(ABORT,'offsite cleanup obligations are append-only'); END;

CREATE TABLE backup_offsite_cleanup_upload_receipts (
    obligation_id TEXT NOT NULL REFERENCES backup_offsite_cleanup_obligations(obligation_id),
    upload_id TEXT NOT NULL CHECK (length(upload_id) BETWEEN 1 AND 1024),
    received_at TEXT NOT NULL,
    PRIMARY KEY(obligation_id,upload_id)
) STRICT;
CREATE TRIGGER backup_offsite_cleanup_upload_receipts_no_update BEFORE UPDATE ON backup_offsite_cleanup_upload_receipts BEGIN SELECT RAISE(ABORT,'offsite cleanup upload receipts are append-only'); END;
CREATE TRIGGER backup_offsite_cleanup_upload_receipts_no_delete BEFORE DELETE ON backup_offsite_cleanup_upload_receipts BEGIN SELECT RAISE(ABORT,'offsite cleanup upload receipts are append-only'); END;

CREATE TABLE backup_offsite_cleanup_outcomes (
    obligation_id TEXT PRIMARY KEY REFERENCES backup_offsite_cleanup_obligations(obligation_id),
    outcome TEXT NOT NULL CHECK (outcome='resolved'),
    resolved_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER backup_offsite_cleanup_outcomes_no_update BEFORE UPDATE ON backup_offsite_cleanup_outcomes BEGIN SELECT RAISE(ABORT,'offsite cleanup outcomes are append-only'); END;
CREATE TRIGGER backup_offsite_cleanup_outcomes_no_delete BEFORE DELETE ON backup_offsite_cleanup_outcomes BEGIN SELECT RAISE(ABORT,'offsite cleanup outcomes are append-only'); END;

CREATE TABLE backup_offsite_generations (
    generation_id TEXT PRIMARY KEY CHECK (length(generation_id) BETWEEN 1 AND 128),
    source_point_id TEXT NOT NULL REFERENCES recovery_points(point_id),
    repository_id TEXT NOT NULL CHECK (length(repository_id) BETWEEN 1 AND 128),
    offsite_snapshot_id TEXT NOT NULL CHECK (length(offsite_snapshot_id)=64),
    pending_json TEXT NOT NULL CHECK (length(pending_json) BETWEEN 2 AND 1048576),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    issuance_stopped_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(source_point_id,recovery_epoch)
) STRICT;
CREATE INDEX backup_offsite_generations_current_idx ON backup_offsite_generations(recovery_epoch,created_at DESC,generation_id DESC);
CREATE TRIGGER backup_offsite_generations_no_update BEFORE UPDATE ON backup_offsite_generations BEGIN SELECT RAISE(ABORT,'offsite generations are append-only'); END;
CREATE TRIGGER backup_offsite_generations_no_delete BEFORE DELETE ON backup_offsite_generations BEGIN SELECT RAISE(ABORT,'offsite generations are append-only'); END;

CREATE TABLE backup_offsite_retention_rules (
    generation_id TEXT NOT NULL REFERENCES backup_offsite_generations(generation_id),
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 5),
    rule_id TEXT NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 128),
    protected_prefix TEXT NOT NULL CHECK (length(protected_prefix) BETWEEN 1 AND 512),
    PRIMARY KEY(generation_id,sequence),
    UNIQUE(generation_id,rule_id),
    UNIQUE(generation_id,protected_prefix)
) STRICT;
CREATE TRIGGER backup_offsite_retention_rules_no_update BEFORE UPDATE ON backup_offsite_retention_rules BEGIN SELECT RAISE(ABORT,'offsite retention rules are append-only'); END;
CREATE TRIGGER backup_offsite_retention_rules_no_delete BEFORE DELETE ON backup_offsite_retention_rules BEGIN SELECT RAISE(ABORT,'offsite retention rules are append-only'); END;

CREATE TABLE backup_offsite_objects (
    generation_id TEXT NOT NULL REFERENCES backup_offsite_generations(generation_id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    object_key TEXT NOT NULL CHECK (length(object_key) BETWEEN 1 AND 1024),
    object_digest TEXT NOT NULL CHECK (length(object_digest)=71 AND substr(object_digest,1,7)='sha256:'),
    object_bytes INTEGER NOT NULL CHECK (object_bytes >= 0),
    PRIMARY KEY(generation_id,sequence),
    UNIQUE(generation_id,object_key)
) STRICT;
CREATE TRIGGER backup_offsite_objects_no_update BEFORE UPDATE ON backup_offsite_objects BEGIN SELECT RAISE(ABORT,'offsite objects are append-only'); END;
CREATE TRIGGER backup_offsite_objects_no_delete BEFORE DELETE ON backup_offsite_objects BEGIN SELECT RAISE(ABORT,'offsite objects are append-only'); END;

CREATE TABLE backup_offsite_session_expiries (
    generation_id TEXT NOT NULL REFERENCES backup_offsite_generations(generation_id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    expires_at TEXT NOT NULL,
    PRIMARY KEY(generation_id,sequence)
) STRICT;
CREATE TRIGGER backup_offsite_session_expiries_no_update BEFORE UPDATE ON backup_offsite_session_expiries BEGIN SELECT RAISE(ABORT,'offsite session expiries are append-only'); END;
CREATE TRIGGER backup_offsite_session_expiries_no_delete BEFORE DELETE ON backup_offsite_session_expiries BEGIN SELECT RAISE(ABORT,'offsite session expiries are append-only'); END;

CREATE TABLE backup_offsite_proofs (
    proof_id TEXT PRIMARY KEY CHECK (length(proof_id) BETWEEN 1 AND 128),
    proof_digest TEXT NOT NULL UNIQUE CHECK (length(proof_digest)=71 AND substr(proof_digest,1,7)='sha256:'),
    generation_id TEXT NOT NULL REFERENCES backup_offsite_generations(generation_id),
    status TEXT NOT NULL CHECK (status IN ('fixture-only','offsite-verified','full-payload-due','site-loss-blocked','uncertain','failed')),
    proof_class TEXT NOT NULL CHECK (proof_class IN ('fixture','qualified-provider')),
    proof_json TEXT NOT NULL CHECK (length(proof_json) BETWEEN 2 AND 1048576),
    full_read_at TEXT,
    observed_at TEXT NOT NULL,
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL
) STRICT;
CREATE INDEX backup_offsite_proofs_generation_idx ON backup_offsite_proofs(generation_id,created_at DESC,proof_id DESC);
CREATE TRIGGER backup_offsite_proofs_no_update BEFORE UPDATE ON backup_offsite_proofs BEGIN SELECT RAISE(ABORT,'offsite proofs are append-only'); END;
CREATE TRIGGER backup_offsite_proofs_no_delete BEFORE DELETE ON backup_offsite_proofs BEGIN SELECT RAISE(ABORT,'offsite proofs are append-only'); END;

CREATE TABLE backup_offsite_last_good_history (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    proof_id TEXT NOT NULL UNIQUE REFERENCES backup_offsite_proofs(proof_id),
    generation_id TEXT NOT NULL REFERENCES backup_offsite_generations(generation_id),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    advanced_at TEXT NOT NULL
) STRICT;
CREATE INDEX backup_offsite_last_good_current_idx ON backup_offsite_last_good_history(recovery_epoch,sequence DESC);
CREATE TRIGGER backup_offsite_last_good_history_no_update BEFORE UPDATE ON backup_offsite_last_good_history BEGIN SELECT RAISE(ABORT,'offsite last-good history is append-only'); END;
CREATE TRIGGER backup_offsite_last_good_history_no_delete BEFORE DELETE ON backup_offsite_last_good_history BEGIN SELECT RAISE(ABORT,'offsite last-good history is append-only'); END;
