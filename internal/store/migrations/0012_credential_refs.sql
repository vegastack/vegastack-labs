-- #105 credential metadata only. Secret values and low-entropy plaintext hashes
-- are forbidden in these tables; native ciphertext remains in protected files.
CREATE TABLE credential_reference_versions (
    version_id TEXT PRIMARY KEY CHECK (length(version_id) BETWEEN 1 AND 128),
    reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 128),
    consumer_id TEXT NOT NULL CHECK (length(consumer_id) BETWEEN 1 AND 128),
    purpose_id TEXT NOT NULL CHECK (length(purpose_id) BETWEEN 1 AND 128),
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 128),
    resolver_id TEXT NOT NULL CHECK (length(resolver_id) BETWEEN 1 AND 128),
    material_version TEXT NOT NULL CHECK (length(material_version) BETWEEN 1 AND 128),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 71 AND substr(fingerprint,1,7) = 'sha256:'),
    status TEXT NOT NULL CHECK (status IN ('staged','active','unavailable','revoked')),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    activated_at TEXT,
    verified_consumers_bytes BLOB NOT NULL CHECK (length(verified_consumers_bytes) BETWEEN 2 AND 4096),
    declaration_id TEXT NOT NULL CHECK (length(declaration_id) BETWEEN 1 AND 128),
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    plan_id TEXT NOT NULL CHECK (length(plan_id) BETWEEN 1 AND 128),
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND substr(plan_digest,1,7) = 'sha256:'),
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 128),
    step_id TEXT NOT NULL CHECK (length(step_id) BETWEEN 1 AND 128),
    lease_id TEXT NOT NULL CHECK (length(lease_id) BETWEEN 1 AND 128),
    human_id TEXT NOT NULL CHECK (length(human_id) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX credential_reference_versions_latest_idx
ON credential_reference_versions(reference_id,recovery_epoch,state_revision,version_id);

CREATE TABLE credential_step_bindings (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) BETWEEN 1 AND 128),
    declaration_id TEXT NOT NULL CHECK (length(declaration_id) BETWEEN 1 AND 128),
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 71 AND substr(binding_digest,1,7) = 'sha256:'),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes) BETWEEN 2 AND 4096),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    UNIQUE(declaration_id,declaration_revision,operation_id,binding_digest)
) STRICT;

CREATE INDEX credential_step_bindings_declaration_idx
ON credential_step_bindings(declaration_id,declaration_revision,operation_id);

CREATE TABLE credential_resolution_records (
    record_id TEXT PRIMARY KEY CHECK (length(record_id) BETWEEN 1 AND 128),
    reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 128),
    consumer_id TEXT NOT NULL CHECK (length(consumer_id) BETWEEN 1 AND 128),
    purpose_id TEXT NOT NULL CHECK (length(purpose_id) BETWEEN 1 AND 128),
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 128),
    resolver_id TEXT NOT NULL CHECK (length(resolver_id) BETWEEN 1 AND 128),
    material_version TEXT NOT NULL CHECK (length(material_version) BETWEEN 1 AND 128),
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 71 AND substr(fingerprint,1,7) = 'sha256:'),
    status TEXT NOT NULL CHECK (status IN ('staged','active','unavailable','revoked')),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    resolved_at TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('resolved','unavailable','denied')),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128)
) STRICT;

CREATE TRIGGER credential_reference_versions_no_update BEFORE UPDATE ON credential_reference_versions
BEGIN SELECT RAISE(ABORT,'credential versions are append-only'); END;
CREATE TRIGGER credential_reference_versions_no_delete BEFORE DELETE ON credential_reference_versions
BEGIN SELECT RAISE(ABORT,'credential versions are append-only'); END;
CREATE TRIGGER credential_step_bindings_no_update BEFORE UPDATE ON credential_step_bindings
BEGIN SELECT RAISE(ABORT,'credential bindings are append-only'); END;
CREATE TRIGGER credential_step_bindings_no_delete BEFORE DELETE ON credential_step_bindings
BEGIN SELECT RAISE(ABORT,'credential bindings are append-only'); END;
CREATE TRIGGER credential_resolution_records_no_update BEFORE UPDATE ON credential_resolution_records
BEGIN SELECT RAISE(ABORT,'credential resolution records are append-only'); END;
CREATE TRIGGER credential_resolution_records_no_delete BEFORE DELETE ON credential_resolution_records
BEGIN SELECT RAISE(ABORT,'credential resolution records are append-only'); END;
