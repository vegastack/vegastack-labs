-- #125 credential lifecycle metadata only. These append-only tables record
-- inert lifecycle bindings, per-consumer verification evidence, and clean-host
-- recovery evidence. Secret values and low-entropy plaintext hashes are
-- forbidden; native ciphertext remains in protected files.
CREATE TABLE credential_lifecycle_bindings (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) BETWEEN 1 AND 128),
    declaration_id TEXT NOT NULL CHECK (length(declaration_id) BETWEEN 1 AND 128),
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    action TEXT NOT NULL CHECK (action IN ('credential.stage','credential.activate','credential.rotate','credential.revoke','credential.recover')),
    reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 128),
    binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 71 AND substr(binding_digest,1,7) = 'sha256:'),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes) BETWEEN 2 AND 4096),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    UNIQUE(declaration_id,declaration_revision,operation_id,binding_digest)
) STRICT;

CREATE INDEX credential_lifecycle_bindings_declaration_idx
ON credential_lifecycle_bindings(declaration_id,declaration_revision,operation_id);

CREATE TABLE credential_consumer_verifications (
    verification_id TEXT PRIMARY KEY CHECK (length(verification_id) BETWEEN 1 AND 128),
    reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 128),
    version_id TEXT NOT NULL CHECK (length(version_id) BETWEEN 1 AND 128),
    consumer_id TEXT NOT NULL CHECK (length(consumer_id) BETWEEN 1 AND 128),
    profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
    role_id TEXT NOT NULL CHECK (length(role_id) BETWEEN 1 AND 128),
    material_version TEXT NOT NULL CHECK (length(material_version) BETWEEN 1 AND 128),
    ciphertext_fingerprint TEXT NOT NULL CHECK (length(ciphertext_fingerprint) = 71 AND substr(ciphertext_fingerprint,1,7) = 'sha256:'),
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 71 AND substr(evidence_digest,1,7) = 'sha256:'),
    restart_observed INTEGER NOT NULL CHECK (restart_observed IN (0,1)),
    result TEXT NOT NULL CHECK (result IN ('verified','denied')),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    UNIQUE(version_id,consumer_id,result)
) STRICT;

CREATE INDEX credential_consumer_verifications_version_idx
ON credential_consumer_verifications(reference_id,version_id,recovery_epoch);

CREATE TABLE credential_recovery_records (
    record_id TEXT PRIMARY KEY CHECK (length(record_id) BETWEEN 1 AND 128),
    reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 128),
    version_id TEXT NOT NULL CHECK (length(version_id) BETWEEN 1 AND 128),
    draft_id TEXT NOT NULL CHECK (length(draft_id) BETWEEN 1 AND 128),
    custody_proof_digest TEXT NOT NULL CHECK (length(custody_proof_digest) = 71 AND substr(custody_proof_digest,1,7) = 'sha256:'),
    former_controller_fence_digest TEXT NOT NULL CHECK (length(former_controller_fence_digest) = 71 AND substr(former_controller_fence_digest,1,7) = 'sha256:'),
    prior_recovery_epoch INTEGER NOT NULL CHECK (prior_recovery_epoch >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch > prior_recovery_epoch),
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 71 AND substr(evidence_digest,1,7) = 'sha256:'),
    created_at TEXT NOT NULL,
    UNIQUE(reference_id,version_id,recovery_epoch)
) STRICT;

CREATE INDEX credential_recovery_records_reference_idx
ON credential_recovery_records(reference_id,recovery_epoch);

CREATE TRIGGER credential_lifecycle_bindings_no_update BEFORE UPDATE ON credential_lifecycle_bindings
BEGIN SELECT RAISE(ABORT,'credential lifecycle bindings are append-only'); END;
CREATE TRIGGER credential_lifecycle_bindings_no_delete BEFORE DELETE ON credential_lifecycle_bindings
BEGIN SELECT RAISE(ABORT,'credential lifecycle bindings are append-only'); END;
CREATE TRIGGER credential_consumer_verifications_no_update BEFORE UPDATE ON credential_consumer_verifications
BEGIN SELECT RAISE(ABORT,'credential consumer verifications are append-only'); END;
CREATE TRIGGER credential_consumer_verifications_no_delete BEFORE DELETE ON credential_consumer_verifications
BEGIN SELECT RAISE(ABORT,'credential consumer verifications are append-only'); END;
CREATE TRIGGER credential_recovery_records_no_update BEFORE UPDATE ON credential_recovery_records
BEGIN SELECT RAISE(ABORT,'credential recovery records are append-only'); END;
CREATE TRIGGER credential_recovery_records_no_delete BEFORE DELETE ON credential_recovery_records
BEGIN SELECT RAISE(ABORT,'credential recovery records are append-only'); END;
