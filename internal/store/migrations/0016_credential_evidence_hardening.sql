-- #133 hardens credential verification evidence without changing any prior
-- migration. The store takes and verifies a restorable snapshot before this
-- forward-only migration. Copying retained rows into the tighter tables fails
-- closed if old evidence is not canonical; the migration transaction rolls back.
CREATE TABLE credential_consumer_verifications_new (
    verification_id TEXT PRIMARY KEY CHECK (length(verification_id) BETWEEN 1 AND 128),
    reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 128),
    version_id TEXT NOT NULL CHECK (length(version_id) BETWEEN 1 AND 128),
    consumer_id TEXT NOT NULL CHECK (length(consumer_id) BETWEEN 1 AND 128),
    profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
    role_id TEXT NOT NULL CHECK (length(role_id) BETWEEN 1 AND 128),
    material_version TEXT NOT NULL CHECK (length(material_version) BETWEEN 1 AND 128),
    ciphertext_fingerprint TEXT NOT NULL CHECK (length(ciphertext_fingerprint) = 71 AND substr(ciphertext_fingerprint,1,7) = 'sha256:' AND substr(ciphertext_fingerprint,8) NOT GLOB '*[^0-9a-f]*'),
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 71 AND substr(evidence_digest,1,7) = 'sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    restart_observed INTEGER NOT NULL CHECK (restart_observed IN (0,1)),
    result TEXT NOT NULL CHECK (result IN ('verified','denied')),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 64 AND substr(reason_code,1,1) GLOB '[a-z]' AND reason_code NOT GLOB '*[^a-z0-9-]*'),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    UNIQUE(version_id,consumer_id,result)
) STRICT;

INSERT INTO credential_consumer_verifications_new
SELECT * FROM credential_consumer_verifications;
DROP TABLE credential_consumer_verifications;
ALTER TABLE credential_consumer_verifications_new RENAME TO credential_consumer_verifications;

CREATE INDEX credential_consumer_verifications_version_idx
ON credential_consumer_verifications(reference_id,version_id,recovery_epoch);
CREATE TRIGGER credential_consumer_verifications_no_update BEFORE UPDATE ON credential_consumer_verifications
BEGIN SELECT RAISE(ABORT,'credential consumer verifications are append-only'); END;
CREATE TRIGGER credential_consumer_verifications_no_delete BEFORE DELETE ON credential_consumer_verifications
BEGIN SELECT RAISE(ABORT,'credential consumer verifications are append-only'); END;

CREATE TABLE credential_recovery_records_new (
    record_id TEXT PRIMARY KEY CHECK (length(record_id) BETWEEN 1 AND 128),
    reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 128),
    version_id TEXT NOT NULL CHECK (length(version_id) BETWEEN 1 AND 128),
    draft_id TEXT NOT NULL CHECK (length(draft_id) BETWEEN 1 AND 128),
    custody_proof_digest TEXT NOT NULL CHECK (length(custody_proof_digest) = 71 AND substr(custody_proof_digest,1,7) = 'sha256:' AND substr(custody_proof_digest,8) NOT GLOB '*[^0-9a-f]*'),
    former_controller_fence_digest TEXT NOT NULL CHECK (length(former_controller_fence_digest) = 71 AND substr(former_controller_fence_digest,1,7) = 'sha256:' AND substr(former_controller_fence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    prior_recovery_epoch INTEGER NOT NULL CHECK (prior_recovery_epoch >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch > prior_recovery_epoch),
    evidence_digest TEXT NOT NULL CHECK (length(evidence_digest) = 71 AND substr(evidence_digest,1,7) = 'sha256:' AND substr(evidence_digest,8) NOT GLOB '*[^0-9a-f]*'),
    created_at TEXT NOT NULL,
    UNIQUE(reference_id,version_id,recovery_epoch)
) STRICT;

INSERT INTO credential_recovery_records_new
SELECT * FROM credential_recovery_records;
DROP TABLE credential_recovery_records;
ALTER TABLE credential_recovery_records_new RENAME TO credential_recovery_records;

CREATE INDEX credential_recovery_records_reference_idx
ON credential_recovery_records(reference_id,recovery_epoch);
CREATE TRIGGER credential_recovery_records_no_update BEFORE UPDATE ON credential_recovery_records
BEGIN SELECT RAISE(ABORT,'credential recovery records are append-only'); END;
CREATE TRIGGER credential_recovery_records_no_delete BEFORE DELETE ON credential_recovery_records
BEGIN SELECT RAISE(ABORT,'credential recovery records are append-only'); END;
