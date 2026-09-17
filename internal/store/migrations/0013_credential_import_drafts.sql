-- #124 inert credential import drafts. Private bytes and plaintext-derived
-- hashes are forbidden; native ciphertext stays in protected files.
CREATE TABLE credential_import_drafts (
    draft_id TEXT PRIMARY KEY CHECK (length(draft_id) BETWEEN 1 AND 128),
    reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 128),
    consumer_id TEXT NOT NULL CHECK (length(consumer_id) BETWEEN 1 AND 128),
    purpose_id TEXT NOT NULL CHECK (length(purpose_id) BETWEEN 1 AND 128),
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 128),
    resolver_id TEXT NOT NULL CHECK (resolver_id = 'native-systemd'),
    material_version TEXT NOT NULL CHECK (length(material_version) BETWEEN 1 AND 128),
    idempotency_key_digest TEXT NOT NULL CHECK (length(idempotency_key_digest) = 71 AND substr(idempotency_key_digest,1,7) = 'sha256:'),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71 AND substr(request_digest,1,7) = 'sha256:'),
    target_digest TEXT NOT NULL CHECK (length(target_digest) = 71 AND substr(target_digest,1,7) = 'sha256:'),
    ciphertext_name TEXT NOT NULL CHECK (length(ciphertext_name) BETWEEN 1 AND 128),
    ciphertext_fingerprint TEXT NOT NULL CHECK (length(ciphertext_fingerprint) = 71 AND substr(ciphertext_fingerprint,1,7) = 'sha256:'),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL,
    UNIQUE(recovery_epoch,idempotency_key_digest),
    UNIQUE(reference_id,consumer_id,material_version,recovery_epoch)
) STRICT;

CREATE INDEX credential_import_drafts_reference_idx
ON credential_import_drafts(reference_id,recovery_epoch,state_revision,draft_id);

CREATE TRIGGER credential_import_drafts_no_update BEFORE UPDATE ON credential_import_drafts
BEGIN SELECT RAISE(ABORT,'credential import drafts are append-only'); END;
CREATE TRIGGER credential_import_drafts_no_delete BEFORE DELETE ON credential_import_drafts
BEGIN SELECT RAISE(ABORT,'credential import drafts are append-only'); END;
