-- #140 expands the append-only lifecycle binding envelope for up to 64
-- typed native consumers and 64 denied readers. This is an atomic table copy;
-- existing rows and their plan seals are retained unchanged.
CREATE TABLE credential_lifecycle_bindings_expanded (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) BETWEEN 1 AND 128),
    declaration_id TEXT NOT NULL CHECK (length(declaration_id) BETWEEN 1 AND 128),
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    operation_id TEXT NOT NULL CHECK (length(operation_id) BETWEEN 1 AND 128),
    action TEXT NOT NULL CHECK (action IN ('credential.stage','credential.activate','credential.rotate','credential.revoke','credential.recover')),
    reference_id TEXT NOT NULL CHECK (length(reference_id) BETWEEN 1 AND 128),
    binding_digest TEXT NOT NULL CHECK (length(binding_digest) = 71 AND substr(binding_digest,1,7) = 'sha256:'),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes) BETWEEN 2 AND 262144),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    UNIQUE(declaration_id,declaration_revision,operation_id,binding_digest)
) STRICT;

INSERT INTO credential_lifecycle_bindings_expanded (
    binding_id,declaration_id,declaration_revision,operation_id,action,reference_id,
    binding_digest,binding_bytes,recovery_epoch,created_at
) SELECT binding_id,declaration_id,declaration_revision,operation_id,action,reference_id,
         binding_digest,binding_bytes,recovery_epoch,created_at
  FROM credential_lifecycle_bindings;

DROP TABLE credential_lifecycle_bindings;
ALTER TABLE credential_lifecycle_bindings_expanded RENAME TO credential_lifecycle_bindings;
CREATE INDEX credential_lifecycle_bindings_declaration_idx
ON credential_lifecycle_bindings(declaration_id,declaration_revision,operation_id);
CREATE TRIGGER credential_lifecycle_bindings_no_update BEFORE UPDATE ON credential_lifecycle_bindings
BEGIN SELECT RAISE(ABORT,'credential lifecycle bindings are append-only'); END;
CREATE TRIGGER credential_lifecycle_bindings_no_delete BEFORE DELETE ON credential_lifecycle_bindings
BEGIN SELECT RAISE(ABORT,'credential lifecycle bindings are append-only'); END;
