-- Permit reversible suspension while preserving terminal revocation and durable rows.
PRAGMA defer_foreign_keys=ON;
CREATE TABLE read_principals_next (
    principal_id TEXT PRIMARY KEY CHECK (length(principal_id) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64)
) STRICT;
INSERT INTO read_principals_next SELECT * FROM read_principals;
DROP TABLE read_principals;
ALTER TABLE read_principals_next RENAME TO read_principals;
CREATE TRIGGER read_principals_no_delete BEFORE DELETE ON read_principals BEGIN SELECT RAISE(ABORT, 'read principal is durable'); END;
CREATE TRIGGER read_principals_monotonic BEFORE UPDATE ON read_principals
WHEN NEW.principal_id != OLD.principal_id OR NEW.grant_revision < OLD.grant_revision OR (OLD.status = 'revoked' AND NEW.status != 'revoked')
BEGIN SELECT RAISE(ABORT, 'invalid read principal transition'); END;
CREATE TABLE effective_authorization_principals_next (
    principal_id TEXT PRIMARY KEY CHECK (length(principal_id) BETWEEN 1 AND 128),
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('human', 'agent', 'policy')),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64)
) STRICT;
INSERT INTO effective_authorization_principals_next SELECT * FROM effective_authorization_principals;
DROP TABLE effective_authorization_principals;
ALTER TABLE effective_authorization_principals_next RENAME TO effective_authorization_principals;
CREATE TRIGGER effective_authorization_principals_no_delete BEFORE DELETE ON effective_authorization_principals BEGIN SELECT RAISE(ABORT, 'effective principal is durable'); END;
CREATE TRIGGER effective_authorization_principals_monotonic BEFORE UPDATE ON effective_authorization_principals
WHEN NEW.principal_id != OLD.principal_id OR NEW.principal_kind != OLD.principal_kind OR NEW.grant_revision < OLD.grant_revision OR (OLD.status = 'revoked' AND NEW.status != 'revoked')
BEGIN SELECT RAISE(ABORT, 'invalid effective principal transition'); END;
-- Rebuilding a referenced table records transient deferred deletes. Check
-- actual referential integrity before clearing those transient counters.
CREATE TEMP TABLE lifecycle_fk_guard(value INTEGER CHECK(value=0));
INSERT INTO lifecycle_fk_guard SELECT COUNT(*) FROM pragma_foreign_key_check;
DROP TABLE lifecycle_fk_guard;
PRAGMA defer_foreign_keys=OFF;
