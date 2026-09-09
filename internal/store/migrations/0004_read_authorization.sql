CREATE TABLE read_principals (
    principal_id TEXT PRIMARY KEY CHECK (length(principal_id) BETWEEN 1 AND 128),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64)
) STRICT;

CREATE TABLE read_grants (
    principal_id TEXT NOT NULL,
    capability TEXT NOT NULL CHECK (length(capability) BETWEEN 1 AND 128),
    resource_kind TEXT NOT NULL CHECK (length(resource_kind) BETWEEN 1 AND 128),
    resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 128),
    grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64),
    PRIMARY KEY (principal_id, capability, resource_kind, resource_id),
    FOREIGN KEY (principal_id) REFERENCES read_principals(principal_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX read_grants_lookup_idx ON read_grants(principal_id, capability, resource_kind, status, resource_id);

CREATE TRIGGER read_principals_no_delete BEFORE DELETE ON read_principals BEGIN SELECT RAISE(ABORT, 'read principal is durable'); END;
CREATE TRIGGER read_principals_monotonic BEFORE UPDATE ON read_principals
WHEN NEW.principal_id != OLD.principal_id OR NEW.grant_revision < OLD.grant_revision OR (OLD.status = 'revoked' AND NEW.status != 'revoked')
BEGIN SELECT RAISE(ABORT, 'invalid read principal transition'); END;
CREATE TRIGGER read_grants_no_delete BEFORE DELETE ON read_grants BEGIN SELECT RAISE(ABORT, 'read grant is durable'); END;
CREATE TRIGGER read_grants_immutable_scope BEFORE UPDATE ON read_grants
WHEN NEW.principal_id != OLD.principal_id OR NEW.capability != OLD.capability OR NEW.resource_kind != OLD.resource_kind OR NEW.resource_id != OLD.resource_id OR NEW.grant_revision < OLD.grant_revision OR (OLD.status = 'revoked' AND NEW.status != 'revoked')
BEGIN SELECT RAISE(ABORT, 'invalid read grant transition'); END;

