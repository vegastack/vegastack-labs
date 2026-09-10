CREATE TABLE remote_identity_bindings (
    binding_digest TEXT PRIMARY KEY CHECK (length(binding_digest) = 71 AND substr(binding_digest, 1, 7) = 'sha256:' AND substr(binding_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    principal_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 20 AND 64),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 20 AND 64),
    FOREIGN KEY (principal_id) REFERENCES read_principals(principal_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX remote_identity_bindings_principal_idx ON remote_identity_bindings(principal_id, status);

CREATE TABLE browser_sessions (
    session_digest TEXT PRIMARY KEY CHECK (length(session_digest) = 71 AND substr(session_digest, 1, 7) = 'sha256:' AND substr(session_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    binding_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'logged-out', 'revoked', 'expired')),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
    issued_at TEXT NOT NULL CHECK (length(issued_at) BETWEEN 20 AND 64),
    last_seen_at TEXT NOT NULL CHECK (length(last_seen_at) BETWEEN 20 AND 64),
    idle_expires_at TEXT NOT NULL CHECK (length(idle_expires_at) BETWEEN 20 AND 64),
    absolute_expires_at TEXT NOT NULL CHECK (length(absolute_expires_at) BETWEEN 20 AND 64),
    external_expires_at TEXT NOT NULL CHECK (length(external_expires_at) BETWEEN 20 AND 64),
    replaced_by_digest TEXT,
    ended_at TEXT,
    end_reason TEXT CHECK (end_reason IS NULL OR length(end_reason) BETWEEN 1 AND 64),
    CHECK ((status = 'active' AND replaced_by_digest IS NULL AND ended_at IS NULL AND end_reason IS NULL) OR
           (status = 'rotated' AND replaced_by_digest IS NOT NULL AND ended_at IS NOT NULL AND end_reason = 'renewed') OR
           (status IN ('logged-out', 'revoked', 'expired') AND replaced_by_digest IS NULL AND ended_at IS NOT NULL AND end_reason IS NOT NULL)),
    FOREIGN KEY (binding_digest) REFERENCES remote_identity_bindings(binding_digest) ON DELETE RESTRICT,
    FOREIGN KEY (principal_id) REFERENCES read_principals(principal_id) ON DELETE RESTRICT,
    FOREIGN KEY (replaced_by_digest) REFERENCES browser_sessions(session_digest) ON DELETE RESTRICT
) STRICT;

CREATE INDEX browser_sessions_principal_idx ON browser_sessions(principal_id, status);
CREATE INDEX browser_sessions_binding_idx ON browser_sessions(binding_digest, status);

CREATE TRIGGER remote_identity_bindings_no_delete BEFORE DELETE ON remote_identity_bindings
BEGIN SELECT RAISE(ABORT, 'remote identity binding is durable'); END;

CREATE TRIGGER remote_identity_bindings_immutable BEFORE UPDATE ON remote_identity_bindings
WHEN NEW.binding_digest != OLD.binding_digest OR NEW.principal_id != OLD.principal_id OR
     (OLD.status = 'revoked' AND NEW.status != 'revoked')
BEGIN SELECT RAISE(ABORT, 'invalid remote identity binding transition'); END;

CREATE TRIGGER browser_sessions_no_delete BEFORE DELETE ON browser_sessions
BEGIN SELECT RAISE(ABORT, 'browser session is durable'); END;

CREATE TRIGGER browser_sessions_monotonic BEFORE UPDATE ON browser_sessions
WHEN NEW.session_digest != OLD.session_digest OR NEW.binding_digest != OLD.binding_digest OR
     NEW.principal_id != OLD.principal_id OR NEW.recovery_epoch != OLD.recovery_epoch OR
     NEW.grant_revision != OLD.grant_revision OR NEW.issued_at != OLD.issued_at OR
     NEW.absolute_expires_at != OLD.absolute_expires_at OR NEW.external_expires_at != OLD.external_expires_at OR
     (OLD.status != 'active' AND (NEW.status != OLD.status OR NEW.last_seen_at != OLD.last_seen_at OR
      NEW.idle_expires_at != OLD.idle_expires_at OR NEW.replaced_by_digest IS NOT OLD.replaced_by_digest OR
      NEW.ended_at IS NOT OLD.ended_at OR NEW.end_reason IS NOT OLD.end_reason))
BEGIN SELECT RAISE(ABORT, 'invalid browser session transition'); END;
