CREATE TABLE system_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL CHECK (schema_version >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0)
) STRICT;

INSERT INTO system_meta (id, schema_version, state_revision, recovery_epoch)
VALUES (1, 1, 0, 0);

CREATE TABLE schema_migrations (
    id INTEGER PRIMARY KEY CHECK (id > 0),
    name TEXT NOT NULL UNIQUE CHECK (length(name) > 0),
    sha256 BLOB NOT NULL CHECK (length(sha256) = 32),
    applied_at TEXT NOT NULL CHECK (length(applied_at) > 0),
    tool_version TEXT NOT NULL CHECK (length(tool_version) > 0),
    build_version TEXT NOT NULL CHECK (length(build_version) > 0)
) STRICT;

CREATE TRIGGER schema_migrations_no_update
BEFORE UPDATE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'schema migration ledger is append-only');
END;

CREATE TRIGGER schema_migrations_no_delete
BEFORE DELETE ON schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'schema migration ledger is append-only');
END;
