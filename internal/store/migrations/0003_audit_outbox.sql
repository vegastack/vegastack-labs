ALTER TABLE system_meta
ADD COLUMN audit_sequence INTEGER NOT NULL DEFAULT 0 CHECK (audit_sequence >= 0);

CREATE TABLE audit_events (
    event_id INTEGER PRIMARY KEY CHECK (event_id > 0),
    occurred_at TEXT NOT NULL CHECK (length(occurred_at) BETWEEN 1 AND 64),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 3 AND 96),
    correlation_id TEXT NOT NULL CHECK (length(correlation_id) BETWEEN 1 AND 128),
    causation_event_id INTEGER CHECK (causation_event_id IS NULL OR causation_event_id > 0),
    correction_of_event_id INTEGER CHECK (correction_of_event_id IS NULL OR correction_of_event_id > 0),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 128),
    principal_method TEXT NOT NULL CHECK (length(principal_method) BETWEEN 1 AND 64),
    responsible_human_principal_id TEXT CHECK (responsible_human_principal_id IS NULL OR length(responsible_human_principal_id) BETWEEN 1 AND 128),
    agent_name TEXT CHECK (agent_name IS NULL OR length(agent_name) BETWEEN 1 AND 64),
    agent_session_id TEXT CHECK (agent_session_id IS NULL OR length(agent_session_id) BETWEEN 1 AND 128),
    agent_source TEXT CHECK (agent_source IS NULL OR agent_source = 'self-reported'),
    target_kind TEXT NOT NULL CHECK (length(target_kind) BETWEEN 1 AND 64),
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 128),
    before_fingerprint TEXT CHECK (before_fingerprint IS NULL OR (length(before_fingerprint) = 71 AND substr(before_fingerprint, 1, 7) = 'sha256:' AND substr(before_fingerprint, 8) NOT GLOB '*[^0-9a-f]*')),
    after_fingerprint TEXT CHECK (after_fingerprint IS NULL OR (length(after_fingerprint) = 71 AND substr(after_fingerprint, 1, 7) = 'sha256:' AND substr(after_fingerprint, 8) NOT GLOB '*[^0-9a-f]*')),
    canonical_payload BLOB NOT NULL CHECK (length(canonical_payload) > 0),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 71 AND substr(payload_sha256, 1, 7) = 'sha256:' AND substr(payload_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    CHECK ((agent_name IS NULL AND agent_session_id IS NULL AND agent_source IS NULL) OR (agent_name IS NOT NULL AND agent_session_id IS NOT NULL AND agent_source = 'self-reported')),
    FOREIGN KEY (causation_event_id) REFERENCES audit_events(event_id) ON DELETE RESTRICT,
    FOREIGN KEY (correction_of_event_id) REFERENCES audit_events(event_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE intent_keys (
    scope TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 96),
    key_digest TEXT NOT NULL CHECK (length(key_digest) = 71 AND substr(key_digest, 1, 7) = 'sha256:' AND substr(key_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    request_digest TEXT NOT NULL CHECK (length(request_digest) = 71 AND substr(request_digest, 1, 7) = 'sha256:' AND substr(request_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    event_id INTEGER NOT NULL,
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    PRIMARY KEY (scope, key_digest),
    FOREIGN KEY (event_id) REFERENCES audit_events(event_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE outbox (
    outbox_id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (outbox_id > 0),
    event_id INTEGER NOT NULL,
    destination_id TEXT NOT NULL CHECK (length(destination_id) BETWEEN 1 AND 96),
    payload_schema TEXT NOT NULL CHECK (payload_schema = 'vegastack-labs.dev/audit-event'),
    payload_version TEXT NOT NULL CHECK (payload_version = '1.0.0'),
    payload_bytes BLOB NOT NULL CHECK (length(payload_bytes) > 0),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 71 AND substr(payload_sha256, 1, 7) = 'sha256:' AND substr(payload_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    dedupe_sha256 TEXT NOT NULL UNIQUE CHECK (length(dedupe_sha256) = 71 AND substr(dedupe_sha256, 1, 7) = 'sha256:' AND substr(dedupe_sha256, 8) NOT GLOB '*[^0-9a-f]*'),
    status TEXT NOT NULL CHECK (status IN ('pending', 'retry_wait', 'paused', 'delivered', 'dead_letter')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 8),
    max_attempts INTEGER NOT NULL DEFAULT 8 CHECK (max_attempts = 8),
    next_attempt_at TEXT CHECK (next_attempt_at IS NULL OR length(next_attempt_at) BETWEEN 1 AND 64),
    last_error_code TEXT CHECK (last_error_code IS NULL OR last_error_code IN ('DESTINATION_UNAVAILABLE', 'DELIVERY_REJECTED', 'PAYLOAD_INVALID', 'INTERRUPTED')),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64),
    delivered_at TEXT CHECK (delivered_at IS NULL OR length(delivered_at) BETWEEN 1 AND 64),
    UNIQUE (event_id, destination_id, payload_schema, payload_version),
    FOREIGN KEY (event_id) REFERENCES audit_events(event_id) ON DELETE RESTRICT,
    CHECK (
        (status = 'pending' AND attempt_count = 0 AND next_attempt_at IS NULL AND last_error_code IS NULL AND delivered_at IS NULL) OR
        (status = 'paused' AND attempt_count = 0 AND next_attempt_at IS NULL AND last_error_code IS NULL AND delivered_at IS NULL) OR
        (status = 'retry_wait' AND attempt_count BETWEEN 1 AND 7 AND next_attempt_at IS NOT NULL AND last_error_code IS NOT NULL AND delivered_at IS NULL) OR
        (status = 'delivered' AND attempt_count BETWEEN 1 AND 8 AND next_attempt_at IS NULL AND last_error_code IS NULL AND delivered_at IS NOT NULL) OR
        (status = 'dead_letter' AND next_attempt_at IS NULL AND last_error_code IS NOT NULL AND delivered_at IS NULL)
    )
) STRICT;

CREATE INDEX audit_events_correlation_idx ON audit_events(correlation_id, event_id);
CREATE INDEX audit_events_causation_idx ON audit_events(causation_event_id, event_id);
CREATE INDEX audit_events_correction_idx ON audit_events(correction_of_event_id, event_id);
CREATE INDEX outbox_due_idx ON outbox(status, next_attempt_at, outbox_id);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit event is append-only'); END;
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit event is append-only'); END;
CREATE TRIGGER intent_keys_no_update BEFORE UPDATE ON intent_keys BEGIN SELECT RAISE(ABORT, 'intent binding is append-only'); END;
CREATE TRIGGER intent_keys_no_delete BEFORE DELETE ON intent_keys BEGIN SELECT RAISE(ABORT, 'intent binding is append-only'); END;
CREATE TRIGGER outbox_no_delete BEFORE DELETE ON outbox BEGIN SELECT RAISE(ABORT, 'outbox record is durable'); END;
CREATE TRIGGER outbox_immutable_payload
BEFORE UPDATE OF event_id, destination_id, payload_schema, payload_version, payload_bytes, payload_sha256, dedupe_sha256, created_at ON outbox
BEGIN
    SELECT RAISE(ABORT, 'outbox payload is immutable');
END;
