CREATE TABLE audit_instances (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    instance_id TEXT NOT NULL UNIQUE CHECK (length(instance_id) BETWEEN 10 AND 128),
    created_at TEXT NOT NULL
) STRICT;

INSERT INTO audit_instances(id, instance_id, created_at)
VALUES (1, 'instance-' || lower(hex(randomblob(16))), strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));

CREATE TABLE audit_epoch_genesis (
    recovery_epoch INTEGER PRIMARY KEY CHECK (recovery_epoch >= 0),
    instance_id TEXT NOT NULL,
    prior_checkpoint_digest TEXT NOT NULL CHECK (prior_checkpoint_digest GLOB 'sha256:[0-9a-f]*' AND length(prior_checkpoint_digest) = 71),
    recovery_decision_digest TEXT NOT NULL CHECK (recovery_decision_digest GLOB 'sha256:[0-9a-f]*' AND length(recovery_decision_digest) = 71),
    genesis_digest TEXT NOT NULL UNIQUE CHECK (genesis_digest GLOB 'sha256:[0-9a-f]*' AND length(genesis_digest) = 71),
    FOREIGN KEY(instance_id) REFERENCES audit_instances(instance_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE audit_chain_links (
    event_id INTEGER PRIMARY KEY,
    instance_id TEXT NOT NULL,
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    segment_sequence INTEGER NOT NULL CHECK (segment_sequence > 0),
    previous_digest TEXT NOT NULL CHECK (previous_digest GLOB 'sha256:[0-9a-f]*' AND length(previous_digest) = 71),
    payload_digest TEXT NOT NULL CHECK (payload_digest GLOB 'sha256:[0-9a-f]*' AND length(payload_digest) = 71),
    context_bytes BLOB NOT NULL CHECK (length(context_bytes) <= 512),
    context_digest TEXT NOT NULL CHECK (context_digest GLOB 'sha256:[0-9a-f]*' AND length(context_digest) = 71),
    link_digest TEXT NOT NULL UNIQUE CHECK (link_digest GLOB 'sha256:[0-9a-f]*' AND length(link_digest) = 71),
    pre_anchor INTEGER NOT NULL CHECK (pre_anchor IN (0, 1)),
    UNIQUE(instance_id, recovery_epoch, segment_sequence),
    FOREIGN KEY(event_id) REFERENCES audit_events(event_id) ON DELETE RESTRICT,
    FOREIGN KEY(recovery_epoch) REFERENCES audit_epoch_genesis(recovery_epoch) ON DELETE RESTRICT
) STRICT;

CREATE INDEX audit_chain_epoch_sequence ON audit_chain_links(recovery_epoch, segment_sequence);

CREATE TRIGGER audit_epoch_genesis_no_update
BEFORE UPDATE ON audit_epoch_genesis
BEGIN
    SELECT RAISE(ABORT, 'audit epoch genesis is immutable');
END;

CREATE TRIGGER audit_epoch_genesis_no_delete
BEFORE DELETE ON audit_epoch_genesis
BEGIN
    SELECT RAISE(ABORT, 'audit epoch genesis is append-only');
END;

CREATE TRIGGER audit_chain_links_no_update
BEFORE UPDATE ON audit_chain_links
BEGIN
    SELECT RAISE(ABORT, 'audit chain links are immutable');
END;

CREATE TRIGGER audit_chain_links_no_delete
BEFORE DELETE ON audit_chain_links
BEGIN
    SELECT RAISE(ABORT, 'audit chain links are append-only');
END;

CREATE TABLE audit_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    first_event_id INTEGER NOT NULL CHECK (first_event_id > 0),
    last_event_id INTEGER NOT NULL CHECK (last_event_id >= first_event_id),
    first_segment_sequence INTEGER NOT NULL CHECK (first_segment_sequence > 0),
    last_segment_sequence INTEGER NOT NULL CHECK (last_segment_sequence >= first_segment_sequence),
    chain_digest TEXT NOT NULL CHECK (chain_digest GLOB 'sha256:[0-9a-f]*' AND length(chain_digest) = 71),
    signer_reference_id TEXT NOT NULL,
    signer_material_version TEXT NOT NULL,
    signature_digest TEXT,
    public_key_id TEXT,
    export_namespace TEXT NOT NULL,
    export_receipt_digest TEXT,
    independent_read_digest TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending','signed','export-pending','anchored','degraded','incident')),
    reason_code TEXT NOT NULL,
    pre_anchor INTEGER NOT NULL CHECK (pre_anchor IN (0, 1)),
    canonical_bytes BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(instance_id) REFERENCES audit_instances(instance_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE audit_checkpoint_outbox (
    checkpoint_id TEXT PRIMARY KEY,
    exact_path TEXT NOT NULL UNIQUE,
    encrypted_payload BLOB NOT NULL,
    payload_digest TEXT NOT NULL CHECK (payload_digest GLOB 'sha256:[0-9a-f]*' AND length(payload_digest) = 71),
    status TEXT NOT NULL CHECK (status IN ('pending','retry-wait','written','confirmed','failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_code TEXT,
    next_attempt_at TEXT,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(checkpoint_id) REFERENCES audit_checkpoints(checkpoint_id) ON DELETE RESTRICT
) STRICT;
