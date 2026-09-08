CREATE TABLE inventory_drafts (
    draft_id TEXT NOT NULL CHECK (length(draft_id) BETWEEN 1 AND 128),
    draft_revision INTEGER NOT NULL CHECK (draft_revision > 0),
    validation_status TEXT NOT NULL CHECK (validation_status IN ('valid', 'blocked')),
    source_kind TEXT NOT NULL CHECK (length(source_kind) BETWEEN 1 AND 128),
    adapter_kind TEXT NOT NULL CHECK (length(adapter_kind) BETWEEN 1 AND 128),
    adapter_version TEXT NOT NULL CHECK (length(adapter_version) BETWEEN 1 AND 128),
    source_revision TEXT NOT NULL CHECK (length(source_revision) <= 128),
    source_digest TEXT NOT NULL CHECK (length(source_digest) = 71 AND substr(source_digest, 1, 7) = 'sha256:' AND substr(source_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    captured_at TEXT NOT NULL CHECK (length(captured_at) > 0),
    content_digest TEXT NOT NULL CHECK (length(content_digest) = 71 AND substr(content_digest, 1, 7) = 'sha256:' AND substr(content_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    asset_count INTEGER NOT NULL CHECK (asset_count >= 0),
    node_count INTEGER NOT NULL CHECK (node_count >= 0),
    alias_count INTEGER NOT NULL CHECK (alias_count >= 0),
    address_count INTEGER NOT NULL CHECK (address_count >= 0),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 0),
    hardware_fact_count INTEGER NOT NULL CHECK (hardware_fact_count >= 0),
    provenance_count INTEGER NOT NULL CHECK (provenance_count >= 0),
    finding_count INTEGER NOT NULL CHECK (finding_count >= 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    PRIMARY KEY (draft_id, draft_revision)
) STRICT;

CREATE TABLE inventory_import_keys (
    key_digest TEXT PRIMARY KEY CHECK (length(key_digest) = 71 AND substr(key_digest, 1, 7) = 'sha256:' AND substr(key_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    candidate_digest TEXT NOT NULL CHECK (length(candidate_digest) = 71 AND substr(candidate_digest, 1, 7) = 'sha256:' AND substr(candidate_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    FOREIGN KEY (draft_id, draft_revision) REFERENCES inventory_drafts(draft_id, draft_revision)
) STRICT;

CREATE TABLE inventory_source_bindings (
    source_kind TEXT NOT NULL,
    adapter_kind TEXT NOT NULL,
    adapter_version TEXT NOT NULL,
    source_revision TEXT NOT NULL,
    source_digest TEXT NOT NULL CHECK (length(source_digest) = 71 AND substr(source_digest, 1, 7) = 'sha256:' AND substr(source_digest, 8) NOT GLOB '*[^0-9a-f]*'),
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    PRIMARY KEY (source_kind, adapter_kind, adapter_version, source_revision),
    FOREIGN KEY (draft_id, draft_revision) REFERENCES inventory_drafts(draft_id, draft_revision)
) STRICT;

CREATE TABLE inventory_draft_assets (
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    local_id TEXT NOT NULL CHECK (length(local_id) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    lifecycle TEXT NOT NULL CHECK (length(lifecycle) BETWEEN 1 AND 128),
    PRIMARY KEY (draft_id, draft_revision, ordinal),
    FOREIGN KEY (draft_id, draft_revision) REFERENCES inventory_drafts(draft_id, draft_revision)
) STRICT;

CREATE TABLE inventory_draft_identities (
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    asset_ordinal INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 1024),
    quarantined INTEGER NOT NULL CHECK (quarantined IN (0, 1)),
    PRIMARY KEY (draft_id, draft_revision, asset_ordinal, ordinal),
    FOREIGN KEY (draft_id, draft_revision, asset_ordinal) REFERENCES inventory_draft_assets(draft_id, draft_revision, ordinal)
) STRICT;

CREATE TABLE inventory_draft_hardware_facts (
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    asset_ordinal INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    local_id TEXT NOT NULL CHECK (length(local_id) BETWEEN 1 AND 128),
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    integer_value INTEGER,
    text_value TEXT CHECK (text_value IS NULL OR length(text_value) <= 1024),
    unit TEXT NOT NULL CHECK (length(unit) <= 128),
    PRIMARY KEY (draft_id, draft_revision, asset_ordinal, ordinal),
    FOREIGN KEY (draft_id, draft_revision, asset_ordinal) REFERENCES inventory_draft_assets(draft_id, draft_revision, ordinal)
) STRICT;

CREATE TABLE inventory_draft_nodes (
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    local_id TEXT NOT NULL CHECK (length(local_id) BETWEEN 1 AND 128),
    asset_id TEXT NOT NULL CHECK (length(asset_id) <= 128),
    parent_id TEXT NOT NULL CHECK (length(parent_id) <= 128),
    PRIMARY KEY (draft_id, draft_revision, ordinal),
    FOREIGN KEY (draft_id, draft_revision) REFERENCES inventory_drafts(draft_id, draft_revision)
) STRICT;

CREATE TABLE inventory_draft_aliases (
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    local_id TEXT NOT NULL CHECK (length(local_id) BETWEEN 1 AND 128),
    target_id TEXT NOT NULL CHECK (length(target_id) <= 128),
    value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 1024),
    PRIMARY KEY (draft_id, draft_revision, ordinal),
    FOREIGN KEY (draft_id, draft_revision) REFERENCES inventory_drafts(draft_id, draft_revision)
) STRICT;

CREATE TABLE inventory_draft_addresses (
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    local_id TEXT NOT NULL CHECK (length(local_id) BETWEEN 1 AND 128),
    node_id TEXT NOT NULL CHECK (length(node_id) <= 128),
    value TEXT NOT NULL CHECK (length(value) BETWEEN 1 AND 1024),
    PRIMARY KEY (draft_id, draft_revision, ordinal),
    FOREIGN KEY (draft_id, draft_revision) REFERENCES inventory_drafts(draft_id, draft_revision)
) STRICT;

CREATE TABLE inventory_draft_observations (
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    local_id TEXT NOT NULL CHECK (length(local_id) BETWEEN 1 AND 128),
    subject_id TEXT NOT NULL CHECK (length(subject_id) <= 128),
    kind TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 128),
    value TEXT NOT NULL CHECK (length(value) <= 1024),
    observed_at TEXT NOT NULL CHECK (length(observed_at) > 0),
    PRIMARY KEY (draft_id, draft_revision, ordinal),
    FOREIGN KEY (draft_id, draft_revision) REFERENCES inventory_drafts(draft_id, draft_revision)
) STRICT;

CREATE TABLE inventory_draft_provenance (
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    record_kind TEXT NOT NULL CHECK (length(record_kind) BETWEEN 1 AND 128),
    record_id TEXT NOT NULL CHECK (length(record_id) BETWEEN 1 AND 128),
    field_path TEXT NOT NULL CHECK (length(field_path) BETWEEN 1 AND 256),
    locator TEXT NOT NULL CHECK (length(locator) <= 256),
    captured_at TEXT NOT NULL CHECK (length(captured_at) > 0),
    adapter_version TEXT NOT NULL CHECK (length(adapter_version) BETWEEN 1 AND 128),
    value_status TEXT NOT NULL CHECK (length(value_status) BETWEEN 1 AND 128),
    PRIMARY KEY (draft_id, draft_revision, ordinal),
    FOREIGN KEY (draft_id, draft_revision) REFERENCES inventory_drafts(draft_id, draft_revision)
) STRICT;

CREATE TABLE inventory_draft_findings (
    draft_id TEXT NOT NULL,
    draft_revision INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    code TEXT NOT NULL CHECK (length(code) BETWEEN 1 AND 128),
    severity TEXT NOT NULL CHECK (severity = 'error'),
    blocking INTEGER NOT NULL CHECK (blocking = 1),
    record_kind TEXT NOT NULL CHECK (length(record_kind) <= 128),
    record_id TEXT NOT NULL CHECK (length(record_id) <= 128),
    field_path TEXT NOT NULL CHECK (length(field_path) <= 256),
    location TEXT NOT NULL CHECK (length(location) <= 256),
    related_ids_json TEXT NOT NULL CHECK (json_valid(related_ids_json)),
    PRIMARY KEY (draft_id, draft_revision, ordinal),
    FOREIGN KEY (draft_id, draft_revision) REFERENCES inventory_drafts(draft_id, draft_revision)
) STRICT;

CREATE INDEX inventory_drafts_list_idx ON inventory_drafts(created_at, draft_id, draft_revision);
CREATE INDEX inventory_draft_records_asset_idx ON inventory_draft_assets(draft_id, draft_revision, local_id, ordinal);
CREATE INDEX inventory_draft_records_node_idx ON inventory_draft_nodes(draft_id, draft_revision, local_id, ordinal);

CREATE TRIGGER inventory_drafts_no_update BEFORE UPDATE ON inventory_drafts BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_drafts_no_delete BEFORE DELETE ON inventory_drafts BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_import_keys_no_update BEFORE UPDATE ON inventory_import_keys BEGIN SELECT RAISE(ABORT, 'inventory import binding is immutable'); END;
CREATE TRIGGER inventory_import_keys_no_delete BEFORE DELETE ON inventory_import_keys BEGIN SELECT RAISE(ABORT, 'inventory import binding is immutable'); END;
CREATE TRIGGER inventory_source_bindings_no_update BEFORE UPDATE ON inventory_source_bindings BEGIN SELECT RAISE(ABORT, 'inventory source binding is immutable'); END;
CREATE TRIGGER inventory_source_bindings_no_delete BEFORE DELETE ON inventory_source_bindings BEGIN SELECT RAISE(ABORT, 'inventory source binding is immutable'); END;
CREATE TRIGGER inventory_draft_assets_no_update BEFORE UPDATE ON inventory_draft_assets BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_assets_no_delete BEFORE DELETE ON inventory_draft_assets BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_identities_no_update BEFORE UPDATE ON inventory_draft_identities BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_identities_no_delete BEFORE DELETE ON inventory_draft_identities BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_hardware_facts_no_update BEFORE UPDATE ON inventory_draft_hardware_facts BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_hardware_facts_no_delete BEFORE DELETE ON inventory_draft_hardware_facts BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_nodes_no_update BEFORE UPDATE ON inventory_draft_nodes BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_nodes_no_delete BEFORE DELETE ON inventory_draft_nodes BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_aliases_no_update BEFORE UPDATE ON inventory_draft_aliases BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_aliases_no_delete BEFORE DELETE ON inventory_draft_aliases BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_addresses_no_update BEFORE UPDATE ON inventory_draft_addresses BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_addresses_no_delete BEFORE DELETE ON inventory_draft_addresses BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_observations_no_update BEFORE UPDATE ON inventory_draft_observations BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_observations_no_delete BEFORE DELETE ON inventory_draft_observations BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_provenance_no_update BEFORE UPDATE ON inventory_draft_provenance BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_provenance_no_delete BEFORE DELETE ON inventory_draft_provenance BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_findings_no_update BEFORE UPDATE ON inventory_draft_findings BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
CREATE TRIGGER inventory_draft_findings_no_delete BEFORE DELETE ON inventory_draft_findings BEGIN SELECT RAISE(ABORT, 'inventory draft is immutable'); END;
