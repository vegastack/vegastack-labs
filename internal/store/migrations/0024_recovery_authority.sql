-- Issue #108: inert, exact restore plans and append-only recovery history.
ALTER TABLE system_meta ADD COLUMN instance_id TEXT NOT NULL DEFAULT 'instance-uninitialized'
    CHECK (length(instance_id) BETWEEN 10 AND 128);
ALTER TABLE system_meta ADD COLUMN authority_mode TEXT NOT NULL DEFAULT 'ready'
    CHECK (authority_mode IN ('ready','recovery-required'));

UPDATE system_meta
SET instance_id = (SELECT instance_id FROM audit_instances WHERE id = 1)
WHERE id = 1;

-- Recovery introduces a new immutable controller identity for each epoch. The
-- original one-row instance catalog cannot represent that without rewriting
-- history, so rebuild the audit tables while preserving every row and digest.
DROP TRIGGER audit_epoch_genesis_no_update;
DROP TRIGGER audit_epoch_genesis_no_delete;
DROP TRIGGER audit_chain_links_no_update;
DROP TRIGGER audit_chain_links_no_delete;
DROP INDEX audit_chain_epoch_sequence;
ALTER TABLE audit_checkpoint_outbox RENAME TO audit_checkpoint_outbox_before_recovery;
ALTER TABLE audit_checkpoints RENAME TO audit_checkpoints_before_recovery;
ALTER TABLE audit_chain_links RENAME TO audit_chain_links_before_recovery;
ALTER TABLE audit_epoch_genesis RENAME TO audit_epoch_genesis_before_recovery;
ALTER TABLE audit_instances RENAME TO audit_instances_before_recovery;

CREATE TABLE audit_instances (
    instance_id TEXT PRIMARY KEY CHECK (length(instance_id) BETWEEN 10 AND 128),
    created_at TEXT NOT NULL
) STRICT;
INSERT INTO audit_instances(instance_id,created_at)
SELECT instance_id,created_at FROM audit_instances_before_recovery;

CREATE TABLE audit_epoch_genesis (
    recovery_epoch INTEGER PRIMARY KEY CHECK (recovery_epoch >= 0),
    instance_id TEXT NOT NULL,
    prior_checkpoint_digest TEXT NOT NULL CHECK (prior_checkpoint_digest GLOB 'sha256:[0-9a-f]*' AND length(prior_checkpoint_digest) = 71),
    recovery_decision_digest TEXT NOT NULL CHECK (recovery_decision_digest GLOB 'sha256:[0-9a-f]*' AND length(recovery_decision_digest) = 71),
    genesis_digest TEXT NOT NULL UNIQUE CHECK (genesis_digest GLOB 'sha256:[0-9a-f]*' AND length(genesis_digest) = 71),
    FOREIGN KEY(instance_id) REFERENCES audit_instances(instance_id) ON DELETE RESTRICT
) STRICT;
INSERT INTO audit_epoch_genesis SELECT recovery_epoch,instance_id,prior_checkpoint_digest,recovery_decision_digest,genesis_digest FROM audit_epoch_genesis_before_recovery;

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
    pre_anchor INTEGER NOT NULL CHECK (pre_anchor IN (0,1)),
    UNIQUE(instance_id,recovery_epoch,segment_sequence),
    FOREIGN KEY(event_id) REFERENCES audit_events(event_id) ON DELETE RESTRICT,
    FOREIGN KEY(recovery_epoch) REFERENCES audit_epoch_genesis(recovery_epoch) ON DELETE RESTRICT
) STRICT;
INSERT INTO audit_chain_links SELECT event_id,instance_id,recovery_epoch,segment_sequence,previous_digest,payload_digest,context_bytes,context_digest,link_digest,pre_anchor FROM audit_chain_links_before_recovery;

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
    pre_anchor INTEGER NOT NULL CHECK (pre_anchor IN (0,1)),
    canonical_bytes BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(instance_id) REFERENCES audit_instances(instance_id) ON DELETE RESTRICT
) STRICT;
INSERT INTO audit_checkpoints SELECT checkpoint_id,schema_version,instance_id,recovery_epoch,first_event_id,last_event_id,first_segment_sequence,last_segment_sequence,chain_digest,signer_reference_id,signer_material_version,signature_digest,public_key_id,export_namespace,export_receipt_digest,independent_read_digest,status,reason_code,pre_anchor,canonical_bytes,created_at,updated_at FROM audit_checkpoints_before_recovery;

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
INSERT INTO audit_checkpoint_outbox SELECT checkpoint_id,exact_path,encrypted_payload,payload_digest,status,attempt_count,last_error_code,next_attempt_at,updated_at FROM audit_checkpoint_outbox_before_recovery;

DROP TABLE audit_checkpoint_outbox_before_recovery;
DROP TABLE audit_checkpoints_before_recovery;
DROP TABLE audit_chain_links_before_recovery;
DROP TABLE audit_epoch_genesis_before_recovery;
DROP TABLE audit_instances_before_recovery;

CREATE INDEX audit_chain_epoch_sequence ON audit_chain_links(recovery_epoch,segment_sequence);
CREATE TRIGGER audit_epoch_genesis_no_update BEFORE UPDATE ON audit_epoch_genesis BEGIN SELECT RAISE(ABORT,'audit epoch genesis is immutable'); END;
CREATE TRIGGER audit_epoch_genesis_no_delete BEFORE DELETE ON audit_epoch_genesis BEGIN SELECT RAISE(ABORT,'audit epoch genesis is append-only'); END;
CREATE TRIGGER audit_chain_links_no_update BEFORE UPDATE ON audit_chain_links BEGIN SELECT RAISE(ABORT,'audit chain links are immutable'); END;
CREATE TRIGGER audit_chain_links_no_delete BEFORE DELETE ON audit_chain_links BEGIN SELECT RAISE(ABORT,'audit chain links are append-only'); END;

CREATE TABLE restore_sessions (
    plan_id TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL UNIQUE CHECK (plan_digest GLOB 'sha256:[0-9a-f]*' AND length(plan_digest) = 71),
    declaration_id TEXT NOT NULL,
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    human_acknowledgement_id TEXT NOT NULL UNIQUE,
    point_id TEXT NOT NULL,
    point_digest TEXT NOT NULL CHECK (point_digest GLOB 'sha256:[0-9a-f]*' AND length(point_digest) = 71),
    dependency_digest TEXT NOT NULL CHECK (dependency_digest GLOB 'sha256:[0-9a-f]*' AND length(dependency_digest) = 71),
    fence_set_digest TEXT NOT NULL CHECK (fence_set_digest GLOB 'sha256:[0-9a-f]*' AND length(fence_set_digest) = 71),
    audit_decision_digest TEXT NOT NULL CHECK (audit_decision_digest GLOB 'sha256:[0-9a-f]*' AND length(audit_decision_digest) = 71),
    target_digest TEXT NOT NULL CHECK (target_digest GLOB 'sha256:[0-9a-f]*' AND length(target_digest) = 71),
    candidate_digest TEXT NOT NULL CHECK (candidate_digest GLOB 'sha256:[0-9a-f]*' AND length(candidate_digest) = 71),
    prior_instance_id TEXT NOT NULL,
    new_instance_id TEXT NOT NULL CHECK (new_instance_id <> prior_instance_id),
    prior_recovery_epoch INTEGER NOT NULL CHECK (prior_recovery_epoch >= 0),
    next_recovery_epoch INTEGER NOT NULL CHECK (next_recovery_epoch = prior_recovery_epoch + 1),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes) > 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY(plan_id) REFERENCES immutable_plans(plan_id) ON DELETE RESTRICT,
    FOREIGN KEY(human_acknowledgement_id) REFERENCES acknowledgement_requests(acknowledgement_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE restore_plan_qualifications (
    plan_id TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL UNIQUE CHECK (plan_digest GLOB 'sha256:[0-9a-f]*' AND length(plan_digest) = 71),
    request_bytes BLOB NOT NULL CHECK (length(request_bytes) > 0),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes) > 0),
    source_digest TEXT NOT NULL CHECK (source_digest GLOB 'sha256:[0-9a-f]*' AND length(source_digest) = 71),
    fence_set_digest TEXT NOT NULL CHECK (fence_set_digest GLOB 'sha256:[0-9a-f]*' AND length(fence_set_digest) = 71),
    audit_decision_digest TEXT NOT NULL CHECK (audit_decision_digest GLOB 'sha256:[0-9a-f]*' AND length(audit_decision_digest) = 71),
    created_at TEXT NOT NULL,
    FOREIGN KEY(plan_id) REFERENCES immutable_plans(plan_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE restore_transitions (
    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id TEXT NOT NULL,
    from_status TEXT NOT NULL CHECK (from_status IN ('planned','fenced','restoring','verification-required','verified','failed','uncertain')),
    to_status TEXT NOT NULL CHECK (to_status IN ('fenced','restoring','verification-required','verified','failed','uncertain')),
    plan_digest TEXT NOT NULL CHECK (plan_digest GLOB 'sha256:[0-9a-f]*' AND length(plan_digest) = 71),
    evidence_digest TEXT NOT NULL CHECK (evidence_digest GLOB 'sha256:[0-9a-f]*' AND length(evidence_digest) = 71),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    UNIQUE(plan_id, from_status),
    FOREIGN KEY(plan_id) REFERENCES restore_sessions(plan_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE recovery_candidates (
    candidate_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL UNIQUE,
    candidate_digest TEXT NOT NULL UNIQUE CHECK (candidate_digest GLOB 'sha256:[0-9a-f]*' AND length(candidate_digest) = 71),
    preserved_authority_digest TEXT NOT NULL CHECK (preserved_authority_digest GLOB 'sha256:[0-9a-f]*' AND length(preserved_authority_digest) = 71),
    fence_set_digest TEXT NOT NULL CHECK (fence_set_digest GLOB 'sha256:[0-9a-f]*' AND length(fence_set_digest) = 71),
    audit_decision_digest TEXT NOT NULL CHECK (audit_decision_digest GLOB 'sha256:[0-9a-f]*' AND length(audit_decision_digest) = 71),
    database_digest TEXT NOT NULL CHECK (database_digest GLOB 'sha256:[0-9a-f]*' AND length(database_digest) = 71),
    journal_digest TEXT NOT NULL CHECK (journal_digest GLOB 'sha256:[0-9a-f]*' AND length(journal_digest) = 71),
    bundle_digest TEXT NOT NULL CHECK (bundle_digest GLOB 'sha256:[0-9a-f]*' AND length(bundle_digest) = 71),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    FOREIGN KEY(plan_id) REFERENCES restore_sessions(plan_id) ON DELETE RESTRICT
) STRICT;

-- The chosen point can predate the plan that authorized its recovery, so the
-- promoted candidate keeps a self-contained append-only authority journal.
CREATE TABLE recovery_authority_journal (
    plan_id TEXT NOT NULL,
    transition TEXT NOT NULL CHECK (transition IN ('promoted','verified')),
    plan_digest TEXT NOT NULL CHECK (plan_digest GLOB 'sha256:[0-9a-f]*' AND length(plan_digest)=71),
    candidate_digest TEXT NOT NULL CHECK (candidate_digest GLOB 'sha256:[0-9a-f]*' AND length(candidate_digest)=71),
    fence_set_digest TEXT NOT NULL CHECK (fence_set_digest GLOB 'sha256:[0-9a-f]*' AND length(fence_set_digest)=71),
    audit_decision_digest TEXT NOT NULL CHECK (audit_decision_digest GLOB 'sha256:[0-9a-f]*' AND length(audit_decision_digest)=71),
    instance_id TEXT NOT NULL REFERENCES audit_instances(instance_id) ON DELETE RESTRICT,
    recovery_epoch INTEGER NOT NULL REFERENCES audit_epoch_genesis(recovery_epoch) ON DELETE RESTRICT,
    evidence_digest TEXT NOT NULL CHECK (evidence_digest GLOB 'sha256:[0-9a-f]*' AND length(evidence_digest)=71),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes)>0),
    created_at TEXT NOT NULL,
    PRIMARY KEY(plan_id,transition)
) STRICT;

CREATE TABLE recovery_authority_bundles (
    plan_id TEXT PRIMARY KEY,
    plan_digest TEXT NOT NULL UNIQUE CHECK (plan_digest GLOB 'sha256:[0-9a-f]*' AND length(plan_digest)=71),
    bundle_digest TEXT NOT NULL UNIQUE CHECK (bundle_digest GLOB 'sha256:[0-9a-f]*' AND length(bundle_digest)=71),
    plan_bytes BLOB NOT NULL CHECK (length(plan_bytes)>0),
    readable_plan TEXT NOT NULL CHECK (length(readable_plan)>0),
    request_bytes BLOB NOT NULL CHECK (length(request_bytes)>0),
    binding_bytes BLOB NOT NULL CHECK (length(binding_bytes)>0),
    status TEXT NOT NULL CHECK (status='verification-required'),
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX restore_transitions_plan_sequence ON restore_transitions(plan_id, transition_id);

CREATE TRIGGER restore_sessions_no_update BEFORE UPDATE ON restore_sessions BEGIN SELECT RAISE(ABORT, 'restore sessions are immutable'); END;
CREATE TRIGGER restore_sessions_no_delete BEFORE DELETE ON restore_sessions BEGIN SELECT RAISE(ABORT, 'restore sessions are append-only'); END;
CREATE TRIGGER restore_plan_qualifications_no_update BEFORE UPDATE ON restore_plan_qualifications BEGIN SELECT RAISE(ABORT, 'restore plan qualifications are immutable'); END;
CREATE TRIGGER restore_plan_qualifications_no_delete BEFORE DELETE ON restore_plan_qualifications BEGIN SELECT RAISE(ABORT, 'restore plan qualifications are append-only'); END;
CREATE TRIGGER restore_transitions_no_update BEFORE UPDATE ON restore_transitions BEGIN SELECT RAISE(ABORT, 'restore transitions are immutable'); END;
CREATE TRIGGER restore_transitions_no_delete BEFORE DELETE ON restore_transitions BEGIN SELECT RAISE(ABORT, 'restore transitions are append-only'); END;
CREATE TRIGGER recovery_candidates_no_update BEFORE UPDATE ON recovery_candidates BEGIN SELECT RAISE(ABORT, 'recovery candidates are immutable'); END;
CREATE TRIGGER recovery_candidates_no_delete BEFORE DELETE ON recovery_candidates BEGIN SELECT RAISE(ABORT, 'recovery candidates are append-only'); END;
CREATE TRIGGER recovery_authority_journal_no_update BEFORE UPDATE ON recovery_authority_journal BEGIN SELECT RAISE(ABORT,'recovery authority journal is immutable'); END;
CREATE TRIGGER recovery_authority_journal_no_delete BEFORE DELETE ON recovery_authority_journal BEGIN SELECT RAISE(ABORT,'recovery authority journal is append-only'); END;
CREATE TRIGGER recovery_authority_bundles_no_update BEFORE UPDATE ON recovery_authority_bundles BEGIN SELECT RAISE(ABORT,'recovery authority bundles are immutable'); END;
CREATE TRIGGER recovery_authority_bundles_no_delete BEFORE DELETE ON recovery_authority_bundles BEGIN SELECT RAISE(ABORT,'recovery authority bundles are append-only'); END;
