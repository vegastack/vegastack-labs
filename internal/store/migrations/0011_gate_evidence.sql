-- Issue #104: inert gate drafts, immutable applied evidence and applied
-- profile/policy bindings. No stored passed flag or mutable status shortcut.
CREATE TABLE gate_evidence_drafts (
    draft_id TEXT PRIMARY KEY CHECK (length(draft_id) BETWEEN 1 AND 128),
    evidence_id TEXT NOT NULL UNIQUE CHECK (length(evidence_id) BETWEEN 1 AND 128),
    gate_id TEXT NOT NULL CHECK (length(gate_id) BETWEEN 1 AND 128),
    subject_id TEXT NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 128),
    definition_version TEXT NOT NULL,
    evaluator_version TEXT NOT NULL,
    source_kind TEXT NOT NULL CHECK (source_kind IN ('fixture','local','independent')),
    proof_class TEXT NOT NULL CHECK (proof_class IN ('fixture','live')),
    supersedes_evidence_id TEXT,
    revokes_evidence_id TEXT,
    artifact_digest TEXT NOT NULL CHECK (length(artifact_digest) = 71 AND substr(artifact_digest,1,7) = 'sha256:'),
    bundle_digest TEXT NOT NULL CHECK (length(bundle_digest) = 71 AND substr(bundle_digest,1,7) = 'sha256:'),
    bundle_bytes BLOB NOT NULL CHECK (length(bundle_bytes) BETWEEN 1 AND 65536),
    observed_at TEXT NOT NULL,
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    human_id TEXT NOT NULL CHECK (length(human_id) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL,
    CHECK (supersedes_evidence_id IS NULL OR revokes_evidence_id IS NULL)
) STRICT;

CREATE TABLE gate_applied_evidence (
    evidence_id TEXT PRIMARY KEY CHECK (length(evidence_id) BETWEEN 1 AND 128),
    draft_id TEXT NOT NULL,
    gate_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('applied','revoked')),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('fixture','local','independent')),
    proof_class TEXT NOT NULL CHECK (proof_class IN ('fixture','live')),
    bundle_digest TEXT NOT NULL CHECK (length(bundle_digest) = 71 AND substr(bundle_digest,1,7) = 'sha256:'),
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) BETWEEN 1 AND 65536),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    declaration_id TEXT NOT NULL,
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND substr(plan_digest,1,7) = 'sha256:'),
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    supersedes_evidence_id TEXT,
    revokes_evidence_id TEXT,
    applied_at TEXT NOT NULL,
    FOREIGN KEY (draft_id) REFERENCES gate_evidence_drafts(draft_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX gate_applied_evidence_subject_idx
ON gate_applied_evidence(gate_id,subject_id,recovery_epoch,state_revision,evidence_id);

CREATE TABLE gate_profile_drafts (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) BETWEEN 1 AND 128),
    scope_bytes BLOB NOT NULL CHECK (length(scope_bytes) BETWEEN 2 AND 4096),
    scope_digest TEXT NOT NULL CHECK (length(scope_digest) = 71 AND substr(scope_digest,1,7) = 'sha256:'),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    human_id TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE TABLE gate_applied_profiles (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) BETWEEN 1 AND 128),
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    capabilities_bytes BLOB NOT NULL CHECK (length(capabilities_bytes) BETWEEN 2 AND 4096),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    declaration_id TEXT NOT NULL,
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    plan_id TEXT NOT NULL,
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND substr(plan_digest,1,7) = 'sha256:'),
    run_id TEXT NOT NULL,
    step_id TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    human_id TEXT NOT NULL,
    applied_at TEXT NOT NULL
) STRICT;

CREATE INDEX gate_applied_profiles_current_idx
ON gate_applied_profiles(recovery_epoch,state_revision,binding_id);

CREATE TRIGGER gate_evidence_drafts_no_update BEFORE UPDATE ON gate_evidence_drafts
BEGIN SELECT RAISE(ABORT,'gate drafts are append-only'); END;
CREATE TRIGGER gate_evidence_drafts_no_delete BEFORE DELETE ON gate_evidence_drafts
BEGIN SELECT RAISE(ABORT,'gate drafts are append-only'); END;
CREATE TRIGGER gate_applied_evidence_no_update BEFORE UPDATE ON gate_applied_evidence
BEGIN SELECT RAISE(ABORT,'gate evidence is append-only'); END;
CREATE TRIGGER gate_applied_evidence_no_delete BEFORE DELETE ON gate_applied_evidence
BEGIN SELECT RAISE(ABORT,'gate evidence is append-only'); END;
CREATE TRIGGER gate_applied_profiles_no_update BEFORE UPDATE ON gate_applied_profiles
BEGIN SELECT RAISE(ABORT,'gate profiles are append-only'); END;
CREATE TRIGGER gate_applied_profiles_no_delete BEFORE DELETE ON gate_applied_profiles
BEGIN SELECT RAISE(ABORT,'gate profiles are append-only'); END;
CREATE TRIGGER gate_profile_drafts_no_update BEFORE UPDATE ON gate_profile_drafts
BEGIN SELECT RAISE(ABORT,'gate profile drafts are append-only'); END;
CREATE TRIGGER gate_profile_drafts_no_delete BEFORE DELETE ON gate_profile_drafts
BEGIN SELECT RAISE(ABORT,'gate profile drafts are append-only'); END;
