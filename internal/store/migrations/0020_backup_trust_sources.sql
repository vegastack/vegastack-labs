-- #154 revisioned signed dependency-trust sources. Drafts are inert; only an
-- exact plan/run/lease binding can make a source current. Artifact, bundle and
-- root bytes remain outside SQLite; this catalog stores public IDs and digests.
CREATE TABLE backup_trust_source_drafts (
    source_id TEXT NOT NULL CHECK (length(source_id) BETWEEN 1 AND 128),
    dependency_id TEXT NOT NULL CHECK (length(dependency_id) BETWEEN 1 AND 128),
    dependency_kind TEXT NOT NULL CHECK (dependency_kind IN ('config','image','signature')),
    artifact_id TEXT NOT NULL CHECK (length(artifact_id) BETWEEN 1 AND 128),
    artifact_digest TEXT NOT NULL CHECK (length(artifact_digest)=71 AND substr(artifact_digest,1,7)='sha256:'),
    bundle_digest TEXT NOT NULL CHECK (length(bundle_digest)=71 AND substr(bundle_digest,1,7)='sha256:'),
    trusted_root_reference_id TEXT NOT NULL CHECK (length(trusted_root_reference_id) BETWEEN 1 AND 128),
    trust_root_digest TEXT NOT NULL CHECK (length(trust_root_digest)=71 AND substr(trust_root_digest,1,7)='sha256:'),
    signer_identity TEXT NOT NULL CHECK (length(signer_identity) BETWEEN 1 AND 512),
    signer_issuer TEXT NOT NULL CHECK (length(signer_issuer) BETWEEN 1 AND 512),
    revision INTEGER NOT NULL CHECK (revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    source_digest TEXT NOT NULL UNIQUE CHECK (length(source_digest)=71 AND substr(source_digest,1,7)='sha256:'),
    idempotency_key_digest TEXT NOT NULL CHECK (length(idempotency_key_digest)=71 AND substr(idempotency_key_digest,1,7)='sha256:'),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL,
    PRIMARY KEY(source_id, revision, recovery_epoch),
    UNIQUE(idempotency_key_digest, recovery_epoch)
) STRICT;

CREATE TABLE backup_trust_source_bindings (
    binding_id TEXT PRIMARY KEY CHECK (length(binding_id) BETWEEN 1 AND 128),
    source_id TEXT NOT NULL,
    dependency_id TEXT NOT NULL CHECK (length(dependency_id) BETWEEN 1 AND 128),
    source_revision INTEGER NOT NULL CHECK (source_revision > 0),
    status TEXT NOT NULL CHECK (status IN ('current','revoked')),
    plan_id TEXT NOT NULL CHECK (length(plan_id) BETWEEN 1 AND 128),
    plan_digest TEXT NOT NULL CHECK (length(plan_digest)=71 AND substr(plan_digest,1,7)='sha256:'),
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 128),
    step_id TEXT NOT NULL CHECK (length(step_id) BETWEEN 1 AND 128),
    lease_id TEXT NOT NULL CHECK (length(lease_id) BETWEEN 1 AND 128),
    declaration_id TEXT NOT NULL CHECK (length(declaration_id) BETWEEN 1 AND 128),
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    applied_by TEXT NOT NULL CHECK (length(applied_by) BETWEEN 1 AND 128),
    applied_at TEXT NOT NULL,
    FOREIGN KEY(source_id, source_revision, recovery_epoch)
      REFERENCES backup_trust_source_drafts(source_id, revision, recovery_epoch)
) STRICT;

CREATE INDEX backup_trust_bindings_source_idx ON backup_trust_source_bindings(source_id, state_revision DESC);
CREATE INDEX backup_trust_bindings_dependency_idx ON backup_trust_source_bindings(dependency_id, state_revision DESC);
CREATE TRIGGER backup_trust_source_drafts_no_update BEFORE UPDATE ON backup_trust_source_drafts BEGIN SELECT RAISE(ABORT, 'backup trust drafts are append-only'); END;
CREATE TRIGGER backup_trust_source_drafts_no_delete BEFORE DELETE ON backup_trust_source_drafts BEGIN SELECT RAISE(ABORT, 'backup trust drafts are retained'); END;
CREATE TRIGGER backup_trust_source_bindings_no_update BEFORE UPDATE ON backup_trust_source_bindings BEGIN SELECT RAISE(ABORT, 'backup trust bindings are append-only'); END;
CREATE TRIGGER backup_trust_source_bindings_no_delete BEFORE DELETE ON backup_trust_source_bindings BEGIN SELECT RAISE(ABORT, 'backup trust bindings are retained'); END;
