-- #106 inert local recovery-point creation state. No plaintext secret, key
-- material, or repository password is ever stored here; only opaque reference
-- IDs, canonical policy bytes and SHA-256 digests. There is deliberately no
-- last-good column: a pending point never advances local last-good (that is
-- #117's independent verification concern).
CREATE TABLE backup_policy_drafts (
    draft_id TEXT PRIMARY KEY CHECK (length(draft_id) BETWEEN 1 AND 128),
    policy_id TEXT NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 128),
    owner_id TEXT NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 128),
    repository_class TEXT NOT NULL CHECK (repository_class IN ('none','standard','critical')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    canonical_json TEXT NOT NULL CHECK (length(canonical_json) BETWEEN 2 AND 65536),
    policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 71 AND substr(policy_digest,1,7) = 'sha256:'),
    idempotency_key_digest TEXT NOT NULL CHECK (length(idempotency_key_digest) = 71 AND substr(idempotency_key_digest,1,7) = 'sha256:'),
    state_revision INTEGER NOT NULL CHECK (state_revision > 0),
    created_by TEXT NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL,
    UNIQUE(recovery_epoch, idempotency_key_digest),
    UNIQUE(policy_id, revision, recovery_epoch),
    UNIQUE(policy_digest, recovery_epoch)
) STRICT;

CREATE INDEX backup_policy_drafts_digest_idx
ON backup_policy_drafts(policy_digest, recovery_epoch, state_revision, draft_id);

CREATE TRIGGER backup_policy_drafts_no_update BEFORE UPDATE ON backup_policy_drafts
BEGIN SELECT RAISE(ABORT, 'backup policy drafts are append-only'); END;
CREATE TRIGGER backup_policy_drafts_no_delete BEFORE DELETE ON backup_policy_drafts
BEGIN SELECT RAISE(ABORT, 'backup policy drafts are append-only'); END;

-- backup_jobs track one exact policy-bound creation attempt. #106 never writes
-- 'verified': that status is reserved for #117's independent verification. Jobs
-- transition queued->running->pending|failed|uncertain and are never deleted.
CREATE TABLE backup_jobs (
    job_id TEXT PRIMARY KEY CHECK (length(job_id) BETWEEN 1 AND 128),
    policy_id TEXT NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 128),
    policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 71 AND substr(policy_digest,1,7) = 'sha256:'),
    repository_id TEXT NOT NULL CHECK (length(repository_id) BETWEEN 1 AND 128),
    repository_class TEXT NOT NULL CHECK (repository_class IN ('standard','critical')),
    run_id TEXT CHECK (run_id IS NULL OR length(run_id) BETWEEN 1 AND 128),
    point_id TEXT CHECK (point_id IS NULL OR length(point_id) BETWEEN 1 AND 128),
    -- #106 creates only local, fixture-class jobs. Independent/live provenance is
    -- reserved for #117's separate verification and never written here.
    source_kind TEXT NOT NULL CHECK (source_kind = 'local'),
    proof_class TEXT NOT NULL CHECK (proof_class = 'fixture'),
    status TEXT NOT NULL CHECK (status IN ('queued','running','pending','failed','uncertain')),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX backup_jobs_policy_idx ON backup_jobs(policy_id, recovery_epoch, status);

CREATE TRIGGER backup_jobs_no_delete BEFORE DELETE ON backup_jobs
BEGIN SELECT RAISE(ABORT, 'backup jobs are retained'); END;

-- recovery_points are append-only immutable pending receipts. #106 only ever
-- inserts verification_status 'pending' with a NULL verified_at; independent
-- verification and last-good qualification are owned by #117.
CREATE TABLE recovery_points (
    point_id TEXT PRIMARY KEY CHECK (length(point_id) BETWEEN 1 AND 128),
    job_id TEXT NOT NULL REFERENCES backup_jobs(job_id),
    policy_id TEXT NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 128),
    policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 71 AND substr(policy_digest,1,7) = 'sha256:'),
    repository_id TEXT NOT NULL CHECK (length(repository_id) BETWEEN 1 AND 128),
    repository_class TEXT NOT NULL CHECK (repository_class IN ('standard','critical')),
    -- A pending point is always local, fixture-class creation evidence: it can
    -- never be independent or live (that is #117's separate verification concern,
    -- recorded elsewhere, never by mutating this append-only row).
    source_kind TEXT NOT NULL CHECK (source_kind = 'local'),
    proof_class TEXT NOT NULL CHECK (proof_class = 'fixture'),
    snapshot_id TEXT NOT NULL CHECK (length(snapshot_id) BETWEEN 1 AND 128),
    snapshot_count INTEGER NOT NULL CHECK (snapshot_count >= 0),
    object_count INTEGER NOT NULL CHECK (object_count >= 0),
    object_bytes INTEGER NOT NULL CHECK (object_bytes >= 0),
    content_digest TEXT NOT NULL CHECK (length(content_digest) = 71 AND substr(content_digest,1,7) = 'sha256:'),
    manifest_digest TEXT NOT NULL CHECK (length(manifest_digest) = 71 AND substr(manifest_digest,1,7) = 'sha256:'),
    inventory_digest TEXT NOT NULL CHECK (length(inventory_digest) = 71 AND substr(inventory_digest,1,7) = 'sha256:'),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    verification_status TEXT NOT NULL CHECK (verification_status = 'pending'),
    verified_at TEXT CHECK (verified_at IS NULL),
    created_at TEXT NOT NULL,
    UNIQUE(repository_id, snapshot_id)
) STRICT;

CREATE INDEX recovery_points_policy_idx ON recovery_points(policy_id, recovery_epoch, created_at);

CREATE TRIGGER recovery_points_no_update BEFORE UPDATE ON recovery_points
BEGIN SELECT RAISE(ABORT, 'recovery points are append-only'); END;
CREATE TRIGGER recovery_points_no_delete BEFORE DELETE ON recovery_points
BEGIN SELECT RAISE(ABORT, 'recovery points are append-only'); END;

-- backup_expected_objects is the exact append-only expected snapshot/object
-- inventory bound to one point. Presence of every listed object is a
-- precondition for returning a pending point.
CREATE TABLE backup_expected_objects (
    point_id TEXT NOT NULL REFERENCES recovery_points(point_id),
    object_type TEXT NOT NULL CHECK (object_type IN ('config','keys','data','index','snapshots','locks')),
    object_name TEXT NOT NULL CHECK (length(object_name) BETWEEN 1 AND 256),
    object_bytes INTEGER NOT NULL CHECK (object_bytes >= 0),
    object_digest TEXT NOT NULL CHECK (length(object_digest) = 71 AND substr(object_digest,1,7) = 'sha256:'),
    PRIMARY KEY (point_id, object_name)
) STRICT, WITHOUT ROWID;

CREATE TRIGGER backup_expected_objects_no_update BEFORE UPDATE ON backup_expected_objects
BEGIN SELECT RAISE(ABORT, 'expected objects are append-only'); END;
CREATE TRIGGER backup_expected_objects_no_delete BEFORE DELETE ON backup_expected_objects
BEGIN SELECT RAISE(ABORT, 'expected objects are append-only'); END;

-- backup_writer_leases bind exactly one writer to a repository for one exact
-- plan/run/step at a recovery epoch. At most one active (released_at IS NULL)
-- lease may exist per repository. Leases are released, never deleted.
CREATE TABLE backup_writer_leases (
    lease_id TEXT PRIMARY KEY CHECK (length(lease_id) BETWEEN 1 AND 128),
    policy_id TEXT NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 128),
    policy_digest TEXT NOT NULL CHECK (length(policy_digest) = 71 AND substr(policy_digest,1,7) = 'sha256:'),
    job_id TEXT NOT NULL REFERENCES backup_jobs(job_id),
    point_id TEXT CHECK (point_id IS NULL OR length(point_id) BETWEEN 1 AND 128),
    plan_id TEXT NOT NULL CHECK (length(plan_id) BETWEEN 1 AND 128),
    plan_digest TEXT NOT NULL CHECK (length(plan_digest) = 71 AND substr(plan_digest,1,7) = 'sha256:'),
    run_id TEXT NOT NULL CHECK (length(run_id) BETWEEN 1 AND 128),
    step_id TEXT NOT NULL CHECK (length(step_id) BETWEEN 1 AND 128),
    repository_id TEXT NOT NULL CHECK (length(repository_id) BETWEEN 1 AND 128),
    repository_class TEXT NOT NULL CHECK (repository_class IN ('standard','critical')),
    target_id TEXT NOT NULL CHECK (length(target_id) BETWEEN 1 AND 128),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    maximum_expires_at TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    released_at TEXT CHECK (released_at IS NULL OR length(released_at) BETWEEN 1 AND 64)
) STRICT;

-- At most one active writer per physical repository root. Standard and critical
-- each map to exactly one protected root, so fencing by class (the physical root
-- identity) prevents two differently-labelled repositories from writing the same
-- root concurrently; a per-repository-id index would not.
CREATE UNIQUE INDEX backup_writer_leases_active_idx
ON backup_writer_leases(repository_class) WHERE released_at IS NULL;

CREATE TRIGGER backup_writer_leases_no_delete BEFORE DELETE ON backup_writer_leases
BEGIN SELECT RAISE(ABORT, 'backup writer leases are retained'); END;
