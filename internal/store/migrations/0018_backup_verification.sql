-- #117 exact local verification. Immutable attempts are distinct from the
-- pending creation receipt; a failed or fixture attempt never edits a point.
CREATE TABLE backup_read_leases (
    lease_id TEXT PRIMARY KEY CHECK (length(lease_id) BETWEEN 1 AND 128),
    point_id TEXT NOT NULL REFERENCES recovery_points(point_id),
    repository_id TEXT NOT NULL CHECK (length(repository_id) BETWEEN 1 AND 128),
    repository_class TEXT NOT NULL CHECK (repository_class IN ('standard','critical')),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    maximum_expires_at TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    released_at TEXT
) STRICT;

CREATE UNIQUE INDEX backup_read_leases_active_idx ON backup_read_leases(repository_class) WHERE released_at IS NULL;
CREATE TRIGGER backup_read_leases_no_delete BEFORE DELETE ON backup_read_leases BEGIN SELECT RAISE(ABORT, 'backup read leases are retained'); END;

CREATE TABLE backup_local_verifications (
    verification_id TEXT PRIMARY KEY CHECK (length(verification_id) BETWEEN 1 AND 128),
    point_id TEXT NOT NULL REFERENCES recovery_points(point_id),
    read_lease_id TEXT NOT NULL REFERENCES backup_read_leases(lease_id),
    status TEXT NOT NULL CHECK (status IN ('fixture-only','local-verified','failed','uncertain')),
    proof_class TEXT NOT NULL CHECK (proof_class IN ('fixture','live')),
    manifest_digest TEXT NOT NULL CHECK (length(manifest_digest)=71 AND substr(manifest_digest,1,7)='sha256:'),
    inventory_digest TEXT NOT NULL CHECK (length(inventory_digest)=71 AND substr(inventory_digest,1,7)='sha256:'),
    observed_digest TEXT NOT NULL CHECK (length(observed_digest)=71 AND substr(observed_digest,1,7)='sha256:'),
    content_digest TEXT NOT NULL CHECK (length(content_digest)=71 AND substr(content_digest,1,7)='sha256:'),
    catalog_digest TEXT NOT NULL CHECK (length(catalog_digest)=71 AND substr(catalog_digest,1,7)='sha256:'),
    dependency_digest TEXT NOT NULL CHECK (length(dependency_digest)=71 AND substr(dependency_digest,1,7)='sha256:'),
    key_reference_id TEXT NOT NULL CHECK (length(key_reference_id) BETWEEN 1 AND 128),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    full_read_at TEXT,
    functional_restored_at TEXT,
    reason_code TEXT NOT NULL,
    created_at TEXT NOT NULL
) STRICT;

CREATE INDEX backup_local_verifications_point_idx ON backup_local_verifications(point_id, created_at);
CREATE TRIGGER backup_local_verifications_no_update BEFORE UPDATE ON backup_local_verifications BEGIN SELECT RAISE(ABORT, 'backup verification attempts are append-only'); END;
CREATE TRIGGER backup_local_verifications_no_delete BEFORE DELETE ON backup_local_verifications BEGIN SELECT RAISE(ABORT, 'backup verification attempts are append-only'); END;

CREATE TABLE backup_local_last_good (
    repository_class TEXT PRIMARY KEY CHECK (repository_class IN ('standard','critical')),
    point_id TEXT NOT NULL REFERENCES recovery_points(point_id),
    verification_id TEXT NOT NULL REFERENCES backup_local_verifications(verification_id),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    advanced_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER backup_local_last_good_no_delete BEFORE DELETE ON backup_local_last_good BEGIN SELECT RAISE(ABORT, 'last-good is retained'); END;
