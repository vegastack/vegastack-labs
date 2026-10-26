-- #278: inert payloads, explicit resource ownership and sanitized observations.
CREATE TABLE mesh_drafts (
 draft_id TEXT PRIMARY KEY,
 digest TEXT NOT NULL,
 request_bytes BLOB NOT NULL,
 bindings_bytes BLOB NOT NULL,
 actor_id TEXT NOT NULL,
 actor_method TEXT NOT NULL,
 actor_device TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL
) STRICT;
CREATE TABLE mesh_ownership (
 profile_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 scope_digest TEXT NOT NULL,
 resource_key TEXT NOT NULL,
 draft_id TEXT NOT NULL REFERENCES mesh_drafts(draft_id),
 run_id TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL,
 PRIMARY KEY(profile_id,revision)
) STRICT;
CREATE TABLE mesh_observations (
 observation_id TEXT PRIMARY KEY,
 profile_id TEXT NOT NULL,
 draft_id TEXT NOT NULL REFERENCES mesh_drafts(draft_id),
 run_id TEXT NOT NULL,
 status TEXT NOT NULL,
 reason TEXT NOT NULL,
 observation_digest TEXT NOT NULL,
 observed_at TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL
) STRICT;
CREATE TRIGGER mesh_drafts_no_update BEFORE UPDATE ON mesh_drafts BEGIN SELECT RAISE(ABORT,'Mesh drafts immutable'); END;
CREATE TRIGGER mesh_drafts_no_delete BEFORE DELETE ON mesh_drafts BEGIN SELECT RAISE(ABORT,'Mesh drafts immutable'); END;
CREATE TRIGGER mesh_ownership_no_update BEFORE UPDATE ON mesh_ownership BEGIN SELECT RAISE(ABORT,'Mesh ownership immutable'); END;
CREATE TRIGGER mesh_ownership_no_delete BEFORE DELETE ON mesh_ownership BEGIN SELECT RAISE(ABORT,'Mesh ownership immutable'); END;
CREATE TRIGGER mesh_observations_no_update BEFORE UPDATE ON mesh_observations BEGIN SELECT RAISE(ABORT,'Mesh observations immutable'); END;
CREATE TRIGGER mesh_observations_no_delete BEFORE DELETE ON mesh_observations BEGIN SELECT RAISE(ABORT,'Mesh observations immutable'); END;

CREATE TRIGGER mesh_resource_one_owner BEFORE INSERT ON mesh_ownership WHEN EXISTS(SELECT 1 FROM mesh_ownership WHERE resource_key=NEW.resource_key AND profile_id!=NEW.profile_id) BEGIN SELECT RAISE(ABORT,'Mesh resource already owned'); END;
