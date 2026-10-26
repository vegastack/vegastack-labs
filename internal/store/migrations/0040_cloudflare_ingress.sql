-- #279: inert payloads, explicit resource ownership and sanitized observations.
CREATE TABLE ingress_drafts (
 draft_id TEXT PRIMARY KEY,
 digest TEXT NOT NULL,
 request_bytes BLOB NOT NULL,
 bindings_bytes BLOB NOT NULL,
 actor_id TEXT NOT NULL,
 actor_method TEXT NOT NULL,
 actor_device TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL
) STRICT;
CREATE TABLE ingress_ownership (
 profile_id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 scope_digest TEXT NOT NULL,
 resource_key TEXT NOT NULL,
 draft_id TEXT NOT NULL REFERENCES ingress_drafts(draft_id),
 run_id TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL,
 PRIMARY KEY(profile_id,revision)
) STRICT;
CREATE TABLE ingress_observations (
 observation_id TEXT PRIMARY KEY,
 profile_id TEXT NOT NULL,
 draft_id TEXT NOT NULL REFERENCES ingress_drafts(draft_id),
 run_id TEXT NOT NULL,
 status TEXT NOT NULL,
 reason TEXT NOT NULL,
 observation_digest TEXT NOT NULL,
 observed_at TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL
) STRICT;
CREATE TRIGGER ingress_drafts_no_update BEFORE UPDATE ON ingress_drafts BEGIN SELECT RAISE(ABORT,'Ingress drafts immutable'); END;
CREATE TRIGGER ingress_drafts_no_delete BEFORE DELETE ON ingress_drafts BEGIN SELECT RAISE(ABORT,'Ingress drafts immutable'); END;
CREATE TRIGGER ingress_ownership_no_update BEFORE UPDATE ON ingress_ownership BEGIN SELECT RAISE(ABORT,'Ingress ownership immutable'); END;
CREATE TRIGGER ingress_ownership_no_delete BEFORE DELETE ON ingress_ownership BEGIN SELECT RAISE(ABORT,'Ingress ownership immutable'); END;
CREATE TRIGGER ingress_observations_no_update BEFORE UPDATE ON ingress_observations BEGIN SELECT RAISE(ABORT,'Ingress observations immutable'); END;
CREATE TRIGGER ingress_observations_no_delete BEFORE DELETE ON ingress_observations BEGIN SELECT RAISE(ABORT,'Ingress observations immutable'); END;

CREATE TRIGGER ingress_resource_one_owner BEFORE INSERT ON ingress_ownership WHEN EXISTS(SELECT 1 FROM ingress_ownership WHERE resource_key=NEW.resource_key AND profile_id!=NEW.profile_id) BEGIN SELECT RAISE(ABORT,'Ingress resource already owned'); END;
CREATE TABLE ingress_rotation_runs (
 run_id TEXT PRIMARY KEY,
 profile_id TEXT NOT NULL,
 draft_id TEXT NOT NULL REFERENCES ingress_drafts(draft_id),
 material_version TEXT NOT NULL,
 old_connections_bytes BLOB NOT NULL,
 provider_acknowledged INTEGER NOT NULL CHECK(provider_acknowledged IN (0,1)),
 recovery_epoch INTEGER NOT NULL
) STRICT;
CREATE TRIGGER ingress_rotation_runs_no_update BEFORE UPDATE ON ingress_rotation_runs BEGIN SELECT RAISE(ABORT,'Ingress rotation receipts immutable'); END;
CREATE TRIGGER ingress_rotation_runs_no_delete BEFORE DELETE ON ingress_rotation_runs BEGIN SELECT RAISE(ABORT,'Ingress rotation receipts immutable'); END;

CREATE TABLE ingress_rollout_observations (
 request_id TEXT PRIMARY KEY,
 request_digest TEXT NOT NULL,
 rotation_run_id TEXT NOT NULL REFERENCES ingress_rotation_runs(run_id),
 profile_id TEXT NOT NULL,
 rotation_stage TEXT NOT NULL,
 reason TEXT NOT NULL,
 observation_digest TEXT NOT NULL,
 observed_at TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL
) STRICT;
CREATE TRIGGER ingress_rollout_observations_no_update BEFORE UPDATE ON ingress_rollout_observations BEGIN SELECT RAISE(ABORT,'Ingress rollout observations immutable'); END;
CREATE TRIGGER ingress_rollout_observations_no_delete BEFORE DELETE ON ingress_rollout_observations BEGIN SELECT RAISE(ABORT,'Ingress rollout observations immutable'); END;
