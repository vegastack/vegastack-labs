CREATE TABLE host_discovery_drafts (
 draft_id TEXT PRIMARY KEY, target_id TEXT NOT NULL, target_revision INTEGER NOT NULL CHECK(target_revision>0),
 expected_target_revision INTEGER NOT NULL CHECK(expected_target_revision>=0), action TEXT NOT NULL CHECK(action IN ('activate','revoke')),
 digest TEXT NOT NULL CHECK(length(digest)=71), canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=16384),
 principal_id TEXT NOT NULL, state_revision INTEGER NOT NULL, recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0)
) STRICT;
CREATE TABLE host_discovery_targets (
 target_id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), draft_id TEXT NOT NULL REFERENCES host_discovery_drafts(draft_id),
 status TEXT NOT NULL CHECK(status IN ('active','revoked')), plan_id TEXT NOT NULL REFERENCES immutable_plans(plan_id),
 recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0), PRIMARY KEY(target_id,revision)
) STRICT;
CREATE TABLE host_discovery_attempts (
 attempt_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL, key_digest TEXT NOT NULL CHECK(length(key_digest)=71),
 request_digest TEXT NOT NULL CHECK(length(request_digest)=71), target_id TEXT NOT NULL, target_revision INTEGER NOT NULL,
 target_digest TEXT NOT NULL CHECK(length(target_digest)=71), grant_revision INTEGER NOT NULL CHECK(grant_revision>0),
 state_revision INTEGER NOT NULL CHECK(state_revision>=0), recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0),
 deadline TEXT NOT NULL, request_bytes BLOB NOT NULL, UNIQUE(principal_id,key_digest),
 FOREIGN KEY(target_id,target_revision) REFERENCES host_discovery_targets(target_id,revision)
) STRICT;
CREATE TABLE host_observations (
 observation_id TEXT PRIMARY KEY REFERENCES host_discovery_attempts(attempt_id), target_id TEXT NOT NULL, target_revision INTEGER NOT NULL,
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=524288), digest TEXT NOT NULL CHECK(length(digest)=71),
 state_revision INTEGER NOT NULL, recovery_epoch INTEGER NOT NULL,
 FOREIGN KEY(target_id,target_revision) REFERENCES host_discovery_targets(target_id,revision)
) STRICT;
CREATE TABLE host_observation_identities (
 observation_id TEXT NOT NULL REFERENCES host_observations(observation_id), target_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('machine-id','product-uuid','product-serial')), value_digest TEXT NOT NULL CHECK(length(value_digest)=71),
 PRIMARY KEY(observation_id,kind)
) STRICT;
CREATE INDEX host_observation_identity_lookup ON host_observation_identities(kind,value_digest,target_id);
CREATE TRIGGER host_discovery_drafts_no_update BEFORE UPDATE ON host_discovery_drafts BEGIN SELECT RAISE(ABORT,'discovery draft immutable'); END;
CREATE TRIGGER host_discovery_drafts_no_delete BEFORE DELETE ON host_discovery_drafts BEGIN SELECT RAISE(ABORT,'discovery draft durable'); END;
CREATE TRIGGER host_discovery_targets_no_update BEFORE UPDATE ON host_discovery_targets BEGIN SELECT RAISE(ABORT,'discovery target immutable'); END;
CREATE TRIGGER host_discovery_targets_no_delete BEFORE DELETE ON host_discovery_targets BEGIN SELECT RAISE(ABORT,'discovery target durable'); END;
CREATE TRIGGER host_discovery_attempts_no_update BEFORE UPDATE ON host_discovery_attempts BEGIN SELECT RAISE(ABORT,'discovery attempt immutable'); END;
CREATE TRIGGER host_discovery_attempts_no_delete BEFORE DELETE ON host_discovery_attempts BEGIN SELECT RAISE(ABORT,'discovery attempt durable'); END;
CREATE TRIGGER host_observations_no_update BEFORE UPDATE ON host_observations BEGIN SELECT RAISE(ABORT,'observation immutable'); END;
CREATE TRIGGER host_observations_no_delete BEFORE DELETE ON host_observations BEGIN SELECT RAISE(ABORT,'observation durable'); END;
CREATE TRIGGER host_observation_identities_no_update BEFORE UPDATE ON host_observation_identities BEGIN SELECT RAISE(ABORT,'identity observation immutable'); END;
CREATE TRIGGER host_observation_identities_no_delete BEFORE DELETE ON host_observation_identities BEGIN SELECT RAISE(ABORT,'identity observation durable'); END;

CREATE TABLE host_discovery_failures (
 attempt_id TEXT PRIMARY KEY REFERENCES host_discovery_attempts(attempt_id),
 error_code TEXT NOT NULL CHECK(length(error_code) BETWEEN 1 AND 64)
) STRICT;
CREATE TRIGGER host_discovery_failures_no_update BEFORE UPDATE ON host_discovery_failures BEGIN SELECT RAISE(ABORT,'discovery failure immutable'); END;
CREATE TRIGGER host_discovery_failures_no_delete BEFORE DELETE ON host_discovery_failures BEGIN SELECT RAISE(ABORT,'discovery failure durable'); END;
