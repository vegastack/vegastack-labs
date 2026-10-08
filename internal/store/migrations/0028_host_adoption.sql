-- Issue #222: database-only, unadmitted host registration.
CREATE TABLE host_adoption_drafts (
 draft_id TEXT PRIMARY KEY, digest TEXT NOT NULL CHECK(length(digest)=71),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=16384),
 principal_id TEXT NOT NULL, state_revision INTEGER NOT NULL CHECK(state_revision>=0), recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0)
) STRICT;
CREATE TABLE managed_hosts (
 host_id TEXT PRIMARY KEY, target_id TEXT NOT NULL UNIQUE, identity_digest TEXT NOT NULL UNIQUE CHECK(length(identity_digest)=71),
 identity_kind TEXT NOT NULL CHECK(identity_kind IN ('product-serial','product-uuid')),
 identity_class TEXT NOT NULL CHECK(identity_class IN ('physical','qualified-virtual')),
 observation_id TEXT NOT NULL REFERENCES host_observations(observation_id), profile_id TEXT NOT NULL,
 draft_id TEXT NOT NULL UNIQUE REFERENCES host_adoption_drafts(draft_id), plan_id TEXT NOT NULL REFERENCES immutable_plans(plan_id),
 approving_human_id TEXT NOT NULL, acknowledgement_id TEXT NOT NULL REFERENCES acknowledgement_requests(acknowledgement_id),
 state_revision INTEGER NOT NULL CHECK(state_revision>=0), recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0)
) STRICT;
CREATE TRIGGER host_adoption_drafts_no_update BEFORE UPDATE ON host_adoption_drafts BEGIN SELECT RAISE(ABORT,'registration draft immutable'); END;
CREATE TRIGGER host_adoption_drafts_no_delete BEFORE DELETE ON host_adoption_drafts BEGIN SELECT RAISE(ABORT,'registration draft durable'); END;
CREATE TRIGGER managed_hosts_no_update BEFORE UPDATE ON managed_hosts BEGIN SELECT RAISE(ABORT,'registered host immutable'); END;
CREATE TRIGGER managed_hosts_no_delete BEFORE DELETE ON managed_hosts BEGIN SELECT RAISE(ABORT,'registered host durable'); END;
