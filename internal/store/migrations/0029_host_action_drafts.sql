-- Issue #223: immutable privileged-action drafts; authority stays in plans/runs.
CREATE TABLE host_action_drafts (
 draft_id TEXT PRIMARY KEY,
 digest TEXT NOT NULL UNIQUE CHECK(length(digest)=71),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=65536),
 principal_id TEXT NOT NULL,
 state_revision INTEGER NOT NULL CHECK(state_revision>=0),
 recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0)
) STRICT;
CREATE TRIGGER host_action_drafts_no_update BEFORE UPDATE ON host_action_drafts BEGIN SELECT RAISE(ABORT,'host action draft immutable'); END;
CREATE TRIGGER host_action_drafts_no_delete BEFORE DELETE ON host_action_drafts BEGIN SELECT RAISE(ABORT,'host action draft durable'); END;
