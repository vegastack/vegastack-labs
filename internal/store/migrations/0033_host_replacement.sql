-- Finite replacement and applied alias ownership. History never grants admission.
CREATE TABLE host_replacement_drafts (
 draft_id TEXT PRIMARY KEY,
 replacement_id TEXT NOT NULL,
 operation TEXT NOT NULL CHECK(operation IN ('freeze','commit')),
 binding_digest TEXT NOT NULL CHECK(length(binding_digest)=71),
 content_digest TEXT NOT NULL UNIQUE CHECK(length(content_digest)=71),
 request_bytes BLOB NOT NULL CHECK(length(request_bytes) BETWEEN 2 AND 131072),
 principal_id TEXT NOT NULL,
 state_revision INTEGER NOT NULL CHECK(state_revision>=0),
 recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0),
 UNIQUE(replacement_id,operation)
) STRICT;
CREATE TABLE host_replacement_events (
 replacement_id TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence>0),
 event_type TEXT NOT NULL CHECK(event_type IN ('frozen','restore-pending','verification-required','qualification-required','fence-challenged','fence-observed','committed')),
 old_host_id TEXT NOT NULL,
 old_identity_digest TEXT NOT NULL CHECK(length(old_identity_digest)=71),
 new_host_id TEXT NOT NULL,
 new_identity_digest TEXT NOT NULL CHECK(length(new_identity_digest)=71),
 event_digest TEXT NOT NULL UNIQUE CHECK(length(event_digest)=71),
 event_bytes BLOB NOT NULL CHECK(length(event_bytes) BETWEEN 2 AND 1048576),
 state_revision INTEGER NOT NULL CHECK(state_revision>=0),
 recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0),
 PRIMARY KEY(replacement_id,sequence)
) STRICT;
CREATE INDEX host_replacement_old_identity ON host_replacement_events(old_host_id,old_identity_digest,event_type);
CREATE TABLE host_alias_history (
 event_ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
 alias_id TEXT NOT NULL,
 owner_revision INTEGER NOT NULL CHECK(owner_revision>0),
 owner_host_id TEXT NOT NULL,
 owner_identity_digest TEXT NOT NULL CHECK(length(owner_identity_digest)=71),
 ownership_generation INTEGER NOT NULL CHECK(ownership_generation>0),
 replacement_id TEXT,
 event_digest TEXT NOT NULL UNIQUE CHECK(length(event_digest)=71),
 event_bytes BLOB NOT NULL CHECK(length(event_bytes) BETWEEN 2 AND 16384),
 UNIQUE(alias_id,owner_revision)
) STRICT;
CREATE TABLE host_alias_owners (
 alias_id TEXT PRIMARY KEY,
 owner_host_id TEXT NOT NULL,
 owner_identity_digest TEXT NOT NULL CHECK(length(owner_identity_digest)=71),
 owner_revision INTEGER NOT NULL CHECK(owner_revision>0),
 ownership_generation INTEGER NOT NULL CHECK(ownership_generation>0),
 event_digest TEXT NOT NULL REFERENCES host_alias_history(event_digest),
 frozen_replacement_id TEXT
) STRICT;
ALTER TABLE recovery_authority_bundles ADD COLUMN continuity_bytes BLOB CHECK(continuity_bytes IS NULL OR length(continuity_bytes) BETWEEN 2 AND 4194304);
CREATE TRIGGER host_replacement_drafts_no_update BEFORE UPDATE ON host_replacement_drafts BEGIN SELECT RAISE(ABORT,'replacement drafts are immutable'); END;
CREATE TRIGGER host_replacement_drafts_no_delete BEFORE DELETE ON host_replacement_drafts BEGIN SELECT RAISE(ABORT,'replacement drafts are append-only'); END;
CREATE TRIGGER host_replacement_events_no_update BEFORE UPDATE ON host_replacement_events BEGIN SELECT RAISE(ABORT,'replacement events are immutable'); END;
CREATE TRIGGER host_replacement_events_no_delete BEFORE DELETE ON host_replacement_events BEGIN SELECT RAISE(ABORT,'replacement events are append-only'); END;
CREATE TRIGGER host_alias_history_no_update BEFORE UPDATE ON host_alias_history BEGIN SELECT RAISE(ABORT,'alias history is immutable'); END;
CREATE TRIGGER host_alias_history_no_delete BEFORE DELETE ON host_alias_history BEGIN SELECT RAISE(ABORT,'alias history is append-only'); END;
CREATE TRIGGER host_alias_owners_no_delete BEFORE DELETE ON host_alias_owners BEGIN SELECT RAISE(ABORT,'alias ownership cannot be deleted'); END;
