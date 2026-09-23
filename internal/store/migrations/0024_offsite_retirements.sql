-- #118: exact human-only off-site generation retirement. All records are
-- append-only. No table grants provider authority or permits direct status edits.
CREATE TABLE backup_offsite_retirement_intents (
 intent_id TEXT PRIMARY KEY, plan_id TEXT NOT NULL, plan_digest TEXT NOT NULL,
 generation_id TEXT NOT NULL REFERENCES backup_offsite_generations(generation_id),
 point_id TEXT NOT NULL, bucket_id TEXT NOT NULL, rule_set_digest TEXT NOT NULL,
 survivor_rule_digest TEXT NOT NULL, manifest_digest TEXT NOT NULL,
 catalog_digest TEXT NOT NULL, inventory_digest TEXT NOT NULL,
 one_owner_proof_id TEXT NOT NULL, lock_admin_consumer_id TEXT NOT NULL,
 retention_consumer_id TEXT NOT NULL, canonical_json TEXT NOT NULL,
 source_revision INTEGER NOT NULL CHECK(source_revision>=0), state_revision INTEGER NOT NULL CHECK(state_revision>=0),
 recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0), max_work_objects INTEGER NOT NULL CHECK(max_work_objects>0),
 max_mutation_bytes INTEGER NOT NULL CHECK(max_mutation_bytes>=0), pre_rule_count INTEGER NOT NULL CHECK(pre_rule_count>=5),
 survivor_rule_count INTEGER NOT NULL CHECK(survivor_rule_count=pre_rule_count-5), created_at TEXT NOT NULL,
 CHECK(lock_admin_consumer_id<>retention_consumer_id)
) STRICT;
CREATE TRIGGER backup_offsite_retirement_intents_no_update BEFORE UPDATE ON backup_offsite_retirement_intents BEGIN SELECT RAISE(ABORT,'offsite retirement intents are immutable'); END;
CREATE TRIGGER backup_offsite_retirement_intents_no_delete BEFORE DELETE ON backup_offsite_retirement_intents BEGIN SELECT RAISE(ABORT,'offsite retirement intents are durable'); END;
CREATE TABLE backup_offsite_retirement_rules (
 intent_id TEXT NOT NULL REFERENCES backup_offsite_retirement_intents(intent_id), sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 5),
 rule_id TEXT NOT NULL, protected_prefix TEXT NOT NULL, PRIMARY KEY(intent_id,sequence), UNIQUE(intent_id,rule_id), UNIQUE(intent_id,protected_prefix)
) STRICT;
CREATE TRIGGER backup_offsite_retirement_rules_no_update BEFORE UPDATE ON backup_offsite_retirement_rules BEGIN SELECT RAISE(ABORT,'offsite retirement rules are immutable'); END;
CREATE TRIGGER backup_offsite_retirement_rules_no_delete BEFORE DELETE ON backup_offsite_retirement_rules BEGIN SELECT RAISE(ABORT,'offsite retirement rules are durable'); END;
CREATE TABLE backup_offsite_retirement_objects (
 intent_id TEXT NOT NULL REFERENCES backup_offsite_retirement_intents(intent_id), sequence INTEGER NOT NULL CHECK(sequence>0),
 object_key TEXT NOT NULL, object_digest TEXT NOT NULL, object_bytes INTEGER NOT NULL CHECK(object_bytes>=0),
 PRIMARY KEY(intent_id,sequence), UNIQUE(intent_id,object_key)
) STRICT;
CREATE TRIGGER backup_offsite_retirement_objects_no_update BEFORE UPDATE ON backup_offsite_retirement_objects BEGIN SELECT RAISE(ABORT,'offsite retirement objects are immutable'); END;
CREATE TRIGGER backup_offsite_retirement_objects_no_delete BEFORE DELETE ON backup_offsite_retirement_objects BEGIN SELECT RAISE(ABORT,'offsite retirement objects are durable'); END;
CREATE TABLE backup_offsite_retirement_survivors (
 intent_id TEXT NOT NULL REFERENCES backup_offsite_retirement_intents(intent_id), point_id TEXT NOT NULL, PRIMARY KEY(intent_id,point_id)
) STRICT;
CREATE TRIGGER backup_offsite_retirement_survivors_no_update BEFORE UPDATE ON backup_offsite_retirement_survivors BEGIN SELECT RAISE(ABORT,'offsite retirement survivors are immutable'); END;
CREATE TRIGGER backup_offsite_retirement_survivors_no_delete BEFORE DELETE ON backup_offsite_retirement_survivors BEGIN SELECT RAISE(ABORT,'offsite retirement survivors are durable'); END;
CREATE TABLE backup_offsite_retirement_leases (
 lease_id TEXT PRIMARY KEY, intent_id TEXT NOT NULL UNIQUE REFERENCES backup_offsite_retirement_intents(intent_id), run_id TEXT NOT NULL,
 step_id TEXT NOT NULL, executor_lease_id TEXT NOT NULL, acknowledgement_id TEXT NOT NULL, human_id TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL, maximum_expires_at TEXT NOT NULL, acquired_at TEXT NOT NULL,
 UNIQUE(lease_id,intent_id)
) STRICT;
CREATE TRIGGER backup_offsite_retirement_leases_no_update BEFORE UPDATE ON backup_offsite_retirement_leases BEGIN SELECT RAISE(ABORT,'offsite retirement leases are immutable'); END;
CREATE TRIGGER backup_offsite_retirement_leases_no_delete BEFORE DELETE ON backup_offsite_retirement_leases BEGIN SELECT RAISE(ABORT,'offsite retirement leases are durable'); END;
CREATE TABLE backup_offsite_retirement_attempts (
 attempt_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL REFERENCES backup_offsite_retirement_leases(lease_id), sequence INTEGER NOT NULL CHECK(sequence>0),
 kind TEXT NOT NULL CHECK(kind IN ('rule-put','object-delete')), target TEXT NOT NULL, request_digest TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('attempted','observed','denied','uncertain')), response_digest TEXT, recorded_at TEXT NOT NULL,
 UNIQUE(lease_id,sequence)
) STRICT;
CREATE TRIGGER backup_offsite_retirement_attempts_no_update BEFORE UPDATE ON backup_offsite_retirement_attempts BEGIN SELECT RAISE(ABORT,'offsite retirement attempts are append-only'); END;
CREATE TRIGGER backup_offsite_retirement_attempts_no_delete BEFORE DELETE ON backup_offsite_retirement_attempts BEGIN SELECT RAISE(ABORT,'offsite retirement attempts are append-only'); END;
CREATE TABLE backup_offsite_retirement_receipts (
 receipt_id TEXT PRIMARY KEY, intent_id TEXT NOT NULL REFERENCES backup_offsite_retirement_intents(intent_id),
 lease_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('uncertain','failed','verified')),
 effect_digest TEXT NOT NULL, survivor_proof_digest TEXT, reclaimed_bytes INTEGER NOT NULL CHECK(reclaimed_bytes>=0), canonical_json TEXT NOT NULL, recorded_at TEXT NOT NULL,
 UNIQUE(intent_id), FOREIGN KEY(lease_id,intent_id) REFERENCES backup_offsite_retirement_leases(lease_id,intent_id)
) STRICT;
CREATE TRIGGER backup_offsite_retirement_receipts_no_update BEFORE UPDATE ON backup_offsite_retirement_receipts BEGIN SELECT RAISE(ABORT,'offsite retirement receipts are append-only'); END;
CREATE TRIGGER backup_offsite_retirement_receipts_no_delete BEFORE DELETE ON backup_offsite_retirement_receipts BEGIN SELECT RAISE(ABORT,'offsite retirement receipts are append-only'); END;
