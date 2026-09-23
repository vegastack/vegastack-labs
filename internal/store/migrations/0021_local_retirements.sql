-- #115 local retirement is human-only and remains inert until the exact
-- execution, survivor proof and atomic successor-generation paths are wired.
-- Every row stores public bindings and digests, never a repository password.
-- An absent activation is unknown, not an empty promise set. One row is the
-- complete applied point-bound lock catalog for its generation. A later row
-- supersedes it only through another exact human plan; no in-place release.
CREATE TABLE backup_retention_lock_catalog_activations (
    activation_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    activation_id TEXT NOT NULL UNIQUE CHECK (length(activation_id) BETWEEN 1 AND 128),
    repository_id TEXT NOT NULL CHECK (length(repository_id) BETWEEN 1 AND 128),
    repository_class TEXT NOT NULL CHECK (repository_class IN ('standard','critical')),
    catalog_digest TEXT NOT NULL CHECK (length(catalog_digest)=71 AND substr(catalog_digest,1,7)='sha256:'),
    source_coverage_digest TEXT NOT NULL CHECK (length(source_coverage_digest)=71 AND substr(source_coverage_digest,1,7)='sha256:'),
    canonical_json TEXT NOT NULL CHECK (length(canonical_json) BETWEEN 2 AND 1048576),
    declaration_id TEXT NOT NULL,
    declaration_revision INTEGER NOT NULL CHECK (declaration_revision > 0),
    plan_id TEXT NOT NULL REFERENCES immutable_plans(plan_id),
    plan_digest TEXT NOT NULL CHECK (length(plan_digest)=71 AND substr(plan_digest,1,7)='sha256:'),
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    step_id TEXT NOT NULL REFERENCES plan_run_steps(step_id),
    acknowledgement_id TEXT NOT NULL REFERENCES acknowledgement_proofs(acknowledgement_id),
    human_id TEXT NOT NULL CHECK (length(human_id) BETWEEN 1 AND 128),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    activated_at TEXT NOT NULL,
    FOREIGN KEY (declaration_id,declaration_revision) REFERENCES declaration_revisions(declaration_id,declaration_revision),
    UNIQUE(repository_class,recovery_epoch,catalog_digest)
) STRICT;
CREATE INDEX backup_retention_lock_catalog_current_idx ON backup_retention_lock_catalog_activations(repository_class,recovery_epoch,activation_sequence DESC);
CREATE TRIGGER backup_retention_lock_catalog_activations_no_update BEFORE UPDATE ON backup_retention_lock_catalog_activations BEGIN SELECT RAISE(ABORT,'retention lock catalog activations are append-only'); END;
CREATE TRIGGER backup_retention_lock_catalog_activations_no_delete BEFORE DELETE ON backup_retention_lock_catalog_activations BEGIN SELECT RAISE(ABORT,'retention lock catalog activations are append-only'); END;

CREATE TABLE backup_retirement_intents (
    intent_id TEXT PRIMARY KEY CHECK (length(intent_id) BETWEEN 1 AND 128),
    plan_id TEXT NOT NULL REFERENCES immutable_plans(plan_id),
    plan_digest TEXT NOT NULL CHECK (length(plan_digest)=71 AND substr(plan_digest,1,7)='sha256:'),
    repository_id TEXT NOT NULL CHECK (length(repository_id) BETWEEN 1 AND 128),
    repository_class TEXT NOT NULL CHECK (repository_class IN ('standard','critical')),
    catalog_digest TEXT NOT NULL CHECK (length(catalog_digest)=71 AND substr(catalog_digest,1,7)='sha256:'),
    expected_inventory_digest TEXT NOT NULL CHECK (length(expected_inventory_digest)=71 AND substr(expected_inventory_digest,1,7)='sha256:'),
    lock_catalog_digest TEXT NOT NULL CHECK (length(lock_catalog_digest)=71 AND substr(lock_catalog_digest,1,7)='sha256:'),
    source_coverage_digest TEXT NOT NULL CHECK (length(source_coverage_digest)=71 AND substr(source_coverage_digest,1,7)='sha256:'),
    lock_catalog_sequence INTEGER NOT NULL CHECK (lock_catalog_sequence > 0),
    selection_digest TEXT NOT NULL CHECK (length(selection_digest)=71 AND substr(selection_digest,1,7)='sha256:'),
    canonical_json TEXT NOT NULL CHECK (length(canonical_json) BETWEEN 2 AND 1048576),
    target_count INTEGER NOT NULL CHECK (target_count BETWEEN 1 AND 256),
    survivor_count INTEGER NOT NULL CHECK (survivor_count BETWEEN 1 AND 256),
    source_revision INTEGER NOT NULL CHECK (source_revision >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    expected_reclaim_bytes INTEGER NOT NULL CHECK (expected_reclaim_bytes >= 0),
    max_work_objects INTEGER NOT NULL CHECK (max_work_objects > 0),
    max_mutation_bytes INTEGER NOT NULL CHECK (max_mutation_bytes > 0),
    max_repack_bytes INTEGER NOT NULL CHECK (max_repack_bytes > 0),
    created_at TEXT NOT NULL
) STRICT;
CREATE INDEX backup_retirement_intents_repository_idx ON backup_retirement_intents(repository_class,recovery_epoch,created_at);
CREATE TRIGGER backup_retirement_intents_no_update BEFORE UPDATE ON backup_retirement_intents BEGIN SELECT RAISE(ABORT,'retirement intents are immutable'); END;
CREATE TRIGGER backup_retirement_intents_no_delete BEFORE DELETE ON backup_retirement_intents BEGIN SELECT RAISE(ABORT,'retirement intents are immutable'); END;

-- A claim is distinct from the routine writer and verifier. The store must
-- also reject any active writer/read lease for this physical repository class.
CREATE TABLE backup_retirement_leases (
    lease_id TEXT PRIMARY KEY CHECK (length(lease_id) BETWEEN 1 AND 128),
    intent_id TEXT NOT NULL REFERENCES backup_retirement_intents(intent_id),
    run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
    step_id TEXT NOT NULL REFERENCES plan_run_steps(step_id),
    executor_lease_id TEXT NOT NULL REFERENCES target_execution_leases(lease_id),
    acknowledgement_id TEXT NOT NULL REFERENCES acknowledgement_proofs(acknowledgement_id),
    human_id TEXT NOT NULL CHECK (length(human_id) BETWEEN 1 AND 128),
    retention_consumer_id TEXT NOT NULL CHECK (length(retention_consumer_id) BETWEEN 1 AND 128),
    repository_class TEXT NOT NULL CHECK (repository_class IN ('standard','critical')),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    maximum_expires_at TEXT NOT NULL,
    acquired_at TEXT NOT NULL,
    released_at TEXT
) STRICT;
CREATE UNIQUE INDEX backup_retirement_leases_active_idx ON backup_retirement_leases(repository_class) WHERE released_at IS NULL;
CREATE TRIGGER backup_retirement_leases_no_delete BEFORE DELETE ON backup_retirement_leases BEGIN SELECT RAISE(ABORT,'retirement leases are retained'); END;
CREATE TRIGGER backup_retirement_leases_release_only BEFORE UPDATE ON backup_retirement_leases
WHEN OLD.released_at IS NOT NULL OR NEW.released_at IS NULL OR NEW.released_at <= OLD.acquired_at OR
     NEW.lease_id != OLD.lease_id OR NEW.intent_id != OLD.intent_id OR NEW.run_id != OLD.run_id OR
     NEW.step_id != OLD.step_id OR NEW.executor_lease_id != OLD.executor_lease_id OR
     NEW.acknowledgement_id != OLD.acknowledgement_id OR NEW.human_id != OLD.human_id OR
     NEW.retention_consumer_id != OLD.retention_consumer_id OR NEW.repository_class != OLD.repository_class OR
     NEW.recovery_epoch != OLD.recovery_epoch OR NEW.maximum_expires_at != OLD.maximum_expires_at OR
     NEW.acquired_at != OLD.acquired_at
BEGIN SELECT RAISE(ABORT,'retirement lease can only be released once'); END;

-- An attempt is durable before a restic-visible PUT or quarantine DELETE.
-- Outcome loss leaves an unresolved attempt, never an inferred success.
CREATE TABLE backup_retirement_mutation_attempts (
    mutation_id TEXT PRIMARY KEY CHECK (length(mutation_id) BETWEEN 1 AND 128),
    lease_id TEXT NOT NULL REFERENCES backup_retirement_leases(lease_id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    mutation_kind TEXT NOT NULL CHECK (mutation_kind IN ('put','delete')),
    object_type TEXT NOT NULL CHECK (object_type IN ('data','index','snapshots','locks')),
    object_name TEXT NOT NULL CHECK (length(object_name) BETWEEN 1 AND 128),
    object_digest TEXT NOT NULL CHECK (length(object_digest)=71 AND substr(object_digest,1,7)='sha256:'),
    object_bytes INTEGER NOT NULL CHECK (object_bytes >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    begun_at TEXT NOT NULL,
    UNIQUE(lease_id,sequence)
) STRICT;
CREATE TRIGGER backup_retirement_mutation_attempts_no_update BEFORE UPDATE ON backup_retirement_mutation_attempts BEGIN SELECT RAISE(ABORT,'retirement attempts are append-only'); END;
CREATE TRIGGER backup_retirement_mutation_attempts_no_delete BEFORE DELETE ON backup_retirement_mutation_attempts BEGIN SELECT RAISE(ABORT,'retirement attempts are append-only'); END;

CREATE TABLE backup_retirement_mutation_outcomes (
    mutation_id TEXT PRIMARY KEY REFERENCES backup_retirement_mutation_attempts(mutation_id),
    status TEXT NOT NULL CHECK (status IN ('created','quarantined','denied','uncertain')),
    quarantine_name TEXT CHECK (quarantine_name IS NULL OR length(quarantine_name) BETWEEN 1 AND 256),
    observed_digest TEXT CHECK (observed_digest IS NULL OR (length(observed_digest)=71 AND substr(observed_digest,1,7)='sha256:')),
    recorded_at TEXT NOT NULL,
    CHECK ((status='quarantined')=(quarantine_name IS NOT NULL))
) STRICT;
CREATE TRIGGER backup_retirement_mutation_outcomes_no_update BEFORE UPDATE ON backup_retirement_mutation_outcomes BEGIN SELECT RAISE(ABORT,'retirement outcomes are append-only'); END;
CREATE TRIGGER backup_retirement_mutation_outcomes_no_delete BEFORE DELETE ON backup_retirement_mutation_outcomes BEGIN SELECT RAISE(ABORT,'retirement outcomes are append-only'); END;

CREATE TABLE backup_retirement_receipts (
    receipt_id TEXT PRIMARY KEY CHECK (length(receipt_id) BETWEEN 1 AND 128),
    intent_id TEXT NOT NULL REFERENCES backup_retirement_intents(intent_id),
    lease_id TEXT REFERENCES backup_retirement_leases(lease_id),
    status TEXT NOT NULL CHECK (status IN ('planned','in-progress','uncertain','verified','failed')),
    journal_digest TEXT CHECK (journal_digest IS NULL OR (length(journal_digest)=71 AND substr(journal_digest,1,7)='sha256:')),
    proof_digest TEXT CHECK (proof_digest IS NULL OR (length(proof_digest)=71 AND substr(proof_digest,1,7)='sha256:')),
    reason_code TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    CHECK (status!='verified' OR (journal_digest IS NOT NULL AND proof_digest IS NOT NULL))
) STRICT;
CREATE INDEX backup_retirement_receipts_intent_idx ON backup_retirement_receipts(intent_id,recorded_at);
CREATE TRIGGER backup_retirement_receipts_no_update BEFORE UPDATE ON backup_retirement_receipts BEGIN SELECT RAISE(ABORT,'retirement receipts are append-only'); END;
CREATE TRIGGER backup_retirement_receipts_no_delete BEFORE DELETE ON backup_retirement_receipts BEGIN SELECT RAISE(ABORT,'retirement receipts are append-only'); END;

-- One immutable row is one atomic successor generation for the entire survivor
-- set. canonical_json contains every original-point binding and exact post-
-- mutation object; an incomplete row never becomes visible to a verifier.
CREATE TABLE backup_retirement_successor_generations (
    generation_id TEXT PRIMARY KEY CHECK (length(generation_id) BETWEEN 1 AND 128),
    intent_id TEXT NOT NULL REFERENCES backup_retirement_intents(intent_id),
    repository_id TEXT NOT NULL CHECK (length(repository_id) BETWEEN 1 AND 128),
    repository_class TEXT NOT NULL CHECK (repository_class IN ('standard','critical')),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    generation_sequence INTEGER NOT NULL CHECK (generation_sequence > 0),
    parent_generation_digest TEXT CHECK (parent_generation_digest IS NULL OR (length(parent_generation_digest)=71 AND substr(parent_generation_digest,1,7)='sha256:')),
    generation_digest TEXT NOT NULL UNIQUE CHECK (length(generation_digest)=71 AND substr(generation_digest,1,7)='sha256:'),
    predecessor_inventory_digest TEXT NOT NULL CHECK (length(predecessor_inventory_digest)=71 AND substr(predecessor_inventory_digest,1,7)='sha256:'),
    successor_inventory_digest TEXT NOT NULL CHECK (length(successor_inventory_digest)=71 AND substr(successor_inventory_digest,1,7)='sha256:'),
    journal_digest TEXT NOT NULL CHECK (length(journal_digest)=71 AND substr(journal_digest,1,7)='sha256:'),
    survivor_proof_digest TEXT NOT NULL CHECK (length(survivor_proof_digest)=71 AND substr(survivor_proof_digest,1,7)='sha256:'),
    survivor_count INTEGER NOT NULL CHECK (survivor_count BETWEEN 1 AND 256),
    canonical_json TEXT NOT NULL CHECK (length(canonical_json) BETWEEN 2 AND 4194304),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recorded_at TEXT NOT NULL,
    UNIQUE(repository_class,recovery_epoch,generation_sequence)
) STRICT;
CREATE INDEX backup_retirement_successor_repository_idx ON backup_retirement_successor_generations(repository_class,recovery_epoch,generation_sequence DESC);
CREATE TRIGGER backup_retirement_successor_generations_no_update BEFORE UPDATE ON backup_retirement_successor_generations BEGIN SELECT RAISE(ABORT,'retirement successor generations are append-only'); END;
CREATE TRIGGER backup_retirement_successor_generations_no_delete BEFORE DELETE ON backup_retirement_successor_generations BEGIN SELECT RAISE(ABORT,'retirement successor generations are append-only'); END;

-- Physical unlink is separately recorded only after a committed successor
-- generation and rechecked quarantine inode; no unlink is authorized here.
CREATE TABLE backup_retirement_finalizations (
    finalization_id TEXT PRIMARY KEY CHECK (length(finalization_id) BETWEEN 1 AND 128),
    generation_id TEXT NOT NULL REFERENCES backup_retirement_successor_generations(generation_id),
    object_type TEXT NOT NULL CHECK (object_type IN ('data','index','snapshots','locks')),
    object_name TEXT NOT NULL CHECK (length(object_name) BETWEEN 1 AND 128),
    object_digest TEXT NOT NULL CHECK (length(object_digest)=71 AND substr(object_digest,1,7)='sha256:'),
    object_bytes INTEGER NOT NULL CHECK (object_bytes >= 0),
    finalized_at TEXT NOT NULL,
    UNIQUE(generation_id,object_type,object_name)
) STRICT;
CREATE TRIGGER backup_retirement_finalizations_no_update BEFORE UPDATE ON backup_retirement_finalizations BEGIN SELECT RAISE(ABORT,'retirement finalizations are append-only'); END;
CREATE TRIGGER backup_retirement_finalizations_no_delete BEFORE DELETE ON backup_retirement_finalizations BEGIN SELECT RAISE(ABORT,'retirement finalizations are append-only'); END;

CREATE TABLE backup_retirement_custody_attempts (
    attempt_id TEXT PRIMARY KEY,
    lease_id TEXT NOT NULL REFERENCES backup_retirement_leases(lease_id),
    nonce_digest TEXT NOT NULL UNIQUE,
    begun_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER backup_retirement_custody_attempts_no_update BEFORE UPDATE ON backup_retirement_custody_attempts BEGIN SELECT RAISE(ABORT,'retirement custody attempts are append-only'); END;
CREATE TRIGGER backup_retirement_custody_attempts_no_delete BEFORE DELETE ON backup_retirement_custody_attempts BEGIN SELECT RAISE(ABORT,'retirement custody attempts are append-only'); END;
CREATE TABLE backup_retirement_custody_outcomes (
    attempt_id TEXT PRIMARY KEY REFERENCES backup_retirement_custody_attempts(attempt_id),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded','failed','uncertain')),
    recorded_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER backup_retirement_custody_outcomes_no_update BEFORE UPDATE ON backup_retirement_custody_outcomes BEGIN SELECT RAISE(ABORT,'retirement custody outcomes are append-only'); END;
CREATE TRIGGER backup_retirement_custody_outcomes_no_delete BEFORE DELETE ON backup_retirement_custody_outcomes BEGIN SELECT RAISE(ABORT,'retirement custody outcomes are append-only'); END;
