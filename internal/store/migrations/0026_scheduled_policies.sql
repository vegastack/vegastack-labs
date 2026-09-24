-- #109: exact fixed schedules, durable occurrences, attempts and leases.
CREATE TABLE scheduled_policy_drafts (
 draft_id TEXT PRIMARY KEY, policy_id TEXT NOT NULL, policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 canonical_json TEXT NOT NULL, policy_digest TEXT NOT NULL, created_by_human_id TEXT NOT NULL,
 state_revision INTEGER NOT NULL CHECK(state_revision>=0), recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0), created_at TEXT NOT NULL,
 UNIQUE(policy_id,policy_revision,recovery_epoch), UNIQUE(policy_digest,recovery_epoch)
) STRICT;
CREATE TRIGGER scheduled_policy_drafts_no_update BEFORE UPDATE ON scheduled_policy_drafts BEGIN SELECT RAISE(ABORT,'scheduled policy drafts are immutable'); END;
CREATE TRIGGER scheduled_policy_drafts_no_delete BEFORE DELETE ON scheduled_policy_drafts BEGIN SELECT RAISE(ABORT,'scheduled policy drafts are durable'); END;

CREATE TABLE scheduled_policy_activations (
 activation_id TEXT PRIMARY KEY, draft_id TEXT NOT NULL REFERENCES scheduled_policy_drafts(draft_id),
 policy_id TEXT NOT NULL, policy_revision INTEGER NOT NULL CHECK(policy_revision>0), status TEXT NOT NULL CHECK(status IN ('active','disabled')),
 approval_plan_id TEXT NOT NULL, approval_plan_digest TEXT NOT NULL, approved_by_human_id TEXT NOT NULL,
 state_revision INTEGER NOT NULL CHECK(state_revision>=0), recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0), activated_at TEXT NOT NULL,
 UNIQUE(policy_id,policy_revision,status)
) STRICT;
CREATE TRIGGER scheduled_policy_activations_no_update BEFORE UPDATE ON scheduled_policy_activations BEGIN SELECT RAISE(ABORT,'scheduled policy activations are immutable'); END;
CREATE TRIGGER scheduled_policy_activations_no_delete BEFORE DELETE ON scheduled_policy_activations BEGIN SELECT RAISE(ABORT,'scheduled policy activations are durable'); END;

CREATE TABLE scheduled_occurrences (
 job_id TEXT PRIMARY KEY, policy_id TEXT NOT NULL, policy_revision INTEGER NOT NULL CHECK(policy_revision>0), scheduled_at TEXT NOT NULL,
 occurrence_token_digest TEXT NOT NULL, target_digest TEXT NOT NULL, idempotency_key_digest TEXT NOT NULL,
 state_revision INTEGER NOT NULL CHECK(state_revision>=0), recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch>=0), created_at TEXT NOT NULL,
 UNIQUE(policy_id,policy_revision,scheduled_at), UNIQUE(policy_id,occurrence_token_digest)
) STRICT;
CREATE TRIGGER scheduled_occurrences_no_update BEFORE UPDATE ON scheduled_occurrences BEGIN SELECT RAISE(ABORT,'scheduled occurrences are immutable'); END;
CREATE TRIGGER scheduled_occurrences_no_delete BEFORE DELETE ON scheduled_occurrences BEGIN SELECT RAISE(ABORT,'scheduled occurrences are durable'); END;

CREATE TABLE scheduled_occurrence_transitions (
 transition_id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES scheduled_occurrences(job_id),
 from_status TEXT NOT NULL, to_status TEXT NOT NULL, reason_code TEXT NOT NULL, plan_id TEXT, run_id TEXT, recorded_at TEXT NOT NULL,
 UNIQUE(job_id,transition_id)
) STRICT;
CREATE TRIGGER scheduled_occurrence_transitions_no_update BEFORE UPDATE ON scheduled_occurrence_transitions BEGIN SELECT RAISE(ABORT,'scheduled transitions are append-only'); END;
CREATE TRIGGER scheduled_occurrence_transitions_no_delete BEFORE DELETE ON scheduled_occurrence_transitions BEGIN SELECT RAISE(ABORT,'scheduled transitions are append-only'); END;

CREATE TABLE scheduled_occurrence_attempts (
 attempt_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES scheduled_occurrences(job_id), attempt INTEGER NOT NULL CHECK(attempt>0),
 status TEXT NOT NULL CHECK(status IN ('queued','running','failed-before-effect','interrupted-before-effect','effect-unknown','partial','succeeded')),
 plan_id TEXT, run_id TEXT, effect_started INTEGER NOT NULL CHECK(effect_started IN (0,1)), recorded_at TEXT NOT NULL,
 UNIQUE(job_id,attempt)
) STRICT;
CREATE TRIGGER scheduled_occurrence_attempts_no_update BEFORE UPDATE ON scheduled_occurrence_attempts BEGIN SELECT RAISE(ABORT,'scheduled attempts are append-only'); END;
CREATE TRIGGER scheduled_occurrence_attempts_no_delete BEFORE DELETE ON scheduled_occurrence_attempts BEGIN SELECT RAISE(ABORT,'scheduled attempts are append-only'); END;

CREATE TABLE scheduled_occurrence_leases (
 job_id TEXT PRIMARY KEY REFERENCES scheduled_occurrences(job_id), lease_id TEXT NOT NULL UNIQUE, holder_id TEXT NOT NULL,
 acquired_at TEXT NOT NULL, expires_at TEXT NOT NULL
) STRICT;
