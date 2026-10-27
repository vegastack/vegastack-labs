CREATE TABLE ci_job_executions (
 run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
 step_id TEXT NOT NULL REFERENCES plan_run_steps(step_id),
 lifecycle_id TEXT NOT NULL UNIQUE,
 lease_id TEXT NOT NULL REFERENCES target_execution_leases(lease_id),
 enrollment_id TEXT NOT NULL REFERENCES ci_enrollments(enrollment_id),
 provider_run_id TEXT NOT NULL,
 attempt INTEGER NOT NULL CHECK(attempt>0),
 registration_stage TEXT NOT NULL DEFAULT 'not-attempted',
 runner_id TEXT,
 job_id TEXT,
 admission_consumed INTEGER NOT NULL DEFAULT 0 CHECK(admission_consumed IN (0,1)),
 observation_digest TEXT,
 completion_digest TEXT,
 event_digest TEXT,
 cleanup_status TEXT NOT NULL DEFAULT 'pending' CHECK(cleanup_status IN ('pending','verified','uncertain')),
 recovery_epoch INTEGER NOT NULL,
 PRIMARY KEY(run_id,step_id),
 UNIQUE(enrollment_id,provider_run_id,attempt,job_id)
) STRICT;
CREATE TABLE ci_job_events (
 run_id TEXT NOT NULL,
 step_id TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence>0 AND sequence<=256),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=4096),
 digest TEXT NOT NULL,
 PRIMARY KEY(run_id,step_id,sequence),
 FOREIGN KEY(run_id,step_id) REFERENCES ci_job_executions(run_id,step_id)
) STRICT;
CREATE TRIGGER ci_job_admission_no_reset BEFORE UPDATE OF admission_consumed ON ci_job_executions WHEN OLD.admission_consumed=1 AND NEW.admission_consumed!=1 BEGIN SELECT RAISE(ABORT,'CI admission consumed'); END;
CREATE TRIGGER ci_job_events_no_update BEFORE UPDATE ON ci_job_events BEGIN SELECT RAISE(ABORT,'CI event immutable'); END;
CREATE TRIGGER ci_job_events_no_delete BEFORE DELETE ON ci_job_events BEGIN SELECT RAISE(ABORT,'CI event retained'); END;
