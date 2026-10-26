CREATE TABLE hosting_lifecycle_attempts (
 plan_id TEXT PRIMARY KEY NOT NULL REFERENCES immutable_plans(plan_id),
 run_id TEXT NOT NULL UNIQUE REFERENCES plan_runs(run_id),
 step_id TEXT NOT NULL,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=71),
 target_id TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('attempted','succeeded','partial','failed')),
 UNIQUE(run_id,step_id)
) STRICT;
CREATE TRIGGER hosting_lifecycle_attempt_no_delete BEFORE DELETE ON hosting_lifecycle_attempts BEGIN SELECT RAISE(ABORT,'hosting lifecycle attempt durable'); END;
CREATE TABLE hosting_lifecycle_records (
 target_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 plan_id TEXT NOT NULL UNIQUE REFERENCES immutable_plans(plan_id),
 run_id TEXT NOT NULL UNIQUE REFERENCES plan_runs(run_id),
 recovery_epoch INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('succeeded','partial','failed')),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=262144),
 digest TEXT NOT NULL CHECK(length(digest)=71),
 PRIMARY KEY(target_id,revision)
) STRICT;
CREATE TRIGGER hosting_lifecycle_records_no_update BEFORE UPDATE ON hosting_lifecycle_records BEGIN SELECT RAISE(ABORT,'hosting lifecycle history immutable'); END;
CREATE TRIGGER hosting_lifecycle_records_no_delete BEFORE DELETE ON hosting_lifecycle_records BEGIN SELECT RAISE(ABORT,'hosting lifecycle history durable'); END;
