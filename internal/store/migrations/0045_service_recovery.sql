CREATE TABLE service_recovery_attempts (
 plan_id TEXT PRIMARY KEY NOT NULL REFERENCES immutable_plans(plan_id),
 run_id TEXT NOT NULL UNIQUE REFERENCES plan_runs(run_id),
 step_id TEXT NOT NULL,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=71),
 service_id TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('attempted','succeeded','partial','failed','blocked')),
 UNIQUE(run_id,step_id)
) STRICT;
CREATE TRIGGER service_recovery_attempt_no_delete BEFORE DELETE ON service_recovery_attempts BEGIN SELECT RAISE(ABORT,'recovery attempt durable'); END;
CREATE TABLE service_recoveries (
 service_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 policy_id TEXT NOT NULL,
 plan_id TEXT NOT NULL UNIQUE REFERENCES immutable_plans(plan_id),
 run_id TEXT NOT NULL UNIQUE REFERENCES plan_runs(run_id),
 recovery_epoch INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('succeeded','partial','failed','blocked')),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=65536),
 digest TEXT NOT NULL CHECK(length(digest)=71),
 PRIMARY KEY(service_id,revision)
) STRICT;
CREATE TRIGGER service_recoveries_no_update BEFORE UPDATE ON service_recoveries BEGIN SELECT RAISE(ABORT,'recovery history immutable'); END;
CREATE TRIGGER service_recoveries_no_delete BEFORE DELETE ON service_recoveries BEGIN SELECT RAISE(ABORT,'recovery history durable'); END;
