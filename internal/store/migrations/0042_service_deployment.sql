CREATE TABLE service_deployment_attempts (
 plan_id TEXT PRIMARY KEY NOT NULL REFERENCES immutable_plans(plan_id),
 run_id TEXT NOT NULL UNIQUE REFERENCES plan_runs(run_id),
 step_id TEXT NOT NULL,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=71),
 service_id TEXT NOT NULL,
 recovery_epoch INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('attempted','succeeded','partial','failed')),
 UNIQUE(run_id,step_id)
) STRICT;
CREATE TRIGGER service_deployment_attempt_no_delete BEFORE DELETE ON service_deployment_attempts BEGIN SELECT RAISE(ABORT,'deployment attempt durable'); END;
CREATE TABLE service_deployments (
 service_id TEXT NOT NULL,
 revision INTEGER NOT NULL CHECK(revision>0),
 plan_id TEXT NOT NULL UNIQUE REFERENCES immutable_plans(plan_id),
 run_id TEXT NOT NULL UNIQUE REFERENCES plan_runs(run_id),
 artifact_digest TEXT NOT NULL CHECK(length(artifact_digest)=71),
 recovery_epoch INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('succeeded','partial','failed')),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=32768),
 digest TEXT NOT NULL CHECK(length(digest)=71),
 PRIMARY KEY(service_id,revision)
) STRICT;
CREATE TRIGGER service_deployments_no_update BEFORE UPDATE ON service_deployments BEGIN SELECT RAISE(ABORT,'deployment history immutable'); END;
CREATE TRIGGER service_deployments_no_delete BEFORE DELETE ON service_deployments BEGIN SELECT RAISE(ABORT,'deployment history durable'); END;
