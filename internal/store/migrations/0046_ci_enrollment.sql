CREATE TABLE ci_enrollments (
 enrollment_id TEXT PRIMARY KEY NOT NULL,
 resource_key_digest TEXT NOT NULL UNIQUE CHECK(length(resource_key_digest)=71),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=16384),
 digest TEXT NOT NULL CHECK(length(digest)=71),
 import_digest TEXT NOT NULL CHECK(length(import_digest)=71),
 plan_id TEXT NOT NULL REFERENCES immutable_plans(plan_id),
 run_id TEXT NOT NULL UNIQUE REFERENCES plan_runs(run_id),
 binding_bytes BLOB NOT NULL CHECK(length(binding_bytes)<=32768),
 binding_digest TEXT NOT NULL CHECK(length(binding_digest)=71)
) STRICT;
CREATE TRIGGER ci_enrollments_no_update BEFORE UPDATE ON ci_enrollments BEGIN SELECT RAISE(ABORT,'CI enrollment immutable'); END;
CREATE TRIGGER ci_enrollments_no_delete BEFORE DELETE ON ci_enrollments BEGIN SELECT RAISE(ABORT,'CI enrollment durable'); END;
