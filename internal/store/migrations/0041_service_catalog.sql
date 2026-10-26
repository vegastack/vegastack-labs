CREATE TABLE service_catalog (
 service_id TEXT PRIMARY KEY NOT NULL,
 resource_key_digest TEXT NOT NULL UNIQUE CHECK(length(resource_key_digest)=71),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=16384),
 digest TEXT NOT NULL CHECK(length(digest)=71),
 import_digest TEXT NOT NULL CHECK(length(import_digest)=71),
 plan_id TEXT NOT NULL REFERENCES immutable_plans(plan_id),
 run_id TEXT NOT NULL UNIQUE REFERENCES plan_runs(run_id)
) STRICT;
CREATE TRIGGER service_catalog_no_update BEFORE UPDATE ON service_catalog BEGIN SELECT RAISE(ABORT,'service registration immutable'); END;
CREATE TRIGGER service_catalog_no_delete BEFORE DELETE ON service_catalog BEGIN SELECT RAISE(ABORT,'service registration durable'); END;
-- Preserve the authenticated run device for current-authority rechecks after
-- execution moves off the request context. This grants no new authority.
CREATE TABLE service_import_run_actors (
 run_id TEXT PRIMARY KEY NOT NULL REFERENCES plan_runs(run_id),
 principal_id TEXT NOT NULL,
 principal_method TEXT NOT NULL,
 device_id TEXT NOT NULL
) STRICT;
CREATE TRIGGER service_import_actor_no_update BEFORE UPDATE ON service_import_run_actors BEGIN SELECT RAISE(ABORT,'service run actor immutable'); END;
CREATE TRIGGER service_import_actor_no_delete BEFORE DELETE ON service_import_run_actors BEGIN SELECT RAISE(ABORT,'service run actor durable'); END;
