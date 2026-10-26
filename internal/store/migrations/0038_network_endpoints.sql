CREATE TABLE network_endpoint_revisions (
 host_id TEXT NOT NULL REFERENCES managed_hosts(host_id),
 revision INTEGER NOT NULL CHECK(revision>0),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=16384),
 digest TEXT NOT NULL CHECK(length(digest)=71),
 plan_id TEXT NOT NULL REFERENCES immutable_plans(plan_id),
 run_id TEXT NOT NULL REFERENCES plan_runs(run_id),
 PRIMARY KEY(host_id,revision)
) STRICT;
CREATE TRIGGER network_endpoints_no_update BEFORE UPDATE ON network_endpoint_revisions BEGIN SELECT RAISE(ABORT,'network endpoint immutable'); END;
CREATE TRIGGER network_endpoints_no_delete BEFORE DELETE ON network_endpoint_revisions BEGIN SELECT RAISE(ABORT,'network endpoint durable'); END;
