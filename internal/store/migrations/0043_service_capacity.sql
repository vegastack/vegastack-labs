-- Server-observed capacity is inert evidence; reservations precede provider I/O.
CREATE TABLE service_capacity_observations (
 digest TEXT PRIMARY KEY CHECK(length(digest)=71),
 service_id TEXT NOT NULL REFERENCES service_catalog(service_id),
 host_id TEXT NOT NULL REFERENCES managed_hosts(host_id),
 canonical_bytes BLOB NOT NULL CHECK(length(canonical_bytes)<=8192),
 recovery_epoch INTEGER NOT NULL
) STRICT;
CREATE TABLE service_capacity_reservations (
 service_id TEXT PRIMARY KEY REFERENCES service_catalog(service_id),
 host_id TEXT NOT NULL REFERENCES managed_hosts(host_id),
 plan_id TEXT NOT NULL REFERENCES immutable_plans(plan_id),
 configuration_digest TEXT NOT NULL,
 cpu_percent INTEGER NOT NULL CHECK(cpu_percent>0),
 memory_bytes INTEGER NOT NULL CHECK(memory_bytes>0),
 storage_bytes INTEGER NOT NULL CHECK(storage_bytes>=0),
 recovery_epoch INTEGER NOT NULL
) STRICT;
CREATE INDEX service_capacity_host ON service_capacity_reservations(host_id,recovery_epoch);
CREATE TRIGGER service_capacity_observations_no_update BEFORE UPDATE ON service_capacity_observations BEGIN SELECT RAISE(ABORT,'capacity observations immutable'); END;
CREATE TRIGGER service_capacity_observations_no_delete BEFORE DELETE ON service_capacity_observations BEGIN SELECT RAISE(ABORT,'capacity observations durable'); END;
