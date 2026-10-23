CREATE TABLE operator_devices (
 device_id TEXT PRIMARY KEY,
 principal_id TEXT NOT NULL REFERENCES effective_authorization_principals(principal_id),
 status TEXT NOT NULL CHECK(status IN ('pending','approved','revoked')),
 device_revision INTEGER NOT NULL CHECK(device_revision > 0),
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL
) STRICT;
CREATE TRIGGER operator_devices_identity_immutable BEFORE UPDATE OF device_id,principal_id,created_at ON operator_devices BEGIN SELECT RAISE(ABORT,'device identity immutable'); END;
CREATE TRIGGER operator_devices_terminal BEFORE UPDATE ON operator_devices WHEN OLD.status='revoked' BEGIN SELECT RAISE(ABORT,'device revoked'); END;
CREATE TRIGGER operator_devices_preserve BEFORE DELETE ON operator_devices BEGIN SELECT RAISE(ABORT,'device history immutable'); END;
