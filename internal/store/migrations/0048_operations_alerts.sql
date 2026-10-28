CREATE TABLE operations_alerts (
 recovery_epoch INTEGER NOT NULL CHECK(recovery_epoch >= 0),
 alert_key TEXT NOT NULL,
 observed_at TEXT NOT NULL,
 alert_json BLOB NOT NULL CHECK(json_valid(alert_json)),
 PRIMARY KEY(recovery_epoch,alert_key)
);
CREATE TABLE operations_transitions (
 event_id INTEGER PRIMARY KEY REFERENCES audit_events(event_id),
 recovery_epoch INTEGER NOT NULL,
 alert_key TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation > 0),
 transition TEXT NOT NULL CHECK(transition IN ('opened','closed')),
 FOREIGN KEY(recovery_epoch,alert_key) REFERENCES operations_alerts(recovery_epoch,alert_key)
);
