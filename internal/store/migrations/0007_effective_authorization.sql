CREATE TABLE effective_authorization_principals (
    principal_id TEXT PRIMARY KEY CHECK (length(principal_id) BETWEEN 1 AND 128),
    principal_kind TEXT NOT NULL CHECK (principal_kind IN ('human', 'agent', 'policy')),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64)
) STRICT;

CREATE TABLE effective_authorization_grants (
    grant_id TEXT PRIMARY KEY CHECK (length(grant_id) BETWEEN 1 AND 128),
    principal_id TEXT NOT NULL,
    role_id TEXT NOT NULL CHECK (role_id IN ('reader', 'author', 'maintainer', 'infrastructure-admin', 'control-plane-admin', 'preauthorized-executor')),
    action TEXT NOT NULL CHECK (action IN ('read', 'author', 'acknowledge', 'execute')),
    capability TEXT NOT NULL CHECK (length(capability) BETWEEN 1 AND 128),
    resource_kind TEXT NOT NULL CHECK (length(resource_kind) BETWEEN 1 AND 128),
    resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 128),
    branch TEXT CHECK (branch IS NULL OR branch IN ('human', 'preauthorized')),
    grant_revision INTEGER NOT NULL CHECK (grant_revision > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 64),
    FOREIGN KEY (principal_id) REFERENCES effective_authorization_principals(principal_id) ON DELETE RESTRICT,
    CHECK ((action IN ('read', 'author') AND branch IS NULL) OR (action IN ('acknowledge', 'execute') AND branch IS NOT NULL)),
    CHECK ((role_id = 'preauthorized-executor' AND action = 'execute' AND branch = 'preauthorized') OR (role_id != 'preauthorized-executor' AND ifnull(branch, '') != 'preauthorized'))
) STRICT;

CREATE UNIQUE INDEX effective_authorization_grants_scope_idx
ON effective_authorization_grants(principal_id, role_id, action, capability, resource_kind, resource_id, ifnull(branch, ''));
CREATE INDEX effective_authorization_grants_lookup_idx
ON effective_authorization_grants(principal_id, action, capability, resource_kind, resource_id, status, grant_revision);

CREATE TABLE desired_authorization_grants (
    desired_grant_id TEXT PRIMARY KEY CHECK (length(desired_grant_id) BETWEEN 1 AND 128),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 128),
    proposed_by_principal_id TEXT NOT NULL CHECK (length(proposed_by_principal_id) BETWEEN 1 AND 128),
    role_id TEXT NOT NULL CHECK (role_id IN ('reader', 'author', 'maintainer', 'infrastructure-admin', 'control-plane-admin', 'preauthorized-executor')),
    action TEXT NOT NULL CHECK (action IN ('read', 'author', 'acknowledge', 'execute')),
    capability TEXT NOT NULL CHECK (length(capability) BETWEEN 1 AND 128),
    resource_kind TEXT NOT NULL CHECK (length(resource_kind) BETWEEN 1 AND 128),
    resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 128),
    branch TEXT CHECK (branch IS NULL OR branch IN ('human', 'preauthorized')),
    desired_revision INTEGER NOT NULL CHECK (desired_revision > 0),
    status TEXT NOT NULL CHECK (status IN ('draft', 'approved', 'superseded')),
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 64),
    CHECK ((action IN ('read', 'author') AND branch IS NULL) OR (action IN ('acknowledge', 'execute') AND branch IS NOT NULL)),
    CHECK ((role_id = 'preauthorized-executor' AND action = 'execute' AND branch = 'preauthorized') OR (role_id != 'preauthorized-executor' AND ifnull(branch, '') != 'preauthorized'))
) STRICT;

CREATE INDEX desired_authorization_grants_subject_idx
ON desired_authorization_grants(principal_id, desired_revision, status);

CREATE TABLE authorization_decisions (
    decision_id TEXT PRIMARY KEY CHECK (length(decision_id) BETWEEN 1 AND 128),
    principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 128),
    action TEXT NOT NULL CHECK (action IN ('read', 'author', 'acknowledge', 'execute')),
    capability TEXT NOT NULL CHECK (length(capability) BETWEEN 1 AND 128),
    resource_kind TEXT NOT NULL CHECK (length(resource_kind) BETWEEN 1 AND 128),
    resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 128),
    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
    branch TEXT CHECK (branch IS NULL OR branch IN ('human', 'preauthorized')),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
    grant_revision INTEGER NOT NULL CHECK (grant_revision >= 0),
    state_revision INTEGER NOT NULL CHECK (state_revision >= 0),
    recovery_epoch INTEGER NOT NULL CHECK (recovery_epoch >= 0),
    plan_digest TEXT CHECK (plan_digest IS NULL OR (length(plan_digest) = 71 AND substr(plan_digest, 1, 7) = 'sha256:')),
    scope_digest TEXT CHECK (scope_digest IS NULL OR (length(scope_digest) = 71 AND substr(scope_digest, 1, 7) = 'sha256:')),
    decided_at TEXT NOT NULL CHECK (length(decided_at) BETWEEN 1 AND 64),
    audit_correlation_id TEXT NOT NULL CHECK (length(audit_correlation_id) BETWEEN 1 AND 128),
    CHECK ((allowed = 1 AND reason_code = 'allowed' AND scope_digest IS NOT NULL) OR (allowed = 0 AND reason_code != 'allowed' AND branch IS NULL))
) STRICT;

CREATE TRIGGER effective_authorization_principals_no_delete BEFORE DELETE ON effective_authorization_principals BEGIN SELECT RAISE(ABORT, 'effective principal is durable'); END;
CREATE TRIGGER effective_authorization_principals_monotonic BEFORE UPDATE ON effective_authorization_principals
WHEN NEW.principal_id != OLD.principal_id OR NEW.principal_kind != OLD.principal_kind OR NEW.grant_revision < OLD.grant_revision OR (OLD.status = 'revoked' AND NEW.status != 'revoked')
BEGIN SELECT RAISE(ABORT, 'invalid effective principal transition'); END;
CREATE TRIGGER effective_authorization_grants_no_delete BEFORE DELETE ON effective_authorization_grants BEGIN SELECT RAISE(ABORT, 'effective grant is durable'); END;
CREATE TRIGGER effective_authorization_grants_monotonic BEFORE UPDATE ON effective_authorization_grants
WHEN NEW.grant_id != OLD.grant_id OR NEW.principal_id != OLD.principal_id OR NEW.role_id != OLD.role_id OR NEW.action != OLD.action OR NEW.capability != OLD.capability OR NEW.resource_kind != OLD.resource_kind OR NEW.resource_id != OLD.resource_id OR ifnull(NEW.branch, '') != ifnull(OLD.branch, '') OR NEW.grant_revision < OLD.grant_revision OR (OLD.status = 'revoked' AND NEW.status != 'revoked')
BEGIN SELECT RAISE(ABORT, 'invalid effective grant transition'); END;
CREATE TRIGGER desired_authorization_grants_no_update BEFORE UPDATE ON desired_authorization_grants BEGIN SELECT RAISE(ABORT, 'desired grant is immutable'); END;
CREATE TRIGGER desired_authorization_grants_no_delete BEFORE DELETE ON desired_authorization_grants BEGIN SELECT RAISE(ABORT, 'desired grant is durable'); END;
CREATE TRIGGER authorization_decisions_no_update BEFORE UPDATE ON authorization_decisions BEGIN SELECT RAISE(ABORT, 'authorization decision is immutable'); END;
CREATE TRIGGER authorization_decisions_no_delete BEFORE DELETE ON authorization_decisions BEGIN SELECT RAISE(ABORT, 'authorization decision is durable'); END;
