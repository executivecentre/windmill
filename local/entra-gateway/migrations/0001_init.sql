-- Gateway state. Lives in its own database; never in Windmill's.

CREATE TABLE identity (
    tenant_id           uuid        NOT NULL,
    object_id           uuid        NOT NULL,
    windmill_email      text        NOT NULL UNIQUE,
    last_upn            text,
    last_seen_at        timestamptz,
    disabled_by_gateway boolean     NOT NULL DEFAULT false,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, object_id)
);

-- Workspace memberships the gateway created. `disabled_by_gateway` marks a membership the
-- gateway disabled after the user lost the mapping, so it may re-enable only those.
CREATE TABLE managed_membership (
    object_id           uuid    NOT NULL,
    workspace           text    NOT NULL,
    role                text    NOT NULL,
    disabled_by_gateway boolean NOT NULL DEFAULT false,
    PRIMARY KEY (object_id, workspace)
);

-- Windmill group memberships the gateway added.
CREATE TABLE managed_group_membership (
    object_id uuid NOT NULL,
    workspace text NOT NULL,
    grp       text NOT NULL,
    PRIMARY KEY (object_id, workspace, grp)
);

-- Audit trail of every change the gateway made (Windmill OSS audit logging is a no-op).
-- Never holds tokens or secrets.
CREATE TABLE sync_event (
    id        bigserial   PRIMARY KEY,
    at        timestamptz NOT NULL DEFAULT now(),
    object_id uuid,
    action    text        NOT NULL,
    detail    jsonb       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX sync_event_object_action ON sync_event (object_id, action);
