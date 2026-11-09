-- Key material. `sealed` is AES-256-GCM(KEK, private key); `public` is the shareable half.
CREATE TABLE secrets (
    name       TEXT PRIMARY KEY,
    public     TEXT NOT NULL,
    sealed     BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id            UUID PRIMARY KEY,
    sub           TEXT UNIQUE,              -- OIDC subject; NULL for the local break-glass admin
    username      TEXT UNIQUE NOT NULL,
    email         TEXT,
    groups        TEXT[] NOT NULL DEFAULT '{}',
    refresh_token BYTEA,                    -- sealed with the KEK; used to re-check groups live
    disabled      BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    name        TEXT NOT NULL,
    public_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used   TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    UNIQUE (user_id, fingerprint)
);

CREATE TABLE api_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    device_id  UUID REFERENCES devices ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- OIDC logins in flight (in Postgres so the callback can land on any replica).
CREATE TABLE login_requests (
    state      TEXT PRIMARY KEY,
    nonce      TEXT NOT NULL,
    pkce       TEXT NOT NULL,
    cli_port   INT,
    cli_state  TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE login_codes (
    code_hash  TEXT PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);

-- RBAC: one permission catalog; built-in roles are just seeded rows.
CREATE TABLE roles (
    name        TEXT PRIMARY KEY,
    permissions TEXT[] NOT NULL,
    builtin     BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE role_bindings (
    grp  TEXT NOT NULL,
    role TEXT NOT NULL REFERENCES roles ON DELETE CASCADE,
    PRIMARY KEY (grp, role)
);
INSERT INTO roles (name, permissions, builtin) VALUES
 ('admin', ARRAY['nodes:read','nodes:write','policy:read','policy:write','audit:read','recordings:view',
                 'sessions:kill','approvals:decide','devices:write','rbac:write'], true),
 ('team-admin', ARRAY['nodes:read','nodes:write','policy:read','audit:read','approvals:decide'], true),
 ('auditor', ARRAY['nodes:read','policy:read','audit:read','recordings:view'], true),
 ('read-only', ARRAY['nodes:read','policy:read'], true);

CREATE TABLE join_tokens (
    token_hash TEXT PRIMARY KEY,
    created_by UUID REFERENCES users ON DELETE SET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

CREATE TABLE nodes (
    id              UUID PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    labels          JSONB NOT NULL DEFAULT '{}',
    services        JSONB NOT NULL DEFAULT '{}',
    cert_serial     TEXT NOT NULL,
    prev_serial     TEXT,
    cert_expires_at TIMESTAMPTZ NOT NULL,
    version         TEXT,
    last_seen       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Deny list checked at every agent handshake.
CREATE TABLE revoked_certs (
    serial     TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE replicas (
    id        TEXT PRIMARY KEY,
    agent_url TEXT NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policy_rules (
    name TEXT PRIMARY KEY,
    body JSONB NOT NULL
);

CREATE TABLE grants (
    id         UUID PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users ON DELETE CASCADE,
    node_id    UUID NOT NULL REFERENCES nodes ON DELETE CASCADE,
    service    TEXT NOT NULL,
    login      TEXT NOT NULL,
    reason     TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    rule       TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('pending','approved','denied','revoked')),
    emergency  BOOLEAN NOT NULL DEFAULT false,
    ttl_secs   INT NOT NULL,
    approver   UUID REFERENCES users ON DELETE SET NULL,
    decided_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX grants_pending ON grants (created_at) WHERE status = 'pending';

CREATE TABLE sessions (
    id               UUID PRIMARY KEY,
    grant_id         UUID REFERENCES grants ON DELETE SET NULL,
    user_id          UUID REFERENCES users ON DELETE SET NULL,
    node_id          UUID REFERENCES nodes ON DELETE SET NULL,
    node_name        TEXT NOT NULL,
    username         TEXT NOT NULL,
    login            TEXT NOT NULL,
    protocol         TEXT NOT NULL,
    replica          TEXT NOT NULL,
    emergency        BOOLEAN NOT NULL DEFAULT false,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at         TIMESTAMPTZ,
    end_reason       TEXT,
    kill_requested   TEXT,
    recording_path   TEXT,
    recording_sha256 TEXT
);

CREATE TABLE file_ops (
    id         BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions ON DELETE CASCADE,
    op         TEXT NOT NULL,
    path       TEXT NOT NULL,
    path2      TEXT,
    bytes      BIGINT NOT NULL DEFAULT 0,
    at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id       BIGSERIAL PRIMARY KEY,
    at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind     TEXT NOT NULL,
    severity TEXT NOT NULL,
    actor    TEXT,
    data     JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_events_at ON audit_events (at DESC);
