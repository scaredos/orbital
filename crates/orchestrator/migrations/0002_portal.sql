-- Portal sessions live in api_tokens: rows with a csrf token are browser cookies (8h max, 30 min idle);
-- auth_time is the IdP's auth_time claim, used for step-up checks.
ALTER TABLE api_tokens
    ADD COLUMN csrf      TEXT,
    ADD COLUMN last_used TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN auth_time TIMESTAMPTZ;

-- Portal route to land on after login (step-up re-auth returns the user where they were).
ALTER TABLE login_requests ADD COLUMN return_to TEXT;

-- Labels forced onto the node that enrolls with this token (team-scoped admins must pin their team).
ALTER TABLE join_tokens ADD COLUMN labels JSONB NOT NULL DEFAULT '{}';

-- Role bindings may be scoped to a team: the permission then only covers nodes labelled team=<team>.
-- '' = global.
ALTER TABLE role_bindings ADD COLUMN team TEXT NOT NULL DEFAULT '';
ALTER TABLE role_bindings DROP CONSTRAINT role_bindings_pkey;
ALTER TABLE role_bindings ADD PRIMARY KEY (grp, role, team);

-- Break-glass grants are reviewed after the fact.
ALTER TABLE grants
    ADD COLUMN reviewed_by TEXT,
    ADD COLUMN reviewed_at TIMESTAMPTZ;
