# Running Orbital

## Dev / E2E stack

```bash
deploy/e2e.sh          # builds images, starts the stack, runs the end-to-end checks, tears down
KEEP=1 deploy/e2e.sh   # same, but leaves the stack running
```

The stack (`deploy/docker-compose.yml`): two orchestrator replicas, Postgres, guacd (idle until RDP/VNC support lands),
Keycloak with the `orbital` realm (users `alice` / `carol` / `bob`, see `keycloak/orbital-realm.json`),
a Debian `host` running sshd, and a `client` with OpenSSH + the `orbital` CLI.

## Orchestrator configuration

All settings are flags or `ORBITAL_*` env vars (`orbital-orchestrator --help`). The important ones:

| Variable | Meaning |
|---|---|
| `ORBITAL_DATABASE_URL` | Postgres URL (migrations run at startup) |
| `ORBITAL_PUBLIC_URL` | Base URL users and the IdP redirect reach, e.g. `https://orbital.example.com` |
| `ORBITAL_AGENT_URL` | `host:port` agents dial for **this** replica (advertised to agents) |
| `ORBITAL_TLS_SANS` | Names for the self-issued certs (agent listener, and the portal when no BYO cert) |
| `ORBITAL_TLS_CERT` / `ORBITAL_TLS_KEY` | BYO portal certificate (PEM files) |
| `ORBITAL_KEK_FILE` | 32-byte key (64 hex chars) that seals CA keys in Postgres. Mount as a Docker secret. Every replica needs the same one |
| `ORBITAL_OIDC_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_GROUPS_CLAIM` | OIDC provider. Redirect URI: `<PUBLIC_URL>/v1/auth/callback` |
| `ORBITAL_ADMIN_GROUP` | OIDC group bound to the built-in `admin` role |
| `ORBITAL_ADMIN_PASSWORD` | Enables the break-glass local admin (`orbital login --local`) |
| `ORBITAL_WEBHOOK_URL`, `ORBITAL_WEBHOOK_SECRET` | Every audit event is POSTed as JSON, signed `X-Orbital-Signature: sha256=<hmac>` |

Every audit event is also written to stdout as one JSON line (`{"audit": {...}}`) for your log shipper.
Recordings (`*.cast`, asciicast v2) live in `$ORBITAL_DATA_DIR/recordings`; each session row stores the file's SHA-256.

When the portal uses its self-issued certificate, hand users `$ORBITAL_DATA_DIR/ca.pem` and have them run
`orbital login https://orbital.example.com --ca ca.pem`.

## Policy

`orbital policy rules.json` replaces the policy; `orbital policy` prints it. Default deny. Example: `e2e/policy.json`.

```json
{
  "name": "dba-prod",
  "groups": ["dba"],
  "node_labels": { "env": "prod" },
  "services": ["ssh"],
  "logins": ["{{user.username}}", "postgres"],
  "require_approval": true,
  "emergency": true,
  "max_ttl_secs": 3600
}
```

`root` is only reachable when a rule lists `"root"` literally. `emergency: true` lets the requester
self-approve with `orbital ssh --emergency` (high-severity audit + webhook, session flagged).
