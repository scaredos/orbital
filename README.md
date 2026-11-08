<div align="center">

# 🛰️ orbital

**Self-hosted zero trust access to your infrastructure.**

SSH, HTTPS, RDP and VNC to any host without a VPN, without open inbound ports, and with every session justified, approved and recorded.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-pre--alpha-orange)
![Rust](https://img.shields.io/badge/built%20with-Rust-dea584)

</div>

> [!WARNING]
> Orbital is in early design and development. Nothing here is production-ready yet. The design is settled, the code is being written. Star or watch the repo to follow along.

---

## Why Orbital?

Traditional VPNs hand out network access. Orbital hands out **access to one service, for one person, for one reason, for a limited time**, and keeps a record of what happened.

- **No inbound ports on your hosts.** A small agent dials *out* to your orchestrator over mTLS. Firewalls stay closed.
- **Identity first.** Users sign in with your existing SSO (any OIDC provider: Okta, Google, Keycloak, Authentik…).
- **Every session has a reason.** Users say why they need access. Sensitive rules require an approver; emergencies get a loud break-glass path.
- **Everything is audited.** SSH sessions are recorded and replayable, HTTPS requests are logged, RDP/VNC sessions are recorded, file transfers are tracked.
- **Deploying a node takes one command.** Download a pre-configured agent from the portal, run it, answer a few prompts. Done.
- **Self-hosted.** Your keys, your logs, your infrastructure. Apache-2.0.

## How it works

```
                        ┌───────────────────────────────┐
  engineer ── CLI ──TLS─┤                               │──mTLS (outbound)── agent ── sshd / app ports
                        │   orchestrator (1..n)         │
  browser ──── HTTPS ───┤   SSO · policy · approvals    │──mTLS (outbound)── agent ── RDP / VNC
                        │   recording · audit           │
                        └──────┬──────────────┬─────────┘
                               │              │
                           Postgres        guacd (RDP/VNC)
```

1. **Agents** run on each host as an unprivileged, sandboxed systemd service and keep an outbound mTLS tunnel to every orchestrator replica.
2. **Users** authenticate with SSO, pick a target, and give a reason. If the matching rule requires approval, an approver signs off in the portal.
3. **The orchestrator** issues a short-lived, signed grant and relays the session through the agent's tunnel. The agent independently verifies every grant and only exposes the services you chose at install time.
4. **Everything is logged**: who, what, when, why, how long, and for SSH, exactly what was typed and printed.

## Features

### Access
| | |
|---|---|
| **SSH** | Native `ssh`, `scp`, `rsync` and VS Code Remote-SSH via `orbital setup`, plus a browser terminal |
| **HTTPS apps** | Internal web apps on `app.apps.example.com`, behind SSO, with a signed identity JWT passed to the app |
| **RDP / VNC** | Full desktops in the browser via Apache Guacamole |
| **Any TCP** | `orbital proxy db-01:5432` for databases and everything else |

### Security
- Label-based, **default-deny** policy: *"group `dba` may reach `postgres` on nodes labeled `env=prod`"*
- Explicit allowed logins per rule. No `root` unless a rule says so
- **Short-lived certificates** everywhere: Orbital SSH CA certs live for minutes, not months
- **Device-bound credentials** using TPM / Secure Enclave keys where available
- **Live revocation**: remove someone from an SSO group and their open sessions end within a minute
- Agents verify an orchestrator-signed grant on every stream, so a compromised orchestrator can't reach ports a host never exposed
- CA keys encrypted at rest; release binaries signed and verified on self-update
- Post-quantum ready: hybrid **X25519MLKEM768** key exchange and **ML-DSA** for the agent channel

### Audit & oversight
- Session recording with replay for SSH (asciicast) and RDP/VNC
- Per-request HTTPS logs and SFTP/SCP file transfer logs
- **Watch live** sessions read-only, and kill them instantly
- Approval queue, break-glass alerts, signed webhooks, JSON audit stream for your SIEM
- Fine-grained RBAC with built-in admin, team-admin, auditor and read-only roles

## Adding a node (planned UX)

```bash
curl -fsSL https://orbital.example.com/dl/<one-time-token> -o orbital-agent
chmod +x orbital-agent
sudo ./orbital-agent install
```

```
? Node name (db-prod-02)
? Labels  env=prod, team=data
? Expose services  found listening:
  ◉ 22    sshd       → ssh
  ◉ 5432  postgres   → postgres
  ◯ 9100  node_exp
? Trust Orbital SSH CA in sshd? Yes
? Install systemd service? Yes
✓ enrolled · cert valid 30d · tunnel up
```

Every prompt has a flag (`-y --name … --label … --expose ssh=22`) for Ansible, cloud-init and friends.

## Connecting (planned UX)

```bash
orbital login          # SSO in your browser, once a day
orbital setup          # one-time: wires *.orbital into ~/.ssh/config

ssh deploy@web-01.orbital
# orbital: reason for access? Deploy hotfix 4.12.1
# deploy@web-01:~$
```

## Portal preview

Open [`web/samples/portal.html`](web/samples/portal.html) in a browser for an interactive mockup of the portal (nodes, add-node flow, access requests, approvals, audit & replay, policy editor, browser terminal) in dark and light themes.

## Project layout

```
crates/
  proto/          wire protocol shared by agent and orchestrator
  agent/          host daemon + interactive installer (orbital-agent)
  orchestrator/   API, portal, tunnels, SSH recording proxy, policy, CA
  cli/            user CLI (orbital login | ssh | proxy | setup)
web/              portal (React + TypeScript), embedded into the orchestrator
deploy/           docker-compose and container images
```

## Roadmap

- [ ] **M1: Spine.** Enrollment, tunnels, SSO, policy, approvals, recorded SSH via CLI, docker-compose
- [ ] **M2: Portal.** Full web UI and browser SSH terminal
- [ ] **M3: HTTPS apps.** Wildcard app proxy with request logs
- [ ] **M4: Desktops.** RDP/VNC through guacd with recording
- [ ] **Later:** ACME DNS-01 certificates, direct peer-to-peer data path, Windows & macOS agents

## Contributing

Orbital is early, and design feedback is just as valuable as code right now. Open an issue to discuss ideas, threat-model concerns or use cases before starting larger changes.

For security issues, please **do not** open a public issue. Contact the maintainer privately instead.

## License

[Apache License 2.0](LICENSE)
