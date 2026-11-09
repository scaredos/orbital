//! Public HTTPS API; the portal itself is served by web.rs.

use crate::{
    auth::{self, err, ApiResult, User},
    policy::{self, Decision, Rule},
    rbac, replica_urls,
    ssh::{self, GrantRow, GRANT_SELECT},
    web, App, AppRef,
};
use anyhow::Result;
use axum::{
    body::Body,
    extract::{Path, Query, Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use orbital_proto::{append_trailer, sha256_hex, strip_trailer, AgentTrailer};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

pub async fn serve(app: AppRef) -> Result<()> {
    let tls = crate::keys::public_tls(&app.keys, &app.cfg.tls_sans, app.cfg.tls_cert.as_deref(), app.cfg.tls_key.as_deref())?;
    let addr: std::net::SocketAddr = app.cfg.listen.parse()?;
    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/auth/login", get(auth::login))
        .route("/v1/auth/callback", get(auth::callback))
        .route("/v1/auth/exchange", post(auth::exchange))
        .route("/v1/auth/password", post(auth::password_login))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/me", get(auth::me))
        .route("/v1/nodes", get(list_nodes))
        .route("/v1/nodes/join", post(join_token))
        .route("/v1/nodes/{name}", delete(remove_node))
        .route("/dl/{token}", get(download_agent))
        .route("/v1/policy", get(get_policy).put(put_policy))
        .route("/v1/grants", post(create_grant).get(my_grants))
        .route("/v1/grants/{id}", get(get_grant))
        .route("/v1/grants/{id}/{action}", post(decide_grant))
        .route("/v1/approvals", get(list_approvals))
        .route("/v1/sessions", get(list_sessions))
        .route("/v1/sessions/{id}/kill", post(kill_session))
        .route("/v1/sessions/{id}/recording", get(get_recording))
        .route("/v1/sessions/{id}/live", get(web::live))
        .route("/v1/terminal", get(web::terminal))
        .route("/v1/audit", get(list_audit))
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/{id}", delete(revoke_device))
        .route("/v1/rbac", get(rbac::get))
        .route("/v1/rbac/roles/{name}", put(rbac::put_role).delete(rbac::delete_role))
        .route("/v1/rbac/bindings", post(rbac::add_binding).delete(rbac::delete_binding))
        .route("/v1/connect", get(connect))
        .fallback(web::asset)
        .with_state(app);
    tracing::info!("api listening on https://{addr}");
    axum_server::bind_rustls(addr, axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls)))
        .serve(router.into_make_service())
        .await?;
    Ok(())
}

pub async fn load_rules(app: &App) -> Result<Vec<Rule>> {
    let bodies: Vec<sqlx::types::Json<Rule>> = sqlx::query_scalar("SELECT body FROM policy_rules ORDER BY name").fetch_all(&app.db).await?;
    Ok(bodies.into_iter().map(|b| b.0).collect())
}

// ---------------------------------------------------------------- nodes

async fn list_nodes(State(app): State<AppRef>, _user: User) -> ApiResult<Json<Value>> {
    // ponytail: every signed-in user can list nodes; filter by policy if node names are sensitive
    let rows: Vec<(String, Value, Value, Option<DateTime<Utc>>, Option<String>, DateTime<Utc>, bool, bool)> = sqlx::query_as(
        "SELECT name, labels, services, last_seen, version, cert_expires_at,
                last_seen > now() - interval '90 seconds',
                last_seen IS NULL OR last_seen < now() - make_interval(days => $1)
         FROM nodes ORDER BY name",
    )
    .bind(app.cfg.stale_days as i32)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|(name, labels, services, last_seen, version, cert_expires, online, stale)| json!({
            "name": name, "labels": labels, "services": services, "last_seen": last_seen, "version": version,
            "cert_expires_at": cert_expires, "online": online, "stale": stale
        }))
        .collect::<Vec<_>>())))
}

#[derive(Deserialize, Default)]
struct JoinReq {
    /// forced onto the enrolling node, overriding what the installer reports
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

fn valid_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

async fn join_token(State(app): State<AppRef>, user: User, body: Option<Json<JoinReq>>) -> ApiResult<Json<Value>> {
    let labels = body.map(|b| b.0.labels).unwrap_or_default();
    if !labels.iter().all(|(k, v)| valid_label(k) && valid_label(v)) {
        return Err(err(StatusCode::BAD_REQUEST, "label keys and values: 1-63 chars of [A-Za-z0-9-_.]"));
    }
    // team-scoped admins can only mint tokens that pin their team label
    user.require_for("nodes:write", &labels)?;
    let token = auth::random_token("join_");
    sqlx::query("INSERT INTO join_tokens (token_hash, created_by, expires_at, labels) VALUES ($1,$2, now() + interval '1 hour', $3)")
        .bind(sha256_hex(token.as_bytes()))
        .bind(user.id)
        .bind(sqlx::types::Json(&labels))
        .execute(&app.db)
        .await?;
    app.audit("node.join_token_created", "info", Some(&user.username), json!({"labels": labels})).await;
    let url = format!("{}/dl/{token}", app.cfg.public_url);
    Ok(Json(json!({
        "token": token,
        "url": url,
        "expires_in": 3600,
        "command": format!("curl -fsSL '{url}?arch='$(uname -m) -o orbital-agent && chmod +x orbital-agent && sudo ./orbital-agent install"),
    })))
}

#[derive(Deserialize)]
struct ArchQuery {
    arch: Option<String>,
}

/// Stock agent binary + trailer {orch_urls, ca_fingerprint, join_token}.
async fn download_agent(State(app): State<AppRef>, Path(token): Path<String>, Query(q): Query<ArchQuery>) -> ApiResult<Response> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM join_tokens WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now())",
    )
    .bind(sha256_hex(token.as_bytes()))
    .fetch_one(&app.db)
    .await?;
    if !valid {
        return Err(err(StatusCode::NOT_FOUND, "join token invalid, expired or already used"));
    }
    let arch = match q.arch.as_deref().unwrap_or("x86_64") {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        a => return Err(err(StatusCode::BAD_REQUEST, format!("unsupported arch {a}"))),
    };
    let path = format!("{}/orbital-agent-{arch}", app.cfg.agent_dir);
    let bin = tokio::fs::read(&path).await.map_err(|e| err(StatusCode::NOT_FOUND, format!("{path}: {e}")))?;
    let trailer = AgentTrailer { orch_urls: replica_urls(&app).await, ca_fingerprint: app.keys.ca_fingerprint(), join_token: token };
    let body = append_trailer(strip_trailer(&bin), &serde_json::to_vec(&trailer).map_err(anyhow::Error::from)?);
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"orbital-agent-{arch}\"")),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response())
}

async fn remove_node(State(app): State<AppRef>, user: User, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    let labels: Option<sqlx::types::Json<BTreeMap<String, String>>> =
        sqlx::query_scalar("SELECT labels FROM nodes WHERE name = $1").bind(&name).fetch_optional(&app.db).await?;
    user.require_for("nodes:write", &labels.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such node"))?.0)?;
    let mut tx = app.db.begin().await?;
    let row: Option<(Uuid, String, Option<String>)> =
        sqlx::query_as("DELETE FROM nodes WHERE name = $1 RETURNING id, cert_serial, prev_serial").bind(&name).fetch_optional(&mut *tx).await?;
    let (id, serial, prev) = row.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such node"))?;
    for s in [Some(serial), prev].into_iter().flatten() {
        sqlx::query("INSERT INTO revoked_certs (serial) VALUES ($1) ON CONFLICT DO NOTHING").bind(s).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    if let Some(t) = app.tunnels.lock().await.remove(&id) {
        t.cancel.cancel();
    }
    app.audit("node.removed", "warn", Some(&user.username), json!({"node": name, "node_id": id})).await;
    app.notify_change().await;
    Ok(Json(json!({"removed": name})))
}

// ---------------------------------------------------------------- policy

async fn get_policy(State(app): State<AppRef>, user: User) -> ApiResult<Json<Vec<Rule>>> {
    user.require("policy:read")?;
    Ok(Json(load_rules(&app).await?))
}

async fn put_policy(State(app): State<AppRef>, user: User, Json(rules): Json<Vec<Rule>>) -> ApiResult<Json<Value>> {
    user.require("policy:write")?;
    user.require_fresh()?;
    let mut names: Vec<&str> = rules.iter().map(|r| r.name.as_str()).collect();
    names.sort();
    names.dedup();
    if names.len() != rules.len() || names.iter().any(|n| n.is_empty()) {
        return Err(err(StatusCode::BAD_REQUEST, "rule names must be unique and non-empty"));
    }
    let mut tx = app.db.begin().await?;
    sqlx::query("DELETE FROM policy_rules").execute(&mut *tx).await?;
    for r in &rules {
        sqlx::query("INSERT INTO policy_rules (name, body) VALUES ($1, $2)").bind(&r.name).bind(sqlx::types::Json(r)).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    app.audit("policy.updated", "warn", Some(&user.username), json!({"rules": rules.len()})).await;
    app.notify_change().await;
    Ok(Json(json!({"rules": rules.len()})))
}

// ---------------------------------------------------------------- grants

#[derive(Deserialize)]
struct GrantReq {
    node: String,
    #[serde(default = "ssh_svc")]
    service: String,
    login: Option<String>,
    reason: String,
    #[serde(default)]
    emergency: bool,
}
fn ssh_svc() -> String {
    "ssh".into()
}

async fn grant_view(app: &App, id: Uuid) -> ApiResult<GrantRow> {
    sqlx::query_as::<_, GrantRow>(&format!("{GRANT_SELECT} WHERE g.id = $1"))
        .bind(id)
        .fetch_optional(&app.db)
        .await?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such grant"))
}

async fn create_grant(State(app): State<AppRef>, user: User, Json(b): Json<GrantReq>) -> ApiResult<Json<GrantRow>> {
    let reason = b.reason.trim();
    if reason.is_empty() || reason.len() > 1000 {
        return Err(err(StatusCode::BAD_REQUEST, "a reason (1-1000 chars) is required"));
    }
    if b.emergency {
        user.require_fresh()?; // break-glass from the portal re-authenticates first
    }
    // fresh groups from the IdP; a dead IdP session means re-login
    if !auth::refresh_user(&app, user.id).await? {
        return Err(err(StatusCode::UNAUTHORIZED, "IdP session ended, run `orbital login`"));
    }
    let user = auth::load_user(&app, user.id, user.device_id).await?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "user disabled"))?;
    let login = b.login.unwrap_or_else(|| user.username.clone());
    let node: Option<(Uuid, sqlx::types::Json<BTreeMap<String, String>>)> =
        sqlx::query_as("SELECT id, labels FROM nodes WHERE name = $1").bind(&b.node).fetch_optional(&app.db).await?;
    let (node_id, labels) = node.ok_or_else(|| err(StatusCode::NOT_FOUND, format!("no node named {:?}", b.node)))?;
    let rules = load_rules(&app).await?;
    let req = policy::Request {
        username: &user.username,
        groups: &user.groups,
        node_labels: &labels,
        service: &b.service,
        login: &login,
        emergency: b.emergency,
    };
    let decision = policy::evaluate(&rules, &req);
    let base = json!({"node": b.node, "login": login, "service": b.service, "reason": reason});
    let (status, rule, ttl, emergency) = match decision {
        Decision::Deny(why) => {
            app.audit("grant.denied", "warn", Some(&user.username), json!({"request": base, "why": why})).await;
            return Err(err(StatusCode::FORBIDDEN, why));
        }
        Decision::Allow { rule, ttl } => ("approved", rule, ttl, false),
        Decision::NeedsApproval { rule, ttl } => ("pending", rule, ttl, false),
        Decision::Emergency { rule, ttl } => ("approved", rule, ttl, true),
    };
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO grants (id, user_id, node_id, service, login, reason, rule, status, emergency, ttl_secs, decided_at, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
                 CASE WHEN $8 = 'approved' THEN now() END,
                 CASE WHEN $8 = 'approved' THEN now() + make_interval(secs => $10) END)",
    )
    .bind(id)
    .bind(user.id)
    .bind(node_id)
    .bind(&b.service)
    .bind(&login)
    .bind(reason)
    .bind(&rule)
    .bind(status)
    .bind(emergency)
    .bind(ttl)
    .execute(&app.db)
    .await?;
    let (kind, sev) = match (status, emergency) {
        (_, true) => ("grant.emergency", "high"),
        ("pending", _) => ("grant.requested", "info"),
        _ => ("grant.approved", "info"),
    };
    app.audit(kind, sev, Some(&user.username), json!({"grant": id, "rule": rule, "request": base})).await;
    Ok(Json(grant_view(&app, id).await?))
}

async fn get_grant(State(app): State<AppRef>, user: User, Path(id): Path<Uuid>) -> ApiResult<Json<GrantRow>> {
    let g = grant_view(&app, id).await?;
    if g.user_id != user.id && !user.has_for("approvals:decide", &g.node_labels) {
        return Err(err(StatusCode::NOT_FOUND, "no such grant"));
    }
    Ok(Json(g))
}

async fn my_grants(State(app): State<AppRef>, user: User) -> ApiResult<Json<Vec<GrantRow>>> {
    Ok(Json(
        sqlx::query_as::<_, GrantRow>(&format!("{GRANT_SELECT} WHERE g.user_id = $1 ORDER BY g.created_at DESC LIMIT 20"))
            .bind(user.id)
            .fetch_all(&app.db)
            .await?,
    ))
}

async fn decide_grant(State(app): State<AppRef>, user: User, Path((id, action)): Path<(Uuid, String)>) -> ApiResult<Json<GrantRow>> {
    let g = grant_view(&app, id).await?;
    let q = match action.as_str() {
        "approve" | "deny" => {
            user.require_for("approvals:decide", &g.node_labels)?;
            user.require_fresh()?;
            if g.user_id == user.id {
                return Err(err(StatusCode::FORBIDDEN, "you cannot decide your own request"));
            }
            if action == "approve" {
                "UPDATE grants SET status = 'approved', approver = $2, decided_at = now(), expires_at = now() + make_interval(secs => ttl_secs)
                 WHERE id = $1 AND status = 'pending'"
            } else {
                "UPDATE grants SET status = 'denied', approver = $2, decided_at = now() WHERE id = $1 AND status = 'pending'"
            }
        }
        "revoke" => {
            if g.user_id != user.id && !user.has_for("sessions:kill", &g.node_labels) {
                return Err(err(StatusCode::FORBIDDEN, "missing permission sessions:kill"));
            }
            "UPDATE grants SET status = 'revoked', approver = COALESCE(approver, $2) WHERE id = $1 AND status IN ('pending','approved')"
        }
        // break-glass grants are reviewed after the fact
        "review" => {
            user.require_for("approvals:decide", &g.node_labels)?;
            "UPDATE grants SET reviewed_by = (SELECT username FROM users WHERE id = $2), reviewed_at = now()
             WHERE id = $1 AND emergency AND reviewed_by IS NULL"
        }
        _ => return Err(err(StatusCode::NOT_FOUND, "unknown action")),
    };
    let n = sqlx::query(q).bind(id).bind(user.id).execute(&app.db).await?.rows_affected();
    if n == 0 {
        return Err(err(StatusCode::CONFLICT, format!("grant is {}", g.status)));
    }
    let kind = match action.as_str() {
        "approve" => "grant.approved",
        "deny" => "grant.denied",
        "review" => "grant.reviewed",
        _ => "grant.revoked",
    };
    app.audit(kind, "info", Some(&user.username), json!({"grant": id, "requester": g.user_id, "node": g.node_name, "login": g.login, "reason": g.reason})).await;
    app.notify_change().await;
    Ok(Json(grant_view(&app, id).await?))
}

/// Pending requests first, then break-glass grants nobody has reviewed yet.
async fn list_approvals(State(app): State<AppRef>, user: User) -> ApiResult<Json<Value>> {
    let (global, teams) = user.scope("approvals:decide")?;
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id', g.id, 'user', u.username, 'node', n.name, 'login', g.login, 'reason', g.reason,
                'rule', g.rule, 'status', g.status, 'emergency', g.emergency, 'ttl_secs', g.ttl_secs, 'created_at', g.created_at,
                'live_session', (SELECT s.id FROM sessions s WHERE s.grant_id = g.id AND s.ended_at IS NULL LIMIT 1))
         FROM grants g JOIN users u ON u.id = g.user_id JOIN nodes n ON n.id = g.node_id
         WHERE (g.status = 'pending' OR (g.emergency AND g.reviewed_by IS NULL))
           AND ($1 OR n.labels->>'team' = ANY($2))
         ORDER BY g.status = 'pending' DESC, g.created_at",
    )
    .bind(global)
    .bind(&teams)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(json!(rows)))
}

// ---------------------------------------------------------------- sessions / audit

async fn list_sessions(State(app): State<AppRef>, user: User) -> ApiResult<Json<Value>> {
    let (global, teams) = user.scope("audit:read")?;
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(s) || jsonb_build_object('reason', g.reason, 'files',
            (SELECT coalesce(jsonb_agg(to_jsonb(f) - 'session_id' ORDER BY f.id), '[]') FROM file_ops f WHERE f.session_id = s.id))
         FROM sessions s LEFT JOIN nodes n ON n.id = s.node_id LEFT JOIN grants g ON g.id = s.grant_id
         WHERE $1 OR n.labels->>'team' = ANY($2)
         ORDER BY s.started_at DESC LIMIT 200",
    )
    .bind(global)
    .bind(&teams)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(json!(rows)))
}

async fn session_labels(app: &App, id: Uuid) -> ApiResult<BTreeMap<String, String>> {
    let l: Option<sqlx::types::Json<BTreeMap<String, String>>> = sqlx::query_scalar(
        "SELECT coalesce(n.labels, '{}') FROM sessions s LEFT JOIN nodes n ON n.id = s.node_id WHERE s.id = $1",
    )
    .bind(id)
    .fetch_optional(&app.db)
    .await?;
    Ok(l.ok_or_else(|| err(StatusCode::NOT_FOUND, "no such session"))?.0)
}

async fn kill_session(State(app): State<AppRef>, user: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    user.require_for("sessions:kill", &session_labels(&app, id).await?)?;
    let n = sqlx::query("UPDATE sessions SET kill_requested = $2 WHERE id = $1 AND ended_at IS NULL")
        .bind(id)
        .bind(&user.username)
        .execute(&app.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(err(StatusCode::NOT_FOUND, "no live session with that id"));
    }
    ssh::kill(&app, id, &format!("killed by {}", user.username)).await; // fast path if it's ours
    app.notify_change().await; // other replicas
    Ok(Json(json!({"killed": id})))
}

async fn get_recording(State(app): State<AppRef>, user: User, Path(id): Path<Uuid>) -> ApiResult<Response> {
    user.require_for("recordings:view", &session_labels(&app, id).await?)?;
    let path: Option<String> =
        sqlx::query_scalar("SELECT recording_path FROM sessions WHERE id = $1").bind(id).fetch_optional(&app.db).await?.flatten();
    let path = path.ok_or_else(|| err(StatusCode::NOT_FOUND, "no recording"))?;
    let data = tokio::fs::read(&path).await.map_err(|e| err(StatusCode::NOT_FOUND, format!("{e}")))?;
    app.audit("recording.viewed", "info", Some(&user.username), json!({"session": id})).await;
    Ok(([(header::CONTENT_TYPE, "application/x-asciicast")], data).into_response())
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<i64>,
    kind: Option<String>,
    session: Option<Uuid>,
}

async fn list_audit(State(app): State<AppRef>, user: User, Query(q): Query<AuditQuery>) -> ApiResult<Json<Value>> {
    // team-scoped readers see events naming one of their team's nodes
    let (global, teams) = user.scope("audit:read")?;
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(a) FROM audit_events a
         WHERE ($2::text IS NULL OR kind LIKE $2 || '%')
           AND ($3::text IS NULL OR data->>'session' = $3)
           AND ($4 OR data->>'node' IN (SELECT name FROM nodes WHERE labels->>'team' = ANY($5)))
         ORDER BY id DESC LIMIT $1",
    )
    .bind(q.limit.unwrap_or(100).clamp(1, 1000))
    .bind(q.kind)
    .bind(q.session.map(|s| s.to_string()))
    .bind(global)
    .bind(&teams)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(json!(rows)))
}

// ---------------------------------------------------------------- devices

async fn list_devices(State(app): State<AppRef>, user: User) -> ApiResult<Json<Value>> {
    let all = user.has("devices:write");
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT to_jsonb(d) - 'public_key' || jsonb_build_object('user', u.username) FROM devices d JOIN users u ON u.id = d.user_id
         WHERE $1 OR d.user_id = $2 ORDER BY d.created_at",
    )
    .bind(all)
    .bind(user.id)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(json!(rows)))
}

async fn revoke_device(State(app): State<AppRef>, user: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let n = sqlx::query("UPDATE devices SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL AND ($2 OR user_id = $3)")
        .bind(id)
        .bind(user.has("devices:write"))
        .bind(user.id)
        .execute(&app.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(err(StatusCode::NOT_FOUND, "no such device"));
    }
    sqlx::query("DELETE FROM api_tokens WHERE device_id = $1").bind(id).execute(&app.db).await?;
    app.audit("device.revoked", "warn", Some(&user.username), json!({"device": id})).await;
    app.notify_change().await;
    Ok(Json(json!({"revoked": id})))
}

// ---------------------------------------------------------------- SSH connect (HTTP upgrade)

#[derive(Deserialize)]
struct ConnectQuery {
    grant: Uuid,
}

/// `orbital proxy` upgrades this request to a raw byte pipe carrying the user's SSH session.
async fn connect(State(app): State<AppRef>, user: User, Query(q): Query<ConnectQuery>, mut req: Request) -> ApiResult<Response> {
    let g = usable_grant(&app, &user, q.grant).await?;
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(up) => ssh::serve_connection(app, hyper_util::rt::TokioIo::new(up), g, user, Uuid::new_v4(), false).await,
            Err(e) => tracing::warn!("upgrade failed: {e}"),
        }
    });
    Ok(Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "orbital-ssh")
        .body(Body::empty())
        .unwrap())
}

/// The grant is the caller's, approved, unexpired, still allowed by policy, and its node is connected here.
pub async fn usable_grant(app: &App, user: &User, id: Uuid) -> ApiResult<GrantRow> {
    let g = grant_view(app, id).await?;
    if g.user_id != user.id {
        return Err(err(StatusCode::FORBIDDEN, "grant belongs to another user"));
    }
    match g.status.as_str() {
        "approved" if g.expires_at.is_some_and(|e| e > Utc::now()) => {}
        "approved" => return Err(err(StatusCode::FORBIDDEN, "grant expired")),
        s => return Err(err(StatusCode::FORBIDDEN, format!("grant is {s}"))),
    }
    if g.service != "ssh" {
        return Err(err(StatusCode::BAD_REQUEST, "not an ssh grant"));
    }
    // policy may have changed since the grant was issued
    let rules = load_rules(app).await?;
    let preq = policy::Request {
        username: &user.username,
        groups: &user.groups,
        node_labels: &g.node_labels,
        service: "ssh",
        login: &g.login,
        emergency: g.emergency,
    };
    if let Decision::Deny(why) = policy::evaluate(&rules, &preq) {
        return Err(err(StatusCode::FORBIDDEN, why));
    }
    if !app.tunnels.lock().await.contains_key(&g.node_id) {
        return Err(err(StatusCode::SERVICE_UNAVAILABLE, format!("node {} is not connected to this replica", g.node_name)));
    }
    Ok(g)
}
