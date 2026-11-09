//! Role management: roles carry permissions from the catalog; bindings map OIDC groups to roles,
//! optionally scoped to a team. Built-in roles are seeded rows and read-only.

use crate::{
    auth::{err, ApiResult, User, CATALOG},
    AppRef,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:/".contains(c))
}

/// Every write: rbac:write + a fresh SSO login.
fn writer(user: &User) -> ApiResult<()> {
    user.require("rbac:write")?;
    user.require_fresh()
}

pub async fn get(State(app): State<AppRef>, user: User) -> ApiResult<Json<Value>> {
    user.require("rbac:write")?;
    let roles: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(r) FROM roles r ORDER BY builtin DESC, name").fetch_all(&app.db).await?;
    let bindings: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('group', grp, 'role', role, 'team', NULLIF(team, '')) FROM role_bindings ORDER BY grp, role, team",
    )
    .fetch_all(&app.db)
    .await?;
    Ok(Json(json!({"catalog": CATALOG, "roles": roles, "bindings": bindings})))
}

#[derive(Deserialize)]
pub struct RoleBody {
    permissions: Vec<String>,
}

pub async fn put_role(State(app): State<AppRef>, user: User, Path(name): Path<String>, Json(b): Json<RoleBody>) -> ApiResult<Json<Value>> {
    writer(&user)?;
    if !valid_name(&name) {
        return Err(err(StatusCode::BAD_REQUEST, "role name: 1-64 chars of [A-Za-z0-9-_.:/]"));
    }
    if let Some(p) = b.permissions.iter().find(|p| !CATALOG.contains(&p.as_str())) {
        return Err(err(StatusCode::BAD_REQUEST, format!("unknown permission {p}")));
    }
    let n = sqlx::query(
        "INSERT INTO roles (name, permissions) VALUES ($1, $2)
         ON CONFLICT (name) DO UPDATE SET permissions = $2 WHERE NOT roles.builtin",
    )
    .bind(&name)
    .bind(&b.permissions)
    .execute(&app.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(err(StatusCode::CONFLICT, "built-in roles cannot be changed"));
    }
    app.audit("rbac.role_saved", "warn", Some(&user.username), json!({"role": name, "permissions": b.permissions})).await;
    app.notify_change().await;
    Ok(Json(json!({"role": name})))
}

pub async fn delete_role(State(app): State<AppRef>, user: User, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    writer(&user)?;
    let n = sqlx::query("DELETE FROM roles WHERE name = $1 AND NOT builtin").bind(&name).execute(&app.db).await?.rows_affected();
    if n == 0 {
        return Err(err(StatusCode::NOT_FOUND, "no such custom role"));
    }
    app.audit("rbac.role_deleted", "warn", Some(&user.username), json!({"role": name})).await;
    app.notify_change().await;
    Ok(Json(json!({"deleted": name})))
}

#[derive(Deserialize)]
pub struct BindingBody {
    group: String,
    role: String,
    #[serde(default)]
    team: Option<String>,
}

pub async fn add_binding(State(app): State<AppRef>, user: User, Json(b): Json<BindingBody>) -> ApiResult<Json<Value>> {
    writer(&user)?;
    let team = b.team.unwrap_or_default();
    if !valid_name(&b.group) || !(team.is_empty() || valid_name(&team)) {
        return Err(err(StatusCode::BAD_REQUEST, "group/team: 1-64 chars of [A-Za-z0-9-_.:/]"));
    }
    sqlx::query("INSERT INTO role_bindings (grp, role, team) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(&b.group)
        .bind(&b.role)
        .bind(&team)
        .execute(&app.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => err(StatusCode::BAD_REQUEST, "no such role"),
            e => e.into(),
        })?;
    app.audit("rbac.binding_added", "warn", Some(&user.username), json!({"group": b.group, "role": b.role, "team": team})).await;
    app.notify_change().await;
    Ok(Json(json!({"group": b.group, "role": b.role, "team": team})))
}

pub async fn delete_binding(State(app): State<AppRef>, user: User, Json(b): Json<BindingBody>) -> ApiResult<Json<Value>> {
    writer(&user)?;
    let team = b.team.unwrap_or_default();
    let n = sqlx::query("DELETE FROM role_bindings WHERE grp = $1 AND role = $2 AND team = $3")
        .bind(&b.group)
        .bind(&b.role)
        .bind(&team)
        .execute(&app.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(err(StatusCode::NOT_FOUND, "no such binding"));
    }
    app.audit("rbac.binding_removed", "warn", Some(&user.username), json!({"group": b.group, "role": b.role, "team": team})).await;
    app.notify_change().await;
    Ok(Json(json!({"removed": true})))
}
