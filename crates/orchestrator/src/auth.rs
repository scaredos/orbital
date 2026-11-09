//! OIDC login (portal + CLI loopback), break-glass admin, API tokens, device keys, RBAC.

use crate::{keys::mint_ssh_cert, App, AppRef, Config};
use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{FromRequestParts, Query, State},
    http::{request::Parts, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken,
    RequestTokenError, Scope, TokenResponse,
};
use orbital_proto::sha256_hex;
use russh::keys::{HashAlg, PublicKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

// ---------------------------------------------------------------- errors

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("{e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        anyhow::Error::from(e).into()
    }
}
pub fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(code, msg.into())
}
pub type ApiResult<T> = std::result::Result<T, ApiError>;

// ---------------------------------------------------------------- OIDC

type Client = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

pub struct Oidc {
    client: Client,
    http: reqwest::Client,
    groups_claim: String,
}

#[derive(Debug)]
pub struct Identity {
    pub sub: String,
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub refresh_token: Option<String>,
}

impl Oidc {
    pub async fn discover(issuer: &str, cfg: &Config) -> Result<Self> {
        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()?;
        let mut last = None;
        for _ in 0..60 {
            match CoreProviderMetadata::discover_async(IssuerUrl::new(issuer.into())?, &http).await {
                Ok(meta) => {
                    let client = CoreClient::from_provider_metadata(
                        meta,
                        ClientId::new(cfg.oidc_client_id.clone()),
                        cfg.oidc_client_secret.clone().map(ClientSecret::new),
                    )
                    .set_redirect_uri(RedirectUrl::new(format!("{}/v1/auth/callback", cfg.public_url))?);
                    return Ok(Oidc { client, http, groups_claim: cfg.oidc_groups_claim.clone() });
                }
                Err(e) => {
                    tracing::info!("waiting for OIDC issuer {issuer}: {e}");
                    last = Some(e);
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            }
        }
        Err(anyhow!("OIDC discovery failed: {:?}", last))
    }

    fn identity(&self, id_token: &openidconnect::core::CoreIdToken, nonce: Option<&Nonce>, refresh: Option<String>) -> Result<Identity> {
        let verifier = self.client.id_token_verifier();
        let claims = match nonce {
            Some(n) => id_token.claims(&verifier, n)?,
            None => id_token.claims(&verifier, |_: Option<&Nonce>| Ok(()))?,
        };
        // Signature verified above; read the non-standard groups claim from the payload.
        let jwt = id_token.to_string();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(jwt.split('.').nth(1).context("jwt")?.trim_end_matches('='))?)?;
        let groups = payload[&self.groups_claim]
            .as_array()
            .map(|a| a.iter().filter_map(|g| g.as_str()).map(|g| g.trim_start_matches('/').to_string()).collect())
            .unwrap_or_default();
        let sub = claims.subject().to_string();
        let email = claims.email().map(|e| e.to_string());
        let username = claims
            .preferred_username()
            .map(|u| u.to_string())
            .or_else(|| email.as_ref().map(|e| e.split('@').next().unwrap_or(e).to_string()))
            .unwrap_or_else(|| sub.clone());
        Ok(Identity { sub, username, email, groups, refresh_token: refresh })
    }

    pub fn authorize(&self) -> (String, String, String, String) {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let (url, state, nonce) = self
            .client
            .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
            .add_scope(Scope::new("email".into()))
            .add_scope(Scope::new("profile".into()))
            .set_pkce_challenge(challenge)
            .url();
        (url.to_string(), state.secret().clone(), nonce.secret().clone(), verifier.secret().clone())
    }

    pub async fn exchange(&self, code: String, pkce: String, nonce: String) -> Result<Identity> {
        let resp = self
            .client
            .exchange_code(AuthorizationCode::new(code))?
            .set_pkce_verifier(PkceCodeVerifier::new(pkce))
            .request_async(&self.http)
            .await
            .map_err(|e| anyhow!("token exchange: {e:?}"))?;
        let idt = resp.id_token().context("IdP returned no id_token")?;
        self.identity(idt, Some(&Nonce::new(nonce)), resp.refresh_token().map(|r| r.secret().clone()))
    }

    /// Ok(None) = the IdP rejected the refresh token (user disabled, session ended).
    pub async fn refresh(&self, rt: &str) -> Result<Option<Identity>> {
        let resp = self.client.exchange_refresh_token(&RefreshToken::new(rt.into()))?.request_async(&self.http).await;
        match resp {
            Ok(resp) => {
                let idt = resp.id_token().context("IdP returned no id_token on refresh")?;
                let next = resp.refresh_token().map(|r| r.secret().clone()).unwrap_or_else(|| rt.to_string());
                Ok(Some(self.identity(idt, None, Some(next))?))
            }
            Err(RequestTokenError::ServerResponse(e)) => {
                tracing::info!("refresh rejected by IdP: {e:?}");
                Ok(None)
            }
            Err(e) => Err(anyhow!("refresh: {e:?}")),
        }
    }
}

/// Re-reads a user's groups from the IdP. Ok(false) = IdP session is gone (groups cleared).
pub async fn refresh_user(app: &App, user_id: Uuid) -> Result<bool> {
    let Some(oidc) = &app.oidc else { return Ok(true) };
    let sealed: Option<Vec<u8>> = sqlx::query_scalar("SELECT refresh_token FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&app.db)
        .await?
        .flatten();
    let Some(sealed) = sealed else { return Ok(true) }; // local admin / no refresh token
    let rt = String::from_utf8(app.keys.kek.open(&sealed)?)?;
    match oidc.refresh(&rt).await? {
        Some(id) => {
            sqlx::query("UPDATE users SET groups = $2, refresh_token = $3, updated_at = now() WHERE id = $1")
                .bind(user_id)
                .bind(&id.groups)
                .bind(id.refresh_token.map(|r| app.keys.kek.seal(r.as_bytes())))
                .execute(&app.db)
                .await?;
            Ok(true)
        }
        None => {
            sqlx::query("UPDATE users SET groups = '{}', refresh_token = NULL, updated_at = now() WHERE id = $1")
                .bind(user_id)
                .execute(&app.db)
                .await?;
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------- tokens + extractor

pub fn random_token(prefix: &str) -> String {
    let b: [u8; 32] = rand::random();
    format!("{prefix}{}", hex::encode(b))
}

async fn issue_token(app: &App, user_id: Uuid, device_id: Option<Uuid>, ttl_secs: i64) -> Result<String> {
    let t = random_token("orb_");
    sqlx::query("INSERT INTO api_tokens (token_hash, user_id, device_id, expires_at) VALUES ($1,$2,$3, now() + make_interval(secs => $4))")
        .bind(sha256_hex(t.as_bytes()))
        .bind(user_id)
        .bind(device_id)
        .bind(ttl_secs as f64)
        .execute(&app.db)
        .await?;
    Ok(t)
}

#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub groups: Vec<String>,
    pub permissions: Vec<String>,
    #[serde(skip)]
    pub device_id: Option<Uuid>,
}

impl User {
    pub fn require(&self, perm: &str) -> ApiResult<()> {
        if self.has(perm) {
            Ok(())
        } else {
            Err(err(StatusCode::FORBIDDEN, format!("missing permission {perm}")))
        }
    }
    pub fn has(&self, perm: &str) -> bool {
        self.permissions.iter().any(|p| p == perm)
    }
}

pub async fn load_user(app: &App, user_id: Uuid, device_id: Option<Uuid>) -> Result<Option<User>> {
    let row: Option<(String, Vec<String>, bool)> =
        sqlx::query_as("SELECT username, groups, disabled FROM users WHERE id = $1").bind(user_id).fetch_optional(&app.db).await?;
    let Some((username, groups, disabled)) = row else { return Ok(None) };
    if disabled {
        return Ok(None);
    }
    let permissions: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT unnest(r.permissions) FROM roles r JOIN role_bindings b ON b.role = r.name WHERE b.grp = ANY($1)",
    )
    .bind(&groups)
    .fetch_all(&app.db)
    .await?;
    Ok(Some(User { id: user_id, username, groups, permissions, device_id }))
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all("cookie").iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';')).find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

impl FromRequestParts<AppRef> for User {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, app: &AppRef) -> ApiResult<Self> {
        let bearer = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_string);
        let (token, via_cookie) = match bearer {
            Some(t) => (t, false),
            None => (cookie(&parts.headers, "orbital_session").ok_or_else(|| err(StatusCode::UNAUTHORIZED, "login required"))?, true),
        };
        // Cookie sessions: SameSite=Strict + a custom header (forces a CORS preflight) on mutations.
        if via_cookie && parts.method != Method::GET && parts.headers.get("x-orbital-csrf").is_none() {
            return Err(err(StatusCode::FORBIDDEN, "missing x-orbital-csrf header"));
        }
        let row: Option<(Uuid, Option<Uuid>)> =
            sqlx::query_as("SELECT user_id, device_id FROM api_tokens WHERE token_hash = $1 AND expires_at > now()")
                .bind(sha256_hex(token.as_bytes()))
                .fetch_optional(&app.db)
                .await?;
        let (uid, did) = row.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "session expired, run `orbital login`"))?;
        load_user(app, uid, did).await?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "user disabled"))
    }
}

// ---------------------------------------------------------------- routes

#[derive(Deserialize)]
pub struct LoginQuery {
    cli_port: Option<u16>,
    cli_state: Option<String>,
}

pub async fn login(State(app): State<AppRef>, Query(q): Query<LoginQuery>) -> ApiResult<Redirect> {
    let oidc = app.oidc.as_ref().ok_or_else(|| err(StatusCode::NOT_FOUND, "OIDC not configured"))?;
    let (url, state, nonce, pkce) = oidc.authorize();
    sqlx::query("DELETE FROM login_requests WHERE created_at < now() - interval '15 minutes'").execute(&app.db).await?;
    sqlx::query("INSERT INTO login_requests (state, nonce, pkce, cli_port, cli_state) VALUES ($1,$2,$3,$4,$5)")
        .bind(state)
        .bind(nonce)
        .bind(pkce)
        .bind(q.cli_port.map(i32::from))
        .bind(q.cli_state)
        .execute(&app.db)
        .await?;
    Ok(Redirect::to(&url))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: String,
    error: Option<String>,
}

pub async fn callback(State(app): State<AppRef>, Query(q): Query<CallbackQuery>) -> ApiResult<Response> {
    let oidc = app.oidc.as_ref().ok_or_else(|| err(StatusCode::NOT_FOUND, "OIDC not configured"))?;
    let req: Option<(String, String, Option<i32>, Option<String>)> = sqlx::query_as(
        "DELETE FROM login_requests WHERE state = $1 AND created_at > now() - interval '15 minutes'
         RETURNING nonce, pkce, cli_port, cli_state",
    )
    .bind(&q.state)
    .fetch_optional(&app.db)
    .await?;
    let (nonce, pkce, cli_port, cli_state) = req.ok_or_else(|| err(StatusCode::BAD_REQUEST, "unknown or expired login state"))?;
    if let Some(e) = q.error {
        return Err(err(StatusCode::UNAUTHORIZED, format!("IdP error: {e}")));
    }
    let id = oidc
        .exchange(q.code.ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing code"))?, pkce, nonce)
        .await
        .map_err(|e| err(StatusCode::UNAUTHORIZED, format!("{e:#}")))?;
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (id, sub, username, email, groups, refresh_token) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (sub) DO UPDATE SET username = $3, email = $4, groups = $5, refresh_token = $6, updated_at = now()
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(&id.sub)
    .bind(&id.username)
    .bind(&id.email)
    .bind(&id.groups)
    .bind(id.refresh_token.as_ref().map(|r| app.keys.kek.seal(r.as_bytes())))
    .fetch_one(&app.db)
    .await?;
    app.audit("user.login", "info", Some(&id.username), json!({"groups": id.groups, "cli": cli_port.is_some()})).await;
    app.notify_change().await;

    if let Some(port) = cli_port {
        let code = random_token("");
        sqlx::query("INSERT INTO login_codes (code_hash, user_id, expires_at) VALUES ($1,$2, now() + interval '5 minutes')")
            .bind(sha256_hex(code.as_bytes()))
            .bind(user_id)
            .execute(&app.db)
            .await?;
        let st = cli_state.unwrap_or_default();
        return Ok(Redirect::to(&format!("http://127.0.0.1:{port}/callback?code={code}&state={st}")).into_response());
    }
    let token = issue_token(&app, user_id, None, 8 * 3600).await?;
    let cookie = format!("orbital_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800");
    Ok(([("set-cookie", cookie)], Redirect::to("/")).into_response())
}

#[derive(Deserialize)]
pub struct ExchangeBody {
    code: Option<String>,
    password: Option<String>,
    device_pubkey: String,
    device_name: String,
}

#[derive(Serialize)]
pub struct LoginResult {
    token: String,
    username: String,
    ssh_cert: String,
    known_hosts: String,
    expires_in: u64,
}

const LOGIN_TTL: u64 = 8 * 3600;

/// CLI login completion: one-time code (OIDC) or break-glass password -> device-bound token + SSH cert.
pub async fn exchange(State(app): State<AppRef>, Json(b): Json<ExchangeBody>) -> ApiResult<Json<LoginResult>> {
    let user_id: Uuid = match (b.code, b.password) {
        (Some(code), _) => sqlx::query_scalar("DELETE FROM login_codes WHERE code_hash = $1 AND expires_at > now() RETURNING user_id")
            .bind(sha256_hex(code.as_bytes()))
            .fetch_optional(&app.db)
            .await?
            .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid or expired login code"))?,
        (None, Some(pw)) => {
            let want = app.cfg.admin_password.as_deref().ok_or_else(|| err(StatusCode::FORBIDDEN, "break-glass admin disabled"))?;
            // compare digests so timing doesn't leak length/prefix
            let ok = sha256_hex(pw.as_bytes()).bytes().zip(sha256_hex(want.as_bytes()).bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
            if !ok {
                app.audit("auth.breakglass_failed", "high", Some("admin"), json!({})).await;
                return Err(err(StatusCode::UNAUTHORIZED, "bad password"));
            }
            app.audit("auth.breakglass", "high", Some("admin"), json!({})).await;
            sqlx::query_scalar(
                "INSERT INTO users (id, username, groups) VALUES ($1, 'admin', '{orbital-local-admin}')
                 ON CONFLICT (username) DO UPDATE SET groups = '{orbital-local-admin}', disabled = false RETURNING id",
            )
            .bind(Uuid::new_v4())
            .fetch_one(&app.db)
            .await?
        }
        _ => return Err(err(StatusCode::BAD_REQUEST, "code or password required")),
    };
    let user = load_user(&app, user_id, None).await?.ok_or_else(|| err(StatusCode::UNAUTHORIZED, "user disabled"))?;

    let key = PublicKey::from_openssh(&b.device_pubkey).map_err(|e| err(StatusCode::BAD_REQUEST, format!("device key: {e}")))?;
    let fp = key.fingerprint(HashAlg::Sha256).to_string();
    let (device_id, revoked): (Uuid, bool) = sqlx::query_as(
        "INSERT INTO devices (id, user_id, name, public_key, fingerprint) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (user_id, fingerprint) DO UPDATE SET name = $3, last_used = now()
         RETURNING id, revoked_at IS NOT NULL",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(&b.device_name)
    .bind(key.to_openssh().map_err(anyhow::Error::from)?)
    .bind(&fp)
    .fetch_one(&app.db)
    .await?;
    if revoked {
        return Err(err(StatusCode::FORBIDDEN, "this device was revoked; generate a new device key"));
    }
    let token = issue_token(&app, user_id, Some(device_id), LOGIN_TTL as i64).await?;
    let cert = mint_ssh_cert(&app.keys.ssh_user_ca, &key, &format!("{user_id}/{device_id}"), &user.username, LOGIN_TTL)?;
    app.audit("device.login", "info", Some(&user.username), json!({"device": device_id, "fingerprint": fp, "name": b.device_name})).await;
    Ok(Json(LoginResult {
        token,
        username: user.username,
        ssh_cert: cert.to_openssh().map_err(anyhow::Error::from)?,
        known_hosts: format!("orbital {}", app.keys.ssh_host_key.public_key().to_openssh().map_err(anyhow::Error::from)?),
        expires_in: LOGIN_TTL,
    }))
}

pub async fn me(user: User) -> Json<User> {
    Json(user)
}
