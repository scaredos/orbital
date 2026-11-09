mod api;
mod auth;
mod keys;
mod policy;
mod rbac;
mod sftp;
mod ssh;
mod tunnel;
mod web;

use anyhow::{Context, Result};
use clap::Parser;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Parser, Clone, Debug)]
#[command(name = "orbital-orchestrator", version)]
pub struct Config {
    #[arg(long, env = "ORBITAL_DATABASE_URL")]
    pub database_url: String,
    /// Public base URL (redirects, download links), e.g. https://orbital.example.com
    #[arg(long, env = "ORBITAL_PUBLIC_URL")]
    pub public_url: String,
    #[arg(long, env = "ORBITAL_LISTEN", default_value = "0.0.0.0:8443")]
    pub listen: String,
    #[arg(long, env = "ORBITAL_AGENT_LISTEN", default_value = "0.0.0.0:8444")]
    pub agent_listen: String,
    /// host:port agents use to reach THIS replica (advertised in the replica list)
    #[arg(long, env = "ORBITAL_AGENT_URL")]
    pub agent_url: String,
    #[arg(long, env = "ORBITAL_REPLICA_ID", default_value = "orchestrator")]
    pub replica_id: String,
    /// DNS names / IPs for the self-issued certs (comma separated)
    #[arg(long, env = "ORBITAL_TLS_SANS", value_delimiter = ',', default_value = "localhost")]
    pub tls_sans: Vec<String>,
    #[arg(long, env = "ORBITAL_TLS_CERT")]
    pub tls_cert: Option<String>,
    #[arg(long, env = "ORBITAL_TLS_KEY")]
    pub tls_key: Option<String>,
    #[arg(long, env = "ORBITAL_KEK_FILE")]
    pub kek_file: Option<String>,
    #[arg(long, env = "ORBITAL_KEK", hide_env_values = true)]
    pub kek: Option<String>,
    #[arg(long, env = "ORBITAL_OIDC_ISSUER")]
    pub oidc_issuer: Option<String>,
    #[arg(long, env = "ORBITAL_OIDC_CLIENT_ID", default_value = "orbital")]
    pub oidc_client_id: String,
    #[arg(long, env = "ORBITAL_OIDC_CLIENT_SECRET", hide_env_values = true)]
    pub oidc_client_secret: Option<String>,
    #[arg(long, env = "ORBITAL_OIDC_GROUPS_CLAIM", default_value = "groups")]
    pub oidc_groups_claim: String,
    /// OIDC group bound to the built-in admin role at startup
    #[arg(long, env = "ORBITAL_ADMIN_GROUP", default_value = "orbital-admins")]
    pub admin_group: String,
    /// Break-glass local admin password (user "admin"); unset = disabled
    #[arg(long, env = "ORBITAL_ADMIN_PASSWORD", hide_env_values = true)]
    pub admin_password: Option<String>,
    #[arg(long, env = "ORBITAL_WEBHOOK_URL")]
    pub webhook_url: Option<String>,
    #[arg(long, env = "ORBITAL_WEBHOOK_SECRET", hide_env_values = true, default_value = "")]
    pub webhook_secret: String,
    #[arg(long, env = "ORBITAL_DATA_DIR", default_value = "/var/lib/orbital")]
    pub data_dir: String,
    /// Directory holding stock agent binaries named orbital-agent-<arch>
    #[arg(long, env = "ORBITAL_AGENT_DIR", default_value = "/usr/share/orbital/agents")]
    pub agent_dir: String,
    #[arg(long, env = "ORBITAL_RECHECK_SECS", default_value = "60")]
    pub recheck_secs: u64,
    #[arg(long, env = "ORBITAL_STALE_DAYS", default_value = "7")]
    pub stale_days: i64,
}

pub struct App {
    pub cfg: Config,
    pub db: PgPool,
    pub keys: keys::Keys,
    pub oidc: Option<auth::Oidc>,
    pub http: reqwest::Client,
    pub tunnels: Mutex<HashMap<Uuid, tunnel::Tunnel>>,
    pub live: Mutex<HashMap<Uuid, ssh::Live>>,
}

pub type AppRef = Arc<App>;

impl App {
    /// One audit pipeline: Postgres row + JSON line on stdout + HMAC-signed webhook.
    pub async fn audit(&self, kind: &str, severity: &str, actor: Option<&str>, data: Value) {
        let at = chrono::Utc::now();
        if let Err(e) = sqlx::query("INSERT INTO audit_events (at, kind, severity, actor, data) VALUES ($1,$2,$3,$4,$5)")
            .bind(at)
            .bind(kind)
            .bind(severity)
            .bind(actor)
            .bind(&data)
            .execute(&self.db)
            .await
        {
            tracing::error!("audit insert failed: {e}");
        }
        let event = json!({"at": at, "kind": kind, "severity": severity, "actor": actor, "data": data, "replica": self.cfg.replica_id});
        println!("{}", json!({"audit": event}));
        if let Some(url) = &self.cfg.webhook_url {
            let body = event.to_string();
            let sig = webhook_sig(&self.cfg.webhook_secret, body.as_bytes());
            let req = self
                .http
                .post(url)
                .header("content-type", "application/json")
                .header("x-orbital-signature", format!("sha256={sig}"))
                .header("x-orbital-event", kind)
                .body(body);
            tokio::spawn(async move {
                if let Err(e) = req.send().await.and_then(|r| r.error_for_status()) {
                    tracing::warn!("webhook delivery failed: {e}");
                }
            });
        }
    }

    /// Tell every replica something changed (policy, users, grants, nodes) so live sessions get re-checked.
    pub async fn notify_change(&self) {
        let _ = sqlx::query("SELECT pg_notify('orbital_changes', '')").execute(&self.db).await;
    }
}

pub fn webhook_sig(secret: &str, body: &[u8]) -> String {
    use hmac::Mac;
    let mut m = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    m.update(body);
    hex::encode(m.finalize().into_bytes())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,russh=warn".into()))
        .with_writer(std::io::stderr)
        .init();
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();
    let mut cfg = Config::parse();
    // compose passes unset vars as "": treat empty as absent (an empty break-glass password must never work)
    for v in [&mut cfg.admin_password, &mut cfg.webhook_url, &mut cfg.oidc_issuer, &mut cfg.oidc_client_secret, &mut cfg.tls_cert, &mut cfg.tls_key, &mut cfg.kek_file, &mut cfg.kek] {
        if v.as_deref() == Some("") {
            *v = None;
        }
    }

    let db = connect_db(&cfg.database_url).await?;
    sqlx::migrate!("./migrations").run(&db).await.context("migrations")?;
    sqlx::query("INSERT INTO role_bindings (grp, role) VALUES ($1, 'admin'), ('orbital-local-admin', 'admin') ON CONFLICT DO NOTHING")
        .bind(&cfg.admin_group)
        .execute(&db)
        .await?;

    let kek = keys::Kek::load(cfg.kek_file.as_deref(), cfg.kek.as_deref())?;
    let keys = keys::Keys::load(&db, kek).await?;
    std::fs::create_dir_all(format!("{}/recordings", cfg.data_dir))?;
    // public half only: lets admins hand ca.pem to CLIs when the portal cert is self-issued
    std::fs::write(format!("{}/ca.pem", cfg.data_dir), &keys.ca_pem)?;

    let oidc = match &cfg.oidc_issuer {
        Some(iss) => Some(auth::Oidc::discover(iss, &cfg).await?),
        None => {
            tracing::warn!("ORBITAL_OIDC_ISSUER not set: only break-glass admin login is available");
            None
        }
    };

    let app = Arc::new(App {
        http: reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?,
        cfg: cfg.clone(),
        db,
        keys,
        oidc,
        tunnels: Mutex::default(),
        live: Mutex::default(),
    });

    tokio::spawn(tunnel::serve(app.clone()));
    tokio::spawn(heartbeat_replica(app.clone()));
    tokio::spawn(ssh::recheck_loop(app.clone()));
    api::serve(app).await
}

async fn connect_db(url: &str) -> Result<PgPool> {
    let mut last = None;
    for _ in 0..30 {
        match sqlx::postgres::PgPoolOptions::new().max_connections(20).connect(url).await {
            Ok(p) => return Ok(p),
            Err(e) => {
                tracing::info!("waiting for postgres: {e}");
                last = Some(e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Err(last.unwrap().into())
}

async fn heartbeat_replica(app: AppRef) {
    loop {
        let _ = sqlx::query(
            "INSERT INTO replicas (id, agent_url, last_seen) VALUES ($1, $2, now())
             ON CONFLICT (id) DO UPDATE SET agent_url = $2, last_seen = now()",
        )
        .bind(&app.cfg.replica_id)
        .bind(&app.cfg.agent_url)
        .execute(&app.db)
        .await;
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
}

pub async fn replica_urls(app: &App) -> Vec<String> {
    let mut urls: Vec<String> =
        sqlx::query_scalar("SELECT agent_url FROM replicas WHERE last_seen > now() - interval '2 minutes' ORDER BY id")
            .fetch_all(&app.db)
            .await
            .unwrap_or_default();
    if !urls.contains(&app.cfg.agent_url) {
        urls.push(app.cfg.agent_url.clone());
    }
    urls
}

#[cfg(test)]
mod tests {
    #[test]
    fn webhook_signature_is_hmac_sha256() {
        // RFC 4231 test case 2
        assert_eq!(
            super::webhook_sig("Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
