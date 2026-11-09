//! Agent-facing mTLS listener: enrollment, handshake deny list, yamux tunnel registry, control stream.

use crate::{replica_urls, App, AppRef};
use anyhow::{anyhow, bail, Context, Result};
use orbital_proto::{mux, read_msg, sha256_hex, sign_grant, write_msg, Control, GrantClaims, Hello, HelloReply, StreamOpen, StreamReply};
use serde_json::json;
use std::{collections::BTreeMap, sync::atomic::{AtomicU64, Ordering}, time::Duration};
use tokio::{net::TcpListener, time::timeout};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct Tunnel {
    pub mux: mux::Mux,
    pub conn_id: u64,
    pub cancel: CancellationToken,
}

static CONN_ID: AtomicU64 = AtomicU64::new(1);

pub async fn serve(app: AppRef) {
    if let Err(e) = serve_inner(app).await {
        tracing::error!("agent listener died: {e:#}");
        std::process::exit(1);
    }
}

async fn serve_inner(app: AppRef) -> Result<()> {
    let acceptor = TlsAcceptor::from(crate::keys::agent_tls(&app.keys, &app.cfg.tls_sans)?);
    let listener = TcpListener::bind(&app.cfg.agent_listen).await?;
    tracing::info!("agent tunnel listening on {}", app.cfg.agent_listen);
    loop {
        let (sock, peer) = listener.accept().await?;
        let (app, acceptor) = (app.clone(), acceptor.clone());
        tokio::spawn(async move {
            if let Err(e) = handle(app, acceptor, sock).await {
                tracing::info!("agent connection from {peer}: {e:#}");
            }
        });
    }
}

/// (node id from CN, hex serial)
fn cert_identity(der: &[u8]) -> Result<(Uuid, String)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| anyhow!("bad client cert: {e}"))?;
    let cn = cert.subject().iter_common_name().next().context("no CN")?.as_str().map_err(|e| anyhow!("{e}"))?;
    Ok((cn.parse()?, hex::encode(cert.raw_serial())))
}

async fn handle(app: AppRef, acceptor: TlsAcceptor, sock: tokio::net::TcpStream) -> Result<()> {
    let mut tls = timeout(Duration::from_secs(10), acceptor.accept(sock)).await??;
    let peer = tls.get_ref().1.peer_certificates().and_then(|c| c.first()).map(|c| c.to_vec());
    let hello: Hello = timeout(Duration::from_secs(10), read_msg(&mut tls)).await??;
    match hello {
        Hello::Enroll { join_token, csr_pem, name, labels, services } => {
            let reply = match enroll(&app, &join_token, &csr_pem, &name, &labels, &services).await {
                Ok(r) => r,
                Err(e) => {
                    app.audit("node.enroll_failed", "warn", None, json!({"name": name, "error": format!("{e:#}")})).await;
                    HelloReply::Error { msg: format!("{e:#}") }
                }
            };
            write_msg(&mut tls, &reply).await
        }
        Hello::Connect { version, services } => {
            let der = peer.context("client certificate required")?;
            let (node_id, serial) = cert_identity(&der)?;
            let revoked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM revoked_certs WHERE serial = $1)")
                .bind(&serial)
                .fetch_one(&app.db)
                .await?;
            let known: Option<String> = sqlx::query_scalar(
                "UPDATE nodes SET last_seen = now(), version = $3, services = $4
                 WHERE id = $1 AND (cert_serial = $2 OR prev_serial = $2) RETURNING name",
            )
            .bind(node_id)
            .bind(&serial)
            .bind(&version)
            .bind(sqlx::types::Json(&services))
            .fetch_optional(&app.db)
            .await?;
            let name = match (revoked, known) {
                (false, Some(n)) => n,
                _ => {
                    app.audit("node.handshake_rejected", "warn", None, json!({"node_id": node_id, "serial": serial, "revoked": revoked})).await;
                    write_msg(&mut tls, &HelloReply::Error { msg: "certificate revoked or node removed".into() }).await?;
                    bail!("rejected node {node_id} (serial {serial})");
                }
            };
            write_msg(&mut tls, &HelloReply::Ok).await?;
            run_tunnel(app, tls, node_id, name).await
        }
    }
}

async fn enroll(
    app: &App,
    token: &str,
    csr: &str,
    name: &str,
    labels: &BTreeMap<String, String>,
    services: &BTreeMap<String, u16>,
) -> Result<HelloReply> {
    if name.is_empty() || name.len() > 63 || !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)) {
        bail!("invalid node name {name:?}");
    }
    let mut tx = app.db.begin().await?;
    let ok: Option<i32> = sqlx::query_scalar(
        "UPDATE join_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING 1",
    )
    .bind(sha256_hex(token.as_bytes()))
    .fetch_optional(&mut *tx)
    .await?;
    ok.context("join token invalid, expired or already used")?;
    let node_id = Uuid::new_v4();
    let (cert_pem, serial, not_after) = app.keys.sign_agent_csr(csr, &node_id.to_string())?;
    sqlx::query(
        "INSERT INTO nodes (id, name, labels, services, cert_serial, cert_expires_at) VALUES ($1,$2,$3,$4,$5, to_timestamp($6))",
    )
    .bind(node_id)
    .bind(name)
    .bind(sqlx::types::Json(labels))
    .bind(sqlx::types::Json(services))
    .bind(&serial)
    .bind(not_after as f64)
    .execute(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => anyhow!("a node named {name:?} already exists"),
        e => e.into(),
    })?;
    tx.commit().await?;
    app.audit("node.enrolled", "info", None, json!({"node": name, "node_id": node_id, "labels": labels, "services": services})).await;
    Ok(HelloReply::Enrolled {
        node_id: node_id.to_string(),
        cert_pem,
        ca_pem: app.keys.ca_pem.clone(),
        grant_key: hex::encode(app.keys.grant_key.verifying_key().as_bytes()),
        ssh_ca: app.keys.ssh_node_ca.public_key().to_openssh()?,
        not_after,
    })
}

async fn run_tunnel<T>(app: AppRef, io: T, node_id: Uuid, name: String) -> Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (m, mut inbound) = mux::spawn(io, mux::Mode::Server);
    let conn_id = CONN_ID.fetch_add(1, Ordering::Relaxed);
    let cancel = CancellationToken::new();
    if let Some(old) = app.tunnels.lock().await.insert(node_id, Tunnel { mux: m.clone(), conn_id, cancel: cancel.clone() }) {
        old.cancel.cancel();
    }
    tracing::info!("node {name} ({node_id}) connected");
    let res = control(&app, &mut inbound, node_id, &cancel).await;
    {
        let mut t = app.tunnels.lock().await;
        if t.get(&node_id).map(|t| t.conn_id) == Some(conn_id) {
            t.remove(&node_id);
        }
    }
    tracing::info!("node {name} disconnected: {res:?}");
    res
}

async fn control(
    app: &App,
    inbound: &mut tokio::sync::mpsc::UnboundedReceiver<mux::Stream>,
    node_id: Uuid,
    cancel: &CancellationToken,
) -> Result<()> {
    let ctrl = timeout(Duration::from_secs(10), inbound.recv()).await?.context("no control stream")?;
    let (mut r, mut w) = tokio::io::split(ctrl);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Control>>(8);
    tokio::spawn(async move {
        loop {
            let m = read_msg::<_, Control>(&mut r).await;
            let stop = m.is_err();
            if tx.send(m).await.is_err() || stop {
                break;
            }
        }
    });
    write_msg(&mut w, &Control::Replicas { urls: replica_urls(app).await }).await?;
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = cancel.cancelled() => bail!("tunnel cancelled"),
            _ = tick.tick() => write_msg(&mut w, &Control::Replicas { urls: replica_urls(app).await }).await?,
            // the agent opens no other streams; anything extra is dropped
            s = inbound.recv() => if s.is_none() { bail!("connection closed") },
            m = rx.recv() => match m.context("control closed")?? {
                Control::Heartbeat => {
                    sqlx::query("UPDATE nodes SET last_seen = now() WHERE id = $1").bind(node_id).execute(&app.db).await?;
                }
                Control::Renew { csr_pem } => {
                    let (cert_pem, serial, not_after) = app.keys.sign_agent_csr(&csr_pem, &node_id.to_string())?;
                    sqlx::query("UPDATE nodes SET prev_serial = cert_serial, cert_serial = $2, cert_expires_at = to_timestamp($3) WHERE id = $1")
                        .bind(node_id).bind(&serial).bind(not_after as f64).execute(&app.db).await?;
                    app.audit("node.cert_rotated", "info", None, json!({"node_id": node_id, "serial": serial})).await;
                    write_msg(&mut w, &Control::Renewed { cert_pem, not_after }).await?;
                }
                other => tracing::debug!("ignoring control message {other:?}"),
            },
        }
    }
}

/// Opens a data stream to `service` on a node, authorized by a freshly signed grant token.
pub async fn open_stream(app: &App, node_id: Uuid, claims: GrantClaims) -> Result<mux::Stream> {
    let m = app
        .tunnels
        .lock()
        .await
        .get(&node_id)
        .map(|t| t.mux.clone())
        .context("node is not connected to this replica")?;
    let mut s = m.open().await?;
    write_msg(&mut s, &StreamOpen { token: sign_grant(&app.keys.grant_key, &claims) }).await?;
    let r: StreamReply = timeout(Duration::from_secs(10), read_msg(&mut s)).await??;
    if !r.ok {
        bail!("agent refused stream: {}", r.error.unwrap_or_default());
    }
    Ok(s)
}
