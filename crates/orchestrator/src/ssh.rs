//! SSH relay: terminates the user's SSH (Orbital user cert, device-bound), opens upstream to the node's
//! sshd through the agent tunnel with a 5-minute Orbital node-CA cert, relays + records (asciicast v2),
//! audits SFTP file ops, and kills live sessions whose access is revoked.

use crate::{auth::User, keys::mint_ssh_cert, policy, sftp::SftpAudit, tunnel, AppRef};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use orbital_proto::{now, sha256_hex, GrantClaims};
use russh::{
    client,
    keys::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKeyOrCertificate},
    server::{self, Auth, Msg, Session},
    Channel, ChannelId, ChannelMsg, Disconnect, MethodKind, MethodSet,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(sqlx::FromRow, Clone, Debug, serde::Serialize)]
pub struct GrantRow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub node_id: Uuid,
    pub node_name: String,
    pub service: String,
    pub login: String,
    pub reason: String,
    pub status: String,
    pub emergency: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

pub const GRANT_SELECT: &str = "SELECT g.id, g.user_id, g.node_id, n.name AS node_name, g.service, g.login, g.reason,
    g.status, g.emergency, g.expires_at FROM grants g JOIN nodes n ON n.id = g.node_id";

/// A live session registered on this replica.
pub struct Live {
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
    pub cancel: CancellationToken,
    pub kill_reason: Arc<StdMutex<Option<String>>>,
}

// ---------------------------------------------------------------- recording

pub struct Recorder {
    path: String,
    file: Option<std::io::BufWriter<std::fs::File>>,
    start: Instant,
    size: (u32, u32),
}

impl Recorder {
    fn new(path: String) -> Self {
        Recorder { path, file: None, start: Instant::now(), size: (80, 24) }
    }
    fn begin(&mut self, command: Option<&str>, title: &str) {
        if self.file.is_some() {
            return;
        }
        match std::fs::File::create(&self.path) {
            Ok(f) => {
                let mut f = std::io::BufWriter::new(f);
                let header = json!({"version": 2, "width": self.size.0, "height": self.size.1,
                    "timestamp": now(), "title": title, "command": command});
                let _ = writeln!(f, "{header}");
                self.start = Instant::now();
                self.file = Some(f);
            }
            Err(e) => tracing::error!("cannot create recording {}: {e}", self.path),
        }
    }
    fn event(&mut self, kind: &str, data: &str) {
        let t = self.start.elapsed().as_secs_f64();
        if let Some(f) = &mut self.file {
            let _ = writeln!(f, "{}", json!([t, kind, data]));
        }
    }
    fn output(&mut self, data: &[u8]) {
        // ponytail: lossy per chunk; a multibyte char split across chunks renders as U+FFFD
        self.event("o", &String::from_utf8_lossy(data));
    }
    fn resize(&mut self, w: u32, h: u32) {
        self.size = (w, h);
        self.event("r", &format!("{w}x{h}"));
    }
    fn finish(&mut self) -> Option<(String, String)> {
        let mut f = self.file.take()?;
        f.flush().ok()?;
        drop(f);
        let bytes = std::fs::read(&self.path).ok()?;
        Some((self.path.clone(), sha256_hex(&bytes)))
    }
}

// ---------------------------------------------------------------- handler

struct Ctx {
    app: AppRef,
    grant: GrantRow,
    user: User,
    session_id: Uuid,
    rec: StdMutex<Recorder>,
    cancel: CancellationToken,
    kill_reason: Arc<StdMutex<Option<String>>>,
    device_id: StdMutex<Option<Uuid>>,
    upstream: tokio::sync::Mutex<Option<Arc<client::Handle<Up>>>>,
}

struct Mitm(Arc<Ctx>);

struct Up;
impl client::Handler for Up {
    type Error = russh::Error;
    // The upstream hop is localhost sshd behind the agent's authenticated mTLS tunnel.
    // ponytail: no host-key pinning on that hop; pin sshd host keys reported by the agent if needed.
    async fn check_server_key(&mut self, _k: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

impl Mitm {
    async fn check_cert(&self, login: &str, cert: &Certificate) -> Result<Uuid> {
        let c = &self.0;
        let ca_fp = c.app.keys.ssh_user_ca.public_key().fingerprint(HashAlg::Sha256);
        cert.validate([&ca_fp]).context("certificate not signed by the Orbital user CA or expired")?;
        if cert.cert_type() != russh::keys::ssh_key::certificate::CertType::User {
            bail!("not a user certificate");
        }
        if !cert.valid_principals().iter().any(|p| p == &c.user.username) {
            bail!("certificate principal does not match {}", c.user.username);
        }
        let (uid, did) = cert.key_id().split_once('/').context("bad key id")?;
        let (uid, did): (Uuid, Uuid) = (uid.parse()?, did.parse()?);
        if uid != c.user.id {
            bail!("certificate belongs to another user");
        }
        let active: Option<bool> = sqlx::query_scalar("SELECT revoked_at IS NULL FROM devices WHERE id = $1 AND user_id = $2")
            .bind(did)
            .bind(uid)
            .fetch_optional(&c.app.db)
            .await?;
        if active != Some(true) {
            bail!("device revoked");
        }
        if login != c.grant.login {
            bail!("login {login:?} is not covered by this grant (granted {:?})", c.grant.login);
        }
        Ok(did)
    }

    async fn start(&self, handle: server::Handle) -> Result<()> {
        let c = &self.0;
        let g = &c.grant;
        let claims = GrantClaims {
            grant_id: g.id.to_string(),
            node_id: g.node_id.to_string(),
            service: "ssh".into(),
            user: c.user.username.clone(),
            exp: now() + 60,
        };
        let stream = tunnel::open_stream(&c.app, g.node_id, claims).await?;
        let mut up = client::connect_stream(Arc::new(client::Config::default()), stream, Up).await?;
        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
        let cert = mint_ssh_cert(
            &c.app.keys.ssh_node_ca,
            key.public_key(),
            &format!("orbital:{}:{}", c.session_id, c.user.username),
            &g.login,
            300,
        )?;
        if !up.authenticate_openssh_cert(g.login.clone(), Arc::new(key), cert).await?.success() {
            bail!("node sshd rejected the Orbital certificate (is TrustedUserCAKeys set and does {:?} exist?)", g.login);
        }
        *c.upstream.lock().await = Some(Arc::new(up));

        let path = format!("{}/recordings/{}.cast", c.app.cfg.data_dir, c.session_id);
        *c.rec.lock().unwrap() = Recorder::new(path);
        sqlx::query(
            "INSERT INTO sessions (id, grant_id, user_id, node_id, node_name, username, login, protocol, replica, emergency)
             VALUES ($1,$2,$3,$4,$5,$6,$7,'ssh',$8,$9)",
        )
        .bind(c.session_id)
        .bind(g.id)
        .bind(c.user.id)
        .bind(g.node_id)
        .bind(&g.node_name)
        .bind(&c.user.username)
        .bind(&g.login)
        .bind(&c.app.cfg.replica_id)
        .bind(g.emergency)
        .execute(&c.app.db)
        .await?;
        c.app.live.lock().await.insert(
            c.session_id,
            Live { user_id: c.user.id, device_id: *c.device_id.lock().unwrap(), cancel: c.cancel.clone(), kill_reason: c.kill_reason.clone() },
        );
        let sev = if g.emergency { "high" } else { "info" };
        c.app
            .audit("session.started", sev, Some(&c.user.username),
                json!({"session": c.session_id, "grant": g.id, "node": g.node_name, "login": g.login, "reason": g.reason, "emergency": g.emergency}))
            .await;

        let (cancel, reason) = (c.cancel.clone(), c.kill_reason.clone());
        tokio::spawn(async move {
            cancel.cancelled().await;
            tokio::time::sleep(Duration::from_millis(300)).await; // let relays print the banner
            let msg = reason.lock().unwrap().clone().unwrap_or_else(|| "session terminated".into());
            let _ = handle.disconnect(Disconnect::ByApplication, msg, "en".into()).await;
        });
        Ok(())
    }
}

impl server::Handler for Mitm {
    type Error = anyhow::Error;

    async fn auth_openssh_certificate(&mut self, login: &str, cert: &Certificate) -> Result<Auth> {
        match self.check_cert(login, cert).await {
            Ok(did) => {
                *self.0.device_id.lock().unwrap() = Some(did);
                Ok(Auth::Accept)
            }
            Err(e) => {
                let c = &self.0;
                c.app
                    .audit("ssh.auth_denied", "warn", Some(&c.user.username), json!({"grant": c.grant.id, "login": login, "error": format!("{e:#}")}))
                    .await;
                Ok(Auth::reject())
            }
        }
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<()> {
        if let Err(e) = self.start(session.handle()).await {
            let c = &self.0;
            c.app.audit("session.upstream_failed", "warn", Some(&c.user.username), json!({"grant": c.grant.id, "error": format!("{e:#}")})).await;
            return Err(e);
        }
        Ok(())
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, reply: server::ChannelOpenHandle, _s: &mut Session) -> Result<()> {
        let up = self.0.upstream.lock().await.clone();
        match up {
            Some(up) => {
                reply.accept().await;
                let ctx = self.0.clone();
                tokio::spawn(async move {
                    if let Err(e) = relay(ctx, up, channel).await {
                        tracing::info!("relay ended: {e:#}");
                    }
                });
            }
            None => reply.reject(russh::ChannelOpenFailure::ConnectFailed).await,
        }
        Ok(())
    }

    async fn pty_request(&mut self, ch: ChannelId, _: &str, _: u32, _: u32, _: u32, _: u32, _: &[(russh::Pty, u32)], s: &mut Session) -> Result<()> {
        Ok(s.channel_success(ch)?)
    }
    async fn shell_request(&mut self, ch: ChannelId, s: &mut Session) -> Result<()> {
        Ok(s.channel_success(ch)?)
    }
    async fn exec_request(&mut self, ch: ChannelId, _: &[u8], s: &mut Session) -> Result<()> {
        Ok(s.channel_success(ch)?)
    }
    async fn env_request(&mut self, ch: ChannelId, _: &str, _: &str, s: &mut Session) -> Result<()> {
        Ok(s.channel_success(ch)?)
    }
    async fn subsystem_request(&mut self, ch: ChannelId, name: &str, s: &mut Session) -> Result<()> {
        if name == "sftp" {
            s.channel_success(ch)?;
        } else {
            s.channel_failure(ch)?;
        }
        Ok(())
    }
}

async fn record_file_ops(ctx: &Ctx, audit: &mut SftpAudit) {
    for op in audit.drain() {
        let _ = sqlx::query("INSERT INTO file_ops (session_id, op, path, path2, bytes) VALUES ($1,$2,$3,$4,$5)")
            .bind(ctx.session_id)
            .bind(op.op)
            .bind(&op.path)
            .bind(&op.path2)
            .bind(op.bytes as i64)
            .execute(&ctx.app.db)
            .await;
        ctx.app
            .audit(&format!("file.{}", op.op), "info", Some(&ctx.user.username),
                json!({"session": ctx.session_id, "node": ctx.grant.node_name, "path": op.path, "path2": op.path2, "bytes": op.bytes}))
            .await;
    }
}

async fn relay(ctx: Arc<Ctx>, up: Arc<client::Handle<Up>>, mut down: Channel<Msg>) -> Result<()> {
    let mut upc = up.channel_open_session().await?;
    let mut sftp: Option<SftpAudit> = None;
    let title = format!("{}@{} ({})", ctx.grant.login, ctx.grant.node_name, ctx.user.username);
    loop {
        tokio::select! {
            _ = ctx.cancel.cancelled() => {
                let why = ctx.kill_reason.lock().unwrap().clone().unwrap_or_default();
                let _ = down.extended_data_bytes(1, format!("\r\n[orbital] session terminated: {why}\r\n").into_bytes()).await;
                let _ = down.close().await;
                let _ = upc.close().await;
                break;
            }
            m = down.wait() => match m {
                None | Some(ChannelMsg::Close) => { let _ = upc.close().await; break }
                Some(ChannelMsg::Data { data }) => {
                    if let Some(a) = &mut sftp { a.client(&data); record_file_ops(&ctx, a).await; }
                    upc.data_bytes(data).await?;
                }
                Some(ChannelMsg::Eof) => upc.eof().await?,
                Some(ChannelMsg::RequestPty { term, col_width, row_height, pix_width, pix_height, terminal_modes, .. }) => {
                    ctx.rec.lock().unwrap().size = (col_width, row_height);
                    upc.request_pty(false, &term, col_width, row_height, pix_width, pix_height, &terminal_modes).await?;
                }
                Some(ChannelMsg::RequestShell { .. }) => {
                    ctx.rec.lock().unwrap().begin(None, &title);
                    upc.request_shell(false).await?;
                }
                Some(ChannelMsg::Exec { command, .. }) => {
                    ctx.rec.lock().unwrap().begin(Some(&String::from_utf8_lossy(&command)), &title);
                    upc.exec(false, command).await?;
                }
                Some(ChannelMsg::RequestSubsystem { name, .. }) => {
                    if name != "sftp" { continue }
                    sftp = Some(SftpAudit::default());
                    upc.request_subsystem(false, name).await?;
                }
                Some(ChannelMsg::SetEnv { variable_name, variable_value, .. }) => upc.set_env(false, variable_name, variable_value).await?,
                Some(ChannelMsg::WindowChange { col_width, row_height, pix_width, pix_height }) => {
                    ctx.rec.lock().unwrap().resize(col_width, row_height);
                    upc.window_change(col_width, row_height, pix_width, pix_height).await?;
                }
                Some(ChannelMsg::Signal { signal }) => upc.signal(signal).await?,
                Some(_) => {}
            },
            m = upc.wait() => match m {
                None | Some(ChannelMsg::Close) => { let _ = down.close().await; break }
                Some(ChannelMsg::Data { data }) => {
                    match &mut sftp {
                        Some(a) => { a.server(&data); record_file_ops(&ctx, a).await; }
                        None => ctx.rec.lock().unwrap().output(&data),
                    }
                    down.data_bytes(data).await?;
                }
                Some(ChannelMsg::ExtendedData { data, ext }) => {
                    ctx.rec.lock().unwrap().output(&data);
                    down.extended_data_bytes(ext, data).await?;
                }
                Some(ChannelMsg::Eof) => down.eof().await?,
                Some(ChannelMsg::ExitStatus { exit_status }) => down.exit_status(exit_status).await?,
                Some(ChannelMsg::ExitSignal { .. }) => down.exit_status(255).await?,
                Some(_) => {}
            },
        }
    }
    Ok(())
}

pub async fn serve_connection<T>(app: AppRef, io: T, grant: GrantRow, user: User)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let cfg = Arc::new(server::Config {
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        keys: vec![app.keys.ssh_host_key.clone()],
        auth_rejection_time: Duration::from_millis(500),
        auth_rejection_time_initial: Some(Duration::ZERO),
        inactivity_timeout: Some(Duration::from_secs(3600)),
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let ctx = Arc::new(Ctx {
        app: app.clone(),
        grant,
        user,
        session_id: Uuid::new_v4(),
        rec: StdMutex::new(Recorder::new(String::new())),
        cancel: CancellationToken::new(),
        kill_reason: Arc::default(),
        device_id: StdMutex::default(),
        upstream: Default::default(),
    });
    let res = match server::run_stream(cfg, io, Mitm(ctx.clone())).await {
        Ok(running) => running.await,
        Err(e) => Err(e),
    };
    // finalize
    let started = app.live.lock().await.remove(&ctx.session_id).is_some();
    if let Some(up) = ctx.upstream.lock().await.take() {
        let _ = up.disconnect(Disconnect::ByApplication, "", "en").await;
    }
    if !started {
        return;
    }
    let killed = ctx.kill_reason.lock().unwrap().clone();
    let reason = killed.clone().unwrap_or_else(|| match &res {
        Ok(()) => "closed".into(),
        Err(e) => format!("{e:#}"),
    });
    let rec = ctx.rec.lock().unwrap().finish();
    let _ = sqlx::query("UPDATE sessions SET ended_at = now(), end_reason = $2, recording_path = $3, recording_sha256 = $4 WHERE id = $1")
        .bind(ctx.session_id)
        .bind(&reason)
        .bind(rec.as_ref().map(|r| &r.0))
        .bind(rec.as_ref().map(|r| &r.1))
        .execute(&app.db)
        .await;
    app.audit("session.ended", "info", Some(&ctx.user.username),
        json!({"session": ctx.session_id, "node": ctx.grant.node_name, "reason": reason, "recording_sha256": rec.map(|r| r.1)}))
        .await;
}

// ---------------------------------------------------------------- live revocation

pub async fn recheck_loop(app: AppRef) {
    let mut listener = match sqlx::postgres::PgListener::connect_with(&app.db).await {
        Ok(mut l) => match l.listen("orbital_changes").await {
            Ok(()) => Some(l),
            Err(_) => None,
        },
        Err(_) => None,
    };
    let period = Duration::from_secs(app.cfg.recheck_secs);
    let mut next_refresh = Instant::now() + period;
    loop {
        let timer = tokio::time::sleep_until(next_refresh.into());
        let from_idp = match &mut listener {
            Some(l) => tokio::select! { _ = timer => true, _ = l.recv() => false },
            None => {
                timer.await;
                true
            }
        };
        if from_idp {
            next_refresh = Instant::now() + period;
        }
        if let Err(e) = recheck(&app, from_idp).await {
            tracing::warn!("recheck failed: {e:#}");
        }
    }
}

async fn recheck(app: &AppRef, refresh_idp: bool) -> Result<()> {
    // drop tunnels of removed nodes
    let tunnel_ids: Vec<Uuid> = app.tunnels.lock().await.keys().copied().collect();
    if !tunnel_ids.is_empty() {
        let alive: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM nodes WHERE id = ANY($1)").bind(&tunnel_ids).fetch_all(&app.db).await?;
        for (id, t) in app.tunnels.lock().await.iter() {
            if !alive.contains(id) {
                t.cancel.cancel();
            }
        }
    }

    let live: Vec<(Uuid, Uuid, Option<Uuid>)> = app.live.lock().await.iter().map(|(s, l)| (*s, l.user_id, l.device_id)).collect();
    if live.is_empty() {
        return Ok(());
    }
    if refresh_idp {
        let mut users: Vec<Uuid> = live.iter().map(|l| l.1).collect();
        users.sort();
        users.dedup();
        for u in users {
            if let Err(e) = crate::auth::refresh_user(app, u).await {
                tracing::warn!("IdP refresh for {u} failed (keeping sessions): {e:#}");
            }
        }
    }
    let rules = crate::api::load_rules(app).await?;
    for (sid, _, device) in live {
        if let Some(reason) = check_session(app, &rules, sid, device).await? {
            kill(app, sid, &reason).await;
        }
    }
    Ok(())
}

type SessionCheckRow = (String, Option<DateTime<Utc>>, String, String, bool, String, Vec<String>, bool, sqlx::types::Json<BTreeMap<String, String>>, Option<String>, Option<DateTime<Utc>>);

async fn check_session(app: &AppRef, rules: &[policy::Rule], sid: Uuid, device: Option<Uuid>) -> Result<Option<String>> {
    let row: Option<SessionCheckRow> = sqlx::query_as(
        "SELECT g.status, g.expires_at, g.service, g.login, g.emergency, u.username, u.groups, u.disabled, n.labels,
                s.kill_requested, d.revoked_at
         FROM sessions s JOIN grants g ON g.id = s.grant_id JOIN users u ON u.id = g.user_id JOIN nodes n ON n.id = g.node_id
         LEFT JOIN devices d ON d.id = $2
         WHERE s.id = $1",
    )
    .bind(sid)
    .bind(device)
    .fetch_optional(&app.db)
    .await?;
    let Some((status, expires, service, login, emergency, username, groups, disabled, labels, kill_by, dev_revoked)) = row else {
        return Ok(Some("grant, node or user was removed".into()));
    };
    if let Some(by) = kill_by {
        return Ok(Some(format!("killed by {by}")));
    }
    if status != "approved" {
        return Ok(Some(format!("grant {status}")));
    }
    if expires.map_or(true, |e| e < Utc::now()) {
        return Ok(Some("grant expired".into()));
    }
    if disabled {
        return Ok(Some("user disabled".into()));
    }
    if dev_revoked.is_some() {
        return Ok(Some("device revoked".into()));
    }
    let req = policy::Request { username: &username, groups: &groups, node_labels: &labels, service: &service, login: &login, emergency };
    if let policy::Decision::Deny(why) = policy::evaluate(rules, &req) {
        return Ok(Some(format!("access revoked: {why}")));
    }
    Ok(None)
}

pub async fn kill(app: &AppRef, sid: Uuid, reason: &str) {
    let user = {
        let live = app.live.lock().await;
        let Some(l) = live.get(&sid) else { return };
        if l.cancel.is_cancelled() {
            return;
        }
        *l.kill_reason.lock().unwrap() = Some(reason.to_string());
        l.cancel.cancel();
        l.user_id
    };
    app.audit("session.killed", "high", None, json!({"session": sid, "user_id": user, "reason": reason})).await;
}
