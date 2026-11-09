//! Installer: trailer -> prompts -> enrollment (CA fingerprint pin) -> files, user, systemd unit, sshd CA.

use crate::{new_csr, tls_connect, write_atomic, AgentConfig};
use anyhow::{bail, Context, Result};
use clap::Args;
use dialoguer::{Confirm, Input, MultiSelect};
use orbital_proto::{read_msg, read_trailer, sha256_hex, strip_trailer, write_msg, AgentTrailer, Hello, HelloReply};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

const BIN: &str = "/opt/orbital/orbital-agent";
const UNIT: &str = "/etc/systemd/system/orbital-agent.service";
const SSH_CA: &str = "/etc/ssh/orbital_user_ca.pub";
const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const MARK: &str = "# added by orbital-agent";

#[derive(Args)]
pub struct InstallArgs {
    /// Accept defaults, never prompt
    #[arg(short, long)]
    yes: bool,
    #[arg(long)]
    name: Option<String>,
    /// Node label, k=v (repeatable)
    #[arg(long = "label")]
    labels: Vec<String>,
    /// Service to expose, name=port (repeatable), e.g. ssh=22
    #[arg(long = "expose")]
    expose: Vec<String>,
    /// Don't install the systemd unit
    #[arg(long)]
    no_service: bool,
    /// Don't add the Orbital SSH CA to sshd
    #[arg(long)]
    no_sshd: bool,
    #[arg(long, default_value = "/etc/orbital")]
    config_dir: PathBuf,
    #[arg(long, default_value = "/var/lib/orbital")]
    state_dir: PathBuf,
}

fn kv(s: &str) -> Result<(String, String)> {
    let (k, v) = s.split_once('=').with_context(|| format!("expected k=v, got {s:?}"))?;
    Ok((k.trim().to_string(), v.trim().to_string()))
}

/// Listening TCP ports from /proc/net/tcp{,6}.
fn listening_ports() -> Vec<u16> {
    let mut ports: Vec<u16> = ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .flat_map(|s| s.lines().skip(1).map(str::to_string).collect::<Vec<_>>())
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.get(3) == Some(&"0A")).then(|| u16::from_str_radix(f.get(1)?.rsplit(':').next()?, 16).ok()).flatten()
        })
        .collect();
    ports.sort();
    ports.dedup();
    ports
}

fn default_service_name(port: u16) -> String {
    match port {
        22 => "ssh".into(),
        80 => "http".into(),
        443 => "https".into(),
        3389 => "rdp".into(),
        5900 => "vnc".into(),
        p => format!("port-{p}"),
    }
}

/// Accepts the orchestrator only if its chain contains the CA whose SHA-256 is in our trailer.
#[derive(Debug)]
struct PinnedCa {
    fingerprint: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCa {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let ca = intermediates
            .iter()
            .find(|c| sha256_hex(c) == self.fingerprint)
            .ok_or_else(|| rustls::Error::General("orchestrator CA does not match the pinned fingerprint".into()))?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone().into_owned())?;
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
            .build()
            .map_err(|e| rustls::Error::General(e.to_string()))?
            .verify_server_cert(end_entity, &[], server_name, ocsp, now)
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.provider.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let st = Command::new(cmd).args(args).status().with_context(|| format!("running {cmd}"))?;
    if !st.success() {
        bail!("{cmd} {args:?} failed: {st}");
    }
    Ok(())
}

fn is_root() -> bool {
    Command::new("id").arg("-u").output().map(|o| o.stdout.starts_with(b"0")).unwrap_or(false)
}

fn has_systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

pub async fn install(a: InstallArgs) -> Result<()> {
    let exe = std::env::current_exe()?;
    let data = std::fs::read(&exe)?;
    let trailer: AgentTrailer = serde_json::from_slice(
        read_trailer(&data).context("this binary carries no enrollment data; download it from your orchestrator's portal")?,
    )?;
    if cfg!(unix) && !is_root() {
        bail!("install must run as root (it creates the orbital user, systemd unit and sshd config)");
    }
    let interactive = !a.yes;

    let host = std::fs::read_to_string("/etc/hostname").map(|h| h.trim().to_string()).unwrap_or_else(|_| "node".into());
    let name = match a.name {
        Some(n) => n,
        None if interactive => Input::new().with_prompt("Node name").default(host).interact_text()?,
        None => host,
    };
    let mut labels: BTreeMap<String, String> = a.labels.iter().map(|l| kv(l)).collect::<Result<_>>()?;
    if labels.is_empty() && interactive {
        let s: String = Input::new().with_prompt("Labels (k=v, comma separated)").allow_empty(true).interact_text()?;
        for l in s.split(',').filter(|l| !l.trim().is_empty()) {
            let (k, v) = kv(l)?;
            labels.insert(k, v);
        }
    }
    let mut services = BTreeMap::new();
    for e in &a.expose {
        let (n, p) = kv(e)?;
        services.insert(n, p.parse::<u16>().with_context(|| format!("bad port in {e:?}"))?);
    }
    if services.is_empty() {
        let ports = listening_ports();
        if interactive && !ports.is_empty() {
            let items: Vec<String> = ports.iter().map(|p| format!("{p} ({})", default_service_name(*p))).collect();
            let defaults: Vec<bool> = ports.iter().map(|p| *p == 22).collect();
            let picked = MultiSelect::new().with_prompt("Services to expose (space to toggle)").items(&items).defaults(&defaults).interact()?;
            for i in picked {
                let n: String = Input::new().with_prompt(format!("Name for port {}", ports[i])).default(default_service_name(ports[i])).interact_text()?;
                services.insert(n, ports[i]);
            }
        } else {
            services.insert("ssh".into(), 22);
        }
    }

    // ---- enroll
    let (key_pem, csr) = new_csr()?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCa { fingerprint: trailer.ca_fingerprint.clone(), provider }))
        .with_no_client_auth();
    let mut last = None;
    let mut reply = None;
    for url in &trailer.orch_urls {
        match tls_connect(url, tls.clone()).await {
            Ok(mut s) => {
                let hello = Hello::Enroll {
                    join_token: trailer.join_token.clone(),
                    csr_pem: csr.clone(),
                    name: name.clone(),
                    labels: labels.clone(),
                    services: services.clone(),
                };
                write_msg(&mut s, &hello).await?;
                reply = Some(read_msg::<_, HelloReply>(&mut s).await?);
                break;
            }
            Err(e) => last = Some(format!("{url}: {e:#}")),
        }
    }
    let (node_id, cert_pem, ca_pem, grant_key, ssh_ca, not_after) = match reply {
        Some(HelloReply::Enrolled { node_id, cert_pem, ca_pem, grant_key, ssh_ca, not_after }) => (node_id, cert_pem, ca_pem, grant_key, ssh_ca, not_after),
        Some(HelloReply::Error { msg }) => bail!("enrollment refused: {msg}"),
        Some(other) => bail!("unexpected reply {other:?}"),
        None => bail!("could not reach any orchestrator: {}", last.unwrap_or_default()),
    };
    println!("enrolled as {name} ({node_id})");

    // ---- files
    let dir = &a.config_dir;
    std::fs::create_dir_all(dir)?;
    std::fs::create_dir_all(&a.state_dir)?;
    write_atomic(&dir.join("agent.key"), key_pem.as_bytes())?;
    write_atomic(&dir.join("agent.crt"), cert_pem.as_bytes())?;
    write_atomic(&dir.join("ca.crt"), ca_pem.as_bytes())?;
    write_atomic(&dir.join("ssh_user_ca.pub"), ssh_ca.as_bytes())?;
    AgentConfig {
        node_id,
        name,
        orch_urls: trailer.orch_urls.clone(),
        services,
        grant_key,
        cert_not_after: not_after,
        state_dir: a.state_dir.clone(),
    }
    .save(dir)?;

    if !cfg!(unix) {
        println!("non-Linux host: config written to {}; run `orbital-agent run --config-dir {}`", dir.display(), dir.display());
        return Ok(());
    }

    // ---- unprivileged user + binary (trailer stripped: the join token is spent)
    let _ = Command::new("useradd").args(["--system", "--no-create-home", "--home-dir", "/var/lib/orbital", "--shell", "/usr/sbin/nologin", "orbital"]).status();
    std::fs::create_dir_all("/opt/orbital")?;
    write_atomic(Path::new(BIN), strip_trailer(&data))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(BIN, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    for p in [dir.as_path(), a.state_dir.as_path(), Path::new("/opt/orbital")] {
        run("chown", &["-R", "orbital:orbital", &p.to_string_lossy()])?;
    }

    // ---- sshd trusts the Orbital node CA
    let do_sshd = !a.no_sshd
        && Path::new(SSHD_CONFIG).exists()
        && (a.yes
            || Confirm::new()
                .with_prompt(format!("Add the Orbital SSH CA to {SSHD_CONFIG} (TrustedUserCAKeys) and reload sshd? A backup is kept."))
                .default(true)
                .interact()?);
    if do_sshd {
        configure_sshd(&ssh_ca)?;
    }

    // ---- service
    if a.no_service {
        println!("start it with: runuser -u orbital -- {BIN} run");
    } else if has_systemd() {
        std::fs::write(UNIT, UNIT_FILE)?;
        run("systemctl", &["daemon-reload"])?;
        run("systemctl", &["enable", "--now", "orbital-agent"])?;
        println!("orbital-agent.service enabled and started");
    } else {
        println!("no systemd detected; start it with: runuser -u orbital -- {BIN} run");
    }
    Ok(())
}

fn reload_sshd() {
    let _ = Command::new("sh")
        .args(["-c", "systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || kill -HUP $(cat /run/sshd.pid /var/run/sshd.pid 2>/dev/null | head -1) 2>/dev/null || pkill -HUP -o -x sshd"])
        .status();
}

fn configure_sshd(ssh_ca: &str) -> Result<()> {
    std::fs::write(SSH_CA, format!("{}\n", ssh_ca.trim()))?;
    let cfg = std::fs::read_to_string(SSHD_CONFIG)?;
    if cfg.contains(SSH_CA) {
        reload_sshd();
        return Ok(());
    }
    if cfg.lines().any(|l| l.trim_start().to_ascii_lowercase().starts_with("trustedusercakeys")) {
        println!("warning: {SSHD_CONFIG} already sets TrustedUserCAKeys; append {SSH_CA} to that file yourself");
        return Ok(());
    }
    let backup = format!("{SSHD_CONFIG}.orbital.bak");
    std::fs::copy(SSHD_CONFIG, &backup)?;
    // first match wins in sshd_config, and Match blocks must come last: prepend
    std::fs::write(SSHD_CONFIG, format!("TrustedUserCAKeys {SSH_CA} {MARK}\n{cfg}"))?;
    let ok = Command::new("sshd").arg("-t").status().map(|s| s.success()).unwrap_or(true);
    if !ok {
        std::fs::copy(&backup, SSHD_CONFIG)?;
        bail!("sshd -t rejected the new config; restored {backup}");
    }
    reload_sshd();
    println!("sshd now trusts the Orbital SSH CA (backup: {backup})");
    Ok(())
}

pub fn uninstall(yes: bool) -> Result<()> {
    if !yes && !Confirm::new().with_prompt("Remove orbital-agent, its config and sshd integration?").default(false).interact()? {
        return Ok(());
    }
    if Path::new(UNIT).exists() {
        let _ = Command::new("systemctl").args(["disable", "--now", "orbital-agent"]).status();
        let _ = std::fs::remove_file(UNIT);
        let _ = Command::new("systemctl").arg("daemon-reload").status();
    }
    let _ = Command::new("pkill").args(["-u", "orbital", "-f", BIN]).status();
    if let Ok(cfg) = std::fs::read_to_string(SSHD_CONFIG) {
        if cfg.contains(MARK) {
            let kept: String = cfg.lines().filter(|l| !l.contains(MARK)).map(|l| format!("{l}\n")).collect();
            std::fs::write(SSHD_CONFIG, kept)?;
            reload_sshd();
        }
    }
    for p in ["/opt/orbital", "/etc/orbital", "/var/lib/orbital"] {
        let _ = std::fs::remove_dir_all(p);
    }
    let _ = std::fs::remove_file(SSH_CA);
    let _ = Command::new("userdel").arg("orbital").status();
    println!("orbital-agent removed (the node stays listed until an admin removes it in the portal)");
    Ok(())
}

const UNIT_FILE: &str = "[Unit]
Description=Orbital agent
After=network-online.target
Wants=network-online.target

[Service]
User=orbital
Group=orbital
ExecStart=/opt/orbital/orbital-agent run --config-dir /etc/orbital
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/etc/orbital /var/lib/orbital /opt/orbital

[Install]
WantedBy=multi-user.target
";
