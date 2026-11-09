//! Key material: KEK sealing, internal X.509 CA, Orbital SSH CAs, grant-signing key, TLS configs.

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SerialNumber,
};
use russh::keys::ssh_key::{certificate, Algorithm, Certificate, LineEnding, PrivateKey, PublicKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sqlx::PgPool;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

pub struct Kek(Aes256Gcm);

impl Kek {
    /// KEK from a file (Docker secret) or env; 32 bytes as 64 hex chars (raw 32 bytes also accepted from file).
    pub fn load(file: Option<&str>, env: Option<&str>) -> Result<Self> {
        let raw = match (file, env) {
            (Some(f), _) => std::fs::read(f).with_context(|| format!("reading KEK file {f}"))?,
            (None, Some(e)) => e.as_bytes().to_vec(),
            _ => bail!("no KEK: set ORBITAL_KEK_FILE (Docker secret) or ORBITAL_KEK"),
        };
        let trimmed = String::from_utf8_lossy(&raw).trim().to_string();
        let key = match hex::decode(&trimmed) {
            Ok(k) if k.len() == 32 => k,
            _ if raw.len() == 32 => raw,
            _ => bail!("KEK must be 32 bytes (64 hex chars)"),
        };
        Ok(Kek(Aes256Gcm::new_from_slice(&key)?))
    }
    pub fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let nonce: [u8; 12] = rand::random();
        let mut out = nonce.to_vec();
        out.extend(self.0.encrypt(Nonce::from_slice(&nonce), plain).expect("aes-gcm encrypt"));
        out
    }
    pub fn open(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < 12 {
            bail!("sealed blob too short");
        }
        self.0
            .decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..])
            .map_err(|_| anyhow!("cannot unseal secret (wrong KEK?)"))
    }
}

pub struct Keys {
    pub kek: Kek,
    pub ca_pem: String,
    pub ca_der: CertificateDer<'static>,
    ca_key: KeyPair,
    /// signs user certs presented to the orchestrator's SSH front door
    pub ssh_user_ca: PrivateKey,
    /// signs 5-minute upstream certs; trusted by sshd on nodes (TrustedUserCAKeys)
    pub ssh_node_ca: PrivateKey,
    /// the MITM's host key (shared by all replicas)
    pub ssh_host_key: PrivateKey,
    pub grant_key: ed25519_dalek::SigningKey,
}

/// Insert-if-absent then read back, so concurrently starting replicas converge on one key.
async fn load_or_create(
    db: &PgPool,
    kek: &Kek,
    name: &str,
    gen: impl FnOnce() -> Result<(String, Vec<u8>)>,
) -> Result<(String, Vec<u8>)> {
    if sqlx::query("SELECT 1 FROM secrets WHERE name = $1").bind(name).fetch_optional(db).await?.is_none() {
        let (public, private) = gen()?;
        sqlx::query("INSERT INTO secrets (name, public, sealed) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(name)
            .bind(public)
            .bind(kek.seal(&private))
            .execute(db)
            .await?;
    }
    let (public, sealed): (String, Vec<u8>) =
        sqlx::query_as("SELECT public, sealed FROM secrets WHERE name = $1").bind(name).fetch_one(db).await?;
    Ok((public, kek.open(&sealed)?))
}

fn gen_ssh() -> Result<(String, Vec<u8>)> {
    let k = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
    Ok((k.public_key().to_openssh()?, k.to_openssh(LineEnding::LF)?.as_bytes().to_vec()))
}

async fn ssh_key(db: &PgPool, kek: &Kek, name: &str) -> Result<PrivateKey> {
    let (_, private) = load_or_create(db, kek, name, gen_ssh).await?;
    Ok(PrivateKey::from_openssh(&private)?)
}

impl Keys {
    pub async fn load(db: &PgPool, kek: Kek) -> Result<Self> {
        let (ca_pem, ca_key_pem) = load_or_create(db, &kek, "internal_ca", || {
            let key = KeyPair::generate()?;
            let mut p = CertificateParams::new(Vec::<String>::new())?;
            p.distinguished_name = dn("Orbital Internal CA");
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            p.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
            p.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
            Ok((p.self_signed(&key)?.pem(), key.serialize_pem().into_bytes()))
        })
        .await?;
        let ca_key = KeyPair::from_pem(std::str::from_utf8(&ca_key_pem)?)?;
        let ca_der = rustls_pemfile::certs(&mut ca_pem.as_bytes()).next().context("CA pem")??;
        let (_, gk) = load_or_create(db, &kek, "grant_key", || {
            let seed: [u8; 32] = rand::random();
            Ok((hex::encode(ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().as_bytes()), seed.to_vec()))
        })
        .await?;
        let grant_key = ed25519_dalek::SigningKey::from_bytes(&gk.try_into().map_err(|_| anyhow!("grant key"))?);
        Ok(Keys {
            ssh_user_ca: ssh_key(db, &kek, "ssh_user_ca").await?,
            ssh_node_ca: ssh_key(db, &kek, "ssh_node_ca").await?,
            ssh_host_key: ssh_key(db, &kek, "ssh_host_key").await?,
            kek,
            ca_pem,
            ca_der,
            ca_key,
            grant_key,
        })
    }

    pub fn ca_fingerprint(&self) -> String {
        orbital_proto::sha256_hex(&self.ca_der)
    }

    fn issuer(&self) -> Result<rcgen::Certificate> {
        // rcgen 0.13: re-derive an issuer object from the stored CA (same DN + key)
        Ok(CertificateParams::from_ca_cert_pem(&self.ca_pem)?.self_signed(&self.ca_key)?)
    }

    /// Fresh server leaf for this replica, chained to the internal CA.
    pub fn server_leaf(&self, sans: &[String]) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let key = KeyPair::generate()?;
        let mut p = CertificateParams::new(sans.to_vec())?;
        p.distinguished_name = dn("orbital-orchestrator");
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
        p.not_after = OffsetDateTime::now_utc() + Duration::days(365);
        let cert = p.signed_by(&key, &self.issuer()?, &self.ca_key)?;
        Ok((
            vec![cert.der().clone(), self.ca_der.clone()],
            PrivateKeyDer::try_from(key.serialize_der()).map_err(|e| anyhow!(e))?,
        ))
    }

    /// Signs an agent CSR. CN = node id. Returns (pem, serial hex, not_after unix).
    pub fn sign_agent_csr(&self, csr_pem: &str, node_id: &str) -> Result<(String, String, u64)> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
        let serial: [u8; 16] = rand::random();
        let serial = {
            let mut s = serial;
            s[0] = (s[0] & 0x7f) | 0x01; // positive, no leading zero: DER bytes == our bytes
            s
        };
        let not_after = OffsetDateTime::now_utc() + Duration::days(30);
        let p = &mut csr.params;
        p.distinguished_name = dn(node_id);
        p.subject_alt_names = vec![];
        p.is_ca = IsCa::NoCa;
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        p.not_after = not_after;
        p.serial_number = Some(SerialNumber::from_slice(&serial));
        let cert = csr.signed_by(&self.issuer()?, &self.ca_key)?;
        Ok((cert.pem(), hex::encode(serial), not_after.unix_timestamp() as u64))
    }
}

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d
}

/// Mints an OpenSSH user certificate.
pub fn mint_ssh_cert(
    ca: &PrivateKey,
    key: &PublicKey,
    key_id: &str,
    principal: &str,
    ttl_secs: u64,
) -> Result<Certificate> {
    let now = orbital_proto::now();
    let mut b = certificate::Builder::new_with_random_nonce(&mut rand::rng(), key.key_data().clone(), now - 60, now + ttl_secs)?;
    b.serial(rand::random())?;
    b.cert_type(certificate::CertType::User)?;
    b.key_id(key_id)?;
    b.valid_principal(principal)?;
    b.extension("permit-pty", "")?;
    Ok(b.sign(ca)?)
}

// ---------------------------------------------------------------- TLS

pub fn agent_tls(keys: &Keys, sans: &[String]) -> Result<Arc<rustls::ServerConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(keys.ca_der.clone())?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated() // enrollment arrives without a client cert
        .build()?;
    let (chain, key) = keys.server_leaf(sans)?;
    Ok(Arc::new(rustls::ServerConfig::builder().with_client_cert_verifier(verifier).with_single_cert(chain, key)?))
}

pub fn public_tls(keys: &Keys, sans: &[String], cert: Option<&str>, key: Option<&str>) -> Result<rustls::ServerConfig> {
    let (chain, key) = match (cert, key) {
        (Some(c), Some(k)) => (
            rustls_pemfile::certs(&mut std::fs::read(c)?.as_slice()).collect::<Result<Vec<_>, _>>()?,
            rustls_pemfile::private_key(&mut std::fs::read(k)?.as_slice())?.context("no private key in file")?,
        ),
        // no BYO cert: self-issue from the internal CA (clients trust ca.pem)
        _ => keys.server_leaf(sans)?,
    };
    let mut cfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_cert_minting() {
        let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let user = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let cert = mint_ssh_cert(&ca, user.public_key(), "user:alice", "deploy", 300).unwrap();
        assert_eq!(cert.valid_principals(), ["deploy".to_string()]);
        assert_eq!(cert.key_id(), "user:alice");
        assert_eq!(cert.cert_type(), certificate::CertType::User);
        let ttl = cert.valid_before() - cert.valid_after();
        assert_eq!(ttl, 360, "ttl + 60s clock-skew backdate");
        let fp = ca.public_key().fingerprint(Default::default());
        cert.validate([&fp]).unwrap();
        // expired / wrong CA are rejected
        assert!(cert.validate_at(orbital_proto::now() + 301, [&fp]).is_err());
        let other = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        assert!(cert.validate([&other.public_key().fingerprint(Default::default())]).is_err());
    }

    #[test]
    fn kek_round_trip() {
        let kek = Kek::load(None, Some(&"11".repeat(32))).unwrap();
        let s = kek.seal(b"secret");
        assert_eq!(kek.open(&s).unwrap(), b"secret");
        let other = Kek::load(None, Some(&"22".repeat(32))).unwrap();
        assert!(other.open(&s).is_err());
    }
}
