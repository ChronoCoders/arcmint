use crate::error::{ArcMintError, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::client::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};
use rustls::RootCertStore;
use rustls_pemfile::{certs, read_one, Item};
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;
use std::sync::Arc;
use time::Duration;

#[derive(Clone)]
pub struct CertBundle {
    pub cert_pem: String,
    pub key_pem: String,
}

fn rcgen_to_bundle(cert: &Certificate, key_pair: &KeyPair) -> Result<CertBundle> {
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    Ok(CertBundle { cert_pem, key_pem })
}

fn parse_ca_bundle(ca_cert_pem: &str, ca_key_pem: &str) -> Result<(Certificate, KeyPair)> {
    let params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .map_err(|e| ArcMintError::CryptoError(format!("invalid CA cert PEM: {e}")))?;
    let key = KeyPair::from_pem(ca_key_pem)
        .map_err(|e| ArcMintError::CryptoError(format!("invalid CA key PEM: {e}")))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| ArcMintError::CryptoError(format!("failed to rebuild CA certificate: {e}")))?;
    Ok((cert, key))
}

pub fn generate_ca(common_name: &str) -> Result<CertBundle> {
    let mut params = CertificateParams::new(vec![common_name.to_string()])
        .map_err(|e| ArcMintError::CryptoError(format!("CA params generation failed: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365 * 10);
    let key_pair = KeyPair::generate()
        .map_err(|e| ArcMintError::CryptoError(format!("CA key generation failed: {e}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| ArcMintError::CryptoError(format!("CA cert generation failed: {e}")))?;
    rcgen_to_bundle(&cert, &key_pair)
}

pub fn generate_server_cert(
    common_name: &str,
    san_dns: &[&str],
    san_ip: &[&str],
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<CertBundle> {
    let mut all_names: Vec<String> = Vec::new();
    all_names.push(common_name.to_string());
    for dns in san_dns {
        if !dns.is_empty() {
            all_names.push((*dns).to_string());
        }
    }
    for ip_str in san_ip {
        if !ip_str.is_empty() {
            all_names.push((*ip_str).to_string());
        }
    }
    let mut params = CertificateParams::new(all_names)
        .map_err(|e| ArcMintError::CryptoError(format!("server params generation failed: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365);
    let (ca_cert, ca_key) = parse_ca_bundle(ca_cert_pem, ca_key_pem)?;
    let key_pair = KeyPair::generate()
        .map_err(|e| ArcMintError::CryptoError(format!("server key generation failed: {e}")))?;
    let cert = params
        .signed_by(&key_pair, &ca_cert, &ca_key)
        .map_err(|e| ArcMintError::CryptoError(format!("server cert generation failed: {e}")))?;
    rcgen_to_bundle(&cert, &key_pair)
}

pub fn generate_client_cert(
    common_name: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<CertBundle> {
    let mut params = CertificateParams::new(vec![common_name.to_string()])
        .map_err(|e| ArcMintError::CryptoError(format!("client params generation failed: {e}")))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(365);
    let (ca_cert, ca_key) = parse_ca_bundle(ca_cert_pem, ca_key_pem)?;
    let key_pair = KeyPair::generate()
        .map_err(|e| ArcMintError::CryptoError(format!("client key generation failed: {e}")))?;
    let cert = params
        .signed_by(&key_pair, &ca_cert, &ca_key)
        .map_err(|e| ArcMintError::CryptoError(format!("client cert generation failed: {e}")))?;
    rcgen_to_bundle(&cert, &key_pair)
}

pub fn save_cert_bundle(bundle: &CertBundle, cert_path: &Path, key_path: &Path) -> Result<()> {
    if let Some(parent) = cert_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ArcMintError::CryptoError(format!("failed to create cert directory: {e}"))
            })?;
        }
    }
    if let Some(parent) = key_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ArcMintError::CryptoError(format!("failed to create key directory: {e}"))
            })?;
        }
    }
    {
        let mut f = File::create(cert_path)
            .map_err(|e| ArcMintError::CryptoError(format!("failed to create cert file: {e}")))?;
        f.write_all(bundle.cert_pem.as_bytes())
            .map_err(|e| ArcMintError::CryptoError(format!("failed to write cert file: {e}")))?;
    }
    {
        let mut f = File::create(key_path)
            .map_err(|e| ArcMintError::CryptoError(format!("failed to create key file: {e}")))?;
        f.write_all(bundle.key_pem.as_bytes())
            .map_err(|e| ArcMintError::CryptoError(format!("failed to write key file: {e}")))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(key_path)
            .map_err(|e| ArcMintError::CryptoError(format!("failed to stat key file: {e}")))?;
        let mut perms = metadata.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(key_path, perms).map_err(|e| {
            ArcMintError::CryptoError(format!("failed to set key permissions: {e}"))
        })?;
    }
    Ok(())
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .map_err(|e| ArcMintError::CryptoError(format!("failed to open cert file: {e}")))?;
    let mut reader = BufReader::new(file);
    let mut certs_der = Vec::new();
    for item in certs(&mut reader) {
        let cert =
            item.map_err(|e| ArcMintError::CryptoError(format!("failed to read certs: {e}")))?;
        certs_der.push(cert);
    }
    if certs_der.is_empty() {
        return Err(ArcMintError::CryptoError(
            "empty certificate chain".to_string(),
        ));
    }
    Ok(certs_der)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .map_err(|e| ArcMintError::CryptoError(format!("failed to open key file: {e}")))?;
    let mut reader = BufReader::new(file);
    loop {
        let item = read_one(&mut reader)
            .map_err(|e| ArcMintError::CryptoError(format!("failed to read key: {e}")))?;
        match item {
            Some(Item::Pkcs8Key(key)) => {
                return Ok(PrivateKeyDer::Pkcs8(key));
            }
            Some(Item::Sec1Key(_)) => continue,
            Some(Item::X509Certificate(_)) => continue,
            Some(_) => continue,
            None => break,
        }
    }
    Err(ArcMintError::CryptoError(
        "no suitable private key found".to_string(),
    ))
}

pub fn load_tls_server_config(
    cert_path: &Path,
    key_path: &Path,
    ca_cert_path: Option<&Path>,
) -> Result<ServerConfig> {
    let certs = load_cert_chain(cert_path)?;
    let key = load_private_key(key_path)?;
    let mut config = if let Some(ca_path) = ca_cert_path {
        let mut store = RootCertStore::empty();
        let mut buf = Vec::new();
        File::open(ca_path)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(|e| ArcMintError::CryptoError(format!("failed to read CA cert: {e}")))?;
        let mut reader = &buf[..];
        for item in rustls_pemfile::certs(&mut reader) {
            let cert = item
                .map_err(|e| ArcMintError::CryptoError(format!("failed to parse CA certs: {e}")))?;
            store.add(cert).map_err(|e| {
                ArcMintError::CryptoError(format!("failed to add CA cert to store: {e}"))
            })?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(store))
            .build()
            .map_err(|e| {
                ArcMintError::CryptoError(format!("failed to build client verifier: {e}"))
            })?;
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| ArcMintError::CryptoError(format!("invalid server cert or key: {e}")))?
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ArcMintError::CryptoError(format!("invalid server cert or key: {e}")))?
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

pub fn load_tls_client_config(
    ca_cert_path: &Path,
    client_cert_path: Option<&Path>,
    client_key_path: Option<&Path>,
) -> Result<ClientConfig> {
    let mut store = RootCertStore::empty();
    let mut buf = Vec::new();
    File::open(ca_cert_path)
        .and_then(|mut f| f.read_to_end(&mut buf))
        .map_err(|e| ArcMintError::CryptoError(format!("failed to read CA cert: {e}")))?;
    let mut reader = &buf[..];
    for item in rustls_pemfile::certs(&mut reader) {
        let cert =
            item.map_err(|e| ArcMintError::CryptoError(format!("failed to parse CA certs: {e}")))?;
        store.add(cert).map_err(|e| {
            ArcMintError::CryptoError(format!("failed to add CA cert to store: {e}"))
        })?;
    }
    let mut config = if let (Some(cert_path), Some(key_path)) = (client_cert_path, client_key_path)
    {
        let certs = load_cert_chain(cert_path)?;
        let key = load_private_key(key_path)?;
        ClientConfig::builder()
            .with_root_certificates(store)
            .with_client_auth_cert(certs, key)
            .map_err(|e| ArcMintError::CryptoError(format!("invalid client cert or key: {e}")))?
    } else {
        ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}
