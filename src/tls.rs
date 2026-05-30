use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName,
};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::cli::ProxyConfig;
use crate::cli::TunnelConfig;

pub fn build_server_config(config: &ProxyConfig) -> Result<ServerConfig> {
    let certs = load_certs(&config.server_cert)?;
    let key = load_private_key(&config.server_key)?;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&config.server_ca)? {
        roots.add(cert).context("add server CA")?;
    }
    let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
        .build()
        .context("build client cert verifier")?;
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("build server TLS config")?;
    Ok(server_config)
}

pub fn build_client_config(config: &ProxyConfig, disable_resumption: bool) -> Result<ClientConfig> {
    let certs = load_certs(&config.upstream_cert)?;
    let key = load_private_key(&config.upstream_key)?;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&config.upstream_ca)? {
        roots.add(cert).context("add upstream CA")?;
    }
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("build upstream TLS config")?;

    if config.insecure_upstream {
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureVerifier));
    }
    if disable_resumption {
        client_config.resumption = rustls::client::Resumption::disabled();
    }
    Ok(client_config)
}

pub fn build_tunnel_client_config(config: &TunnelConfig) -> Result<ClientConfig> {
    let certs = load_certs(&config.cert)?;
    let key = load_private_key(&config.key)?;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&config.ca)? {
        roots.add(cert).context("add tunnel CA")?;
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("build tunnel TLS config")?;
    Ok(client_config)
}

#[derive(Debug)]
pub struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem_data =
        std::fs::read(path).with_context(|| format!("read cert file {}", path.display()))?;
    let blocks = pem::parse_many(pem_data).context("parse cert PEM")?;
    let mut certs = Vec::new();
    for block in blocks {
        if block.tag() == "CERTIFICATE" {
            certs.push(CertificateDer::from(block.contents().to_vec()));
        }
    }
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let pem_data =
        std::fs::read(path).with_context(|| format!("read key file {}", path.display()))?;
    let blocks = pem::parse_many(pem_data).context("parse key PEM")?;
    for block in blocks {
        let key = match block.tag() {
            "PRIVATE KEY" => {
                let key = PrivatePkcs8KeyDer::from(block.contents().to_vec());
                PrivateKeyDer::from(key)
            }
            "RSA PRIVATE KEY" => {
                let key = PrivatePkcs1KeyDer::from(block.contents().to_vec());
                PrivateKeyDer::from(key)
            }
            "EC PRIVATE KEY" => {
                let key = PrivateSec1KeyDer::from(block.contents().to_vec());
                PrivateKeyDer::from(key)
            }
            _ => continue,
        };
        return Ok(key);
    }
    bail!("no private key found in {}", path.display())
}
