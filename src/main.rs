#![warn(clippy::pedantic)]
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::BytesMut;
use clap::Parser;
use notify::{RecursiveMode, Watcher};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName,
};
use rustls::{AlertDescription, ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Parser, Debug, Clone)]
#[command(name = "dfguard", version, about = "mTLS auth proxy for DragonflyDB")]
struct Config {
    #[arg(long)]
    listen: String,
    #[arg(long)]
    upstream: String,
    #[arg(long, value_name = "FILE")]
    acl: PathBuf,

    #[arg(long, value_name = "FILE")]
    server_cert: PathBuf,
    #[arg(long, value_name = "FILE")]
    server_key: PathBuf,
    #[arg(long, value_name = "FILE")]
    server_ca: PathBuf,

    #[arg(long, value_name = "FILE")]
    upstream_cert: PathBuf,
    #[arg(long, value_name = "FILE")]
    upstream_key: PathBuf,
    #[arg(long, value_name = "FILE")]
    upstream_ca: PathBuf,

    #[arg(long, default_value = "10")]
    handshake_timeout_secs: u64,
    #[arg(long, default_value = "300")]
    idle_timeout_secs: u64,
    #[arg(long, default_value = "16777216")]
    max_frame_size: usize,

    #[arg(long, default_value_t = false)]
    insecure_upstream: bool,
}

#[derive(Clone)]
struct ClientConfigs {
    with_resumption: Arc<ClientConfig>,
    no_resumption: Arc<ClientConfig>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    let config = Config::parse();
    let acl = load_acl(&config.acl)?;
    let (acl_tx, acl_rx) = watch::channel(Arc::new(acl));

    let server_config = Arc::new(build_server_config(&config)?);
    let client_configs = Arc::new(ClientConfigs {
        with_resumption: Arc::new(build_client_config(&config, false)?),
        no_resumption: Arc::new(build_client_config(&config, true)?),
    });
    let (server_tx, server_rx) = watch::channel(server_config);
    let (client_tx, client_rx) = watch::channel(client_configs);
    let resumption_enabled = Arc::new(AtomicBool::new(true));

    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind listen address {}", config.listen))?;

    info!("listening on {}", config.listen);

    let config = Arc::new(config);
    let _acl_watcher = start_acl_watcher(config.acl.clone(), acl_tx)?;
    let _tls_watcher = start_tls_watcher(config.clone(), server_tx, client_tx)?;

    loop {
        let (socket, _) = listener.accept().await?;
        let server_rx = server_rx.clone();
        let client_rx = client_rx.clone();
        let resumption_enabled = resumption_enabled.clone();
        let acl_rx = acl_rx.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                socket,
                server_rx,
                client_rx,
                resumption_enabled,
                acl_rx,
                config,
            )
            .await
            {
                error!("connection error: {err:#}");
            }
        });
    }
}

#[allow(clippy::too_many_lines)]
async fn handle_connection(
    socket: TcpStream,
    server_rx: watch::Receiver<Arc<ServerConfig>>,
    client_rx: watch::Receiver<Arc<ClientConfigs>>,
    resumption_enabled: Arc<AtomicBool>,
    acl_rx: watch::Receiver<Arc<HashMap<String, String>>>,
    config: Arc<Config>,
) -> Result<()> {
    let server_config = server_rx.borrow().clone();
    let acceptor = TlsAcceptor::from(server_config);
    let handshake_timeout = Duration::from_secs(config.handshake_timeout_secs);
    let tls_stream = timeout(handshake_timeout, acceptor.accept(socket))
        .await
        .context("downstream TLS handshake timeout")??;

    let user = extract_dns_user(&tls_stream)?;
    let acl = acl_rx.borrow().clone();
    let password = acl
        .get(&user)
        .ok_or_else(|| anyhow!("user not found in ACL: {user}"))?
        .clone();

    let (upstream_host, _upstream_port) = parse_host_port(&config.upstream)?;
    let upstream_addr = resolve_addr(&config.upstream)?;
    let server_name = parse_server_name(&upstream_host)?;
    let client_configs = client_rx.borrow().clone();
    let connector = TlsConnector::from(client_configs.with_resumption.clone());
    let connector_no_resumption = TlsConnector::from(client_configs.no_resumption.clone());

    let mut upstream_tls = if resumption_enabled.load(Ordering::Relaxed) {
        match connect_upstream(
            &connector,
            upstream_addr,
            server_name.clone(),
            handshake_timeout,
        )
        .await
        {
            Ok(stream) => stream,
            Err(err) => {
                if should_retry_without_resumption(&err) {
                    info!("upstream TLS resumption failed, retrying without resumption");
                    let stream = connect_upstream(
                        &connector_no_resumption,
                        upstream_addr,
                        server_name,
                        handshake_timeout,
                    )
                    .await?;
                    resumption_enabled.store(false, Ordering::Relaxed);
                    info!("upstream TLS resumption disabled for future connections");
                    stream
                } else {
                    return Err(err);
                }
            }
        }
    } else {
        connect_upstream(
            &connector_no_resumption,
            upstream_addr,
            server_name,
            handshake_timeout,
        )
        .await?
    };

    send_auth(&mut upstream_tls, &user, &password).await?;

    let (mut downstream_reader, mut downstream_writer) = tokio::io::split(tls_stream);
    let (mut upstream_reader, mut upstream_writer) = tokio::io::split(upstream_tls);

    let (err_tx, mut err_rx) = mpsc::channel::<Vec<u8>>(8);
    let err_tx_client = err_tx.clone();
    let idle_timeout = Duration::from_secs(config.idle_timeout_secs);
    let max_frame_size = config.max_frame_size;

    let upstream_to_downstream = tokio::spawn(async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            tokio::select! {
                read_res = timeout(idle_timeout, upstream_reader.read(&mut buffer)) => {
                    let n = match read_res {
                        Ok(Ok(n)) => n,
                        Ok(Err(err)) => return Err(anyhow!(err)),
                        Err(_) => return Err(anyhow!("upstream idle timeout")),
                    };
                    if n == 0 {
                        return Ok(());
                    }
                    downstream_writer.write_all(&buffer[..n]).await?;
                }
                msg = err_rx.recv() => {
                    if let Some(payload) = msg {
                        downstream_writer.write_all(&payload).await?;
                    }
                }
            }
        }
    });

    let client_to_upstream = async move {
        let mut buffer = BytesMut::with_capacity(8192);
        let mut read_buf = [0u8; 8192];
        loop {
            let n = match timeout(idle_timeout, downstream_reader.read(&mut read_buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(err)) => return Err(anyhow!(err)),
                Err(_) => return Err(anyhow!("downstream idle timeout")),
            };
            if n == 0 {
                return Ok(());
            }
            buffer.extend_from_slice(&read_buf[..n]);
            if buffer.len() > max_frame_size {
                return Err(anyhow!("frame buffer exceeds max size"));
            }

            loop {
                let Some(frame) = parse_command_frame(&buffer)? else {
                    break;
                };
                if frame.len > max_frame_size {
                    return Err(anyhow!("frame exceeds max size"));
                }
                let data = buffer.split_to(frame.len);
                if frame.is_auth {
                    let _ = err_tx_client
                        .send(b"-ERR AUTH disabled by proxy\r\n".to_vec())
                        .await;
                } else {
                    upstream_writer.write_all(&data).await?;
                }
            }
        }
    };

    let client_to_upstream_result = client_to_upstream.await;
    drop(err_tx);
    let upstream_to_downstream_result = upstream_to_downstream.await;

    client_to_upstream_result?;
    upstream_to_downstream_result??;
    Ok(())
}

fn parse_host_port(input: &str) -> Result<(String, u16)> {
    if let Some(rest) = input.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow!("invalid IPv6 upstream address"))?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("missing port in upstream address"))?;
        let port = port.parse::<u16>().context("invalid port")?;
        return Ok((host.to_string(), port));
    }

    let (host, port) = input
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("upstream must be host:port"))?;
    let port = port.parse::<u16>().context("invalid port")?;
    Ok((host.to_string(), port))
}

fn resolve_addr(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()
        .context("resolve upstream address")?
        .next()
        .ok_or_else(|| anyhow!("no upstream address resolved"))
}

fn extract_dns_user(tls: &tokio_rustls::server::TlsStream<TcpStream>) -> Result<String> {
    let (_, session) = tls.get_ref();
    let certs = session
        .peer_certificates()
        .ok_or_else(|| anyhow!("no client certificate"))?;
    let cert = certs
        .first()
        .ok_or_else(|| anyhow!("no client certificate"))?;
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).context("parse client cert")?;
    let san = parsed
        .subject_alternative_name()
        .context("read client SAN")?
        .ok_or_else(|| anyhow!("client certificate missing SAN"))?;

    let mut dns_names = san
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();

    if dns_names.is_empty() {
        bail!("client certificate missing dNSName SAN");
    }
    if dns_names.len() != 1 {
        bail!("client certificate has multiple dNSName SAN entries");
    }
    Ok(dns_names.remove(0))
}

fn load_acl(path: &Path) -> Result<HashMap<String, String>> {
    let file = File::open(path).with_context(|| format!("open ACL file {}", path.display()))?;
    let reader = BufReader::new(file);
    parse_acl_lines(reader.lines())
}

fn start_acl_watcher(
    path: PathBuf,
    acl_tx: watch::Sender<Arc<HashMap<String, String>>>,
) -> Result<notify::RecommendedWatcher> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            let _ = event_tx.send(());
        }
    })
    .context("create ACL watcher")?;

    watcher
        .watch(&path, RecursiveMode::NonRecursive)
        .with_context(|| format!("watch ACL file {}", path.display()))?;

    tokio::spawn(async move {
        while event_rx.recv().await.is_some() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            match load_acl(&path) {
                Ok(map) => {
                    let _ = acl_tx.send(Arc::new(map));
                    info!("ACL reloaded");
                }
                Err(err) => {
                    error!("ACL reload failed: {err:#}");
                }
            }
        }
    });

    Ok(watcher)
}

fn start_tls_watcher(
    config: Arc<Config>,
    server_tx: watch::Sender<Arc<ServerConfig>>,
    client_tx: watch::Sender<Arc<ClientConfigs>>,
) -> Result<notify::RecommendedWatcher> {
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<()>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            let _ = event_tx.send(());
        }
    })
    .context("create TLS watcher")?;

    let paths = vec![
        config.server_cert.clone(),
        config.server_key.clone(),
        config.server_ca.clone(),
        config.upstream_cert.clone(),
        config.upstream_key.clone(),
        config.upstream_ca.clone(),
    ];
    for path in &paths {
        watcher
            .watch(path, RecursiveMode::NonRecursive)
            .with_context(|| format!("watch TLS file {}", path.display()))?;
    }

    tokio::spawn(async move {
        while event_rx.recv().await.is_some() {
            tokio::time::sleep(Duration::from_millis(200)).await;
            match build_server_config(config.as_ref()) {
                Ok(server_config) => {
                    let _ = server_tx.send(Arc::new(server_config));
                    info!("server TLS config reloaded");
                }
                Err(err) => error!("server TLS reload failed: {err:#}"),
            }

            match (
                build_client_config(config.as_ref(), false),
                build_client_config(config.as_ref(), true),
            ) {
                (Ok(with_resumption), Ok(no_resumption)) => {
                    let configs = ClientConfigs {
                        with_resumption: Arc::new(with_resumption),
                        no_resumption: Arc::new(no_resumption),
                    };
                    let _ = client_tx.send(Arc::new(configs));
                    info!("upstream TLS config reloaded");
                }
                (Err(err), _) | (_, Err(err)) => {
                    error!("upstream TLS reload failed: {err:#}");
                }
            }
        }
    });

    Ok(watcher)
}

fn parse_acl_lines<I>(lines: I) -> Result<HashMap<String, String>>
where
    I: Iterator<Item = std::io::Result<String>>,
{
    let mut map = HashMap::new();

    for (line_num, line) in lines.enumerate() {
        let line = line.with_context(|| format!("read ACL line {}", line_num + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let line = match trimmed.split_once('#') {
            Some((left, _)) => left.trim(),
            None => trimmed,
        };
        if line.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 4 {
            continue;
        }

        let mut setuser_index = None;
        for (idx, token) in tokens.iter().enumerate() {
            if token.eq_ignore_ascii_case("SETUSER") {
                setuser_index = Some(idx);
                break;
            }
        }
        let Some(setuser_index) = setuser_index else {
            continue;
        };
        if setuser_index + 1 >= tokens.len() {
            continue;
        }
        let user = tokens[setuser_index + 1].to_string();
        let mut password: Option<String> = None;
        for token in tokens.iter().skip(setuser_index + 2) {
            if let Some(rest) = token.strip_prefix('>')
                && !rest.is_empty()
            {
                password = Some(rest.to_string());
            }
        }
        let Some(password) = password else {
            continue;
        };

        if map.contains_key(&user) {
            bail!("duplicate ACL entry for user {user}");
        }
        map.insert(user, password);
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::parse_acl_lines;

    #[test]
    fn acl_last_password_wins() {
        let input = vec![
            Ok("ACL SETUSER svc ON >first >second +@all ~*".to_string()),
            Ok("# comment".to_string()),
        ];
        let map = parse_acl_lines(input.into_iter()).expect("parse ACL");
        assert_eq!(map.get("svc").map(String::as_str), Some("second"));
    }

    #[test]
    fn acl_duplicate_user_errors() {
        let input = vec![
            Ok("ACL SETUSER svc ON >one +@all ~*".to_string()),
            Ok("ACL SETUSER svc ON >two +@all ~*".to_string()),
        ];
        let err = parse_acl_lines(input.into_iter()).expect_err("duplicate user should error");
        assert!(err.to_string().contains("duplicate ACL entry"));
    }

    #[test]
    fn acl_namespace_token_supported() {
        let input = vec![Ok(
            "ACL SETUSER user1 NAMESPACE:namespace1 ON >user_pass +@all ~*".to_string(),
        )];
        let map = parse_acl_lines(input.into_iter()).expect("parse ACL");
        assert_eq!(map.get("user1").map(String::as_str), Some("user_pass"));
    }
}

fn build_server_config(config: &Config) -> Result<ServerConfig> {
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

fn build_client_config(config: &Config, disable_resumption: bool) -> Result<ClientConfig> {
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

#[derive(Debug)]
struct InsecureVerifier;

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

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
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

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
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

async fn send_auth(
    upstream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    user: &str,
    password: &str,
) -> Result<()> {
    let payload = build_auth_command(user, password);
    upstream.write_all(&payload).await?;

    let mut buffer = Vec::with_capacity(128);
    let mut temp = [0u8; 64];
    loop {
        let n = upstream.read(&mut temp).await?;
        if n == 0 {
            bail!("upstream closed connection during AUTH");
        }
        buffer.extend_from_slice(&temp[..n]);
        if let Some(pos) = find_crlf(&buffer) {
            let line = &buffer[..pos];
            if line.starts_with(b"-") {
                let msg = String::from_utf8_lossy(line);
                bail!("upstream AUTH error: {msg}");
            }
            return Ok(());
        }
        if buffer.len() > 1024 {
            bail!("unexpected AUTH response size");
        }
    }
}

fn build_auth_command(user: &str, password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + user.len() + password.len());
    out.extend_from_slice(b"*3\r\n");
    push_bulk(&mut out, b"AUTH");
    push_bulk(&mut out, user.as_bytes());
    push_bulk(&mut out, password.as_bytes());
    out
}

fn push_bulk(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(b"$");
    out.extend_from_slice(data.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

fn parse_command_frame(buf: &BytesMut) -> Result<Option<FrameInfo>> {
    if buf.is_empty() {
        return Ok(None);
    }
    match buf[0] {
        b'*' => parse_array_frame(buf),
        b'+' | b'-' | b':' | b'$' => bail!("unsupported frame type from client"),
        _ => parse_inline_frame(buf),
    }
}

fn parse_inline_frame(buf: &BytesMut) -> Result<Option<FrameInfo>> {
    let Some(line_end) = find_crlf(buf) else {
        return Ok(None);
    };
    let line = &buf[..line_end];
    let mut iter = line
        .split(u8::is_ascii_whitespace)
        .filter(|s| !s.is_empty());
    let cmd = iter.next().ok_or_else(|| anyhow!("empty inline command"))?;
    let is_auth = cmd.eq_ignore_ascii_case(b"AUTH");
    Ok(Some(FrameInfo {
        len: line_end + 2,
        is_auth,
    }))
}

fn parse_array_frame(buf: &BytesMut) -> Result<Option<FrameInfo>> {
    let mut idx = 1;
    let Some(line_end) = find_crlf_from(buf, idx) else {
        return Ok(None);
    };
    let count = parse_number(&buf[idx..line_end])?;
    if count <= 0 {
        bail!("invalid array length");
    }
    idx = line_end + 2;

    let mut is_auth = false;
    for i in 0..count {
        if idx >= buf.len() {
            return Ok(None);
        }
        if buf[idx] != b'$' {
            bail!("unsupported array element type");
        }
        idx += 1;
        let Some(bulk_len_end) = find_crlf_from(buf, idx) else {
            return Ok(None);
        };
        let bulk_len = parse_number(&buf[idx..bulk_len_end])?;
        if bulk_len < 0 {
            bail!("null bulk not supported for command");
        }
        let bulk_len = usize::try_from(bulk_len).context("bulk length too large")?;
        idx = bulk_len_end + 2;
        if idx + bulk_len + 2 > buf.len() {
            return Ok(None);
        }
        if i == 0 {
            let cmd = &buf[idx..idx + bulk_len];
            is_auth = cmd.eq_ignore_ascii_case(b"AUTH");
        }
        idx += bulk_len + 2;
    }

    Ok(Some(FrameInfo { len: idx, is_auth }))
}

fn parse_number(slice: &[u8]) -> Result<i64> {
    let s = std::str::from_utf8(slice).context("invalid number")?;
    let n = s.parse::<i64>().context("invalid number")?;
    Ok(n)
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    find_crlf_from(buf, 0)
}

fn find_crlf_from(buf: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

struct FrameInfo {
    len: usize,
    is_auth: bool,
}

async fn connect_upstream(
    connector: &TlsConnector,
    addr: SocketAddr,
    server_name: ServerName<'static>,
    timeout_duration: Duration,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let upstream_socket = timeout(timeout_duration, TcpStream::connect(addr))
        .await
        .context("upstream TCP connect timeout")??;
    let upstream_tls = timeout(
        timeout_duration,
        connector.connect(server_name, upstream_socket),
    )
    .await
    .context("upstream TLS handshake timeout")??;
    Ok(upstream_tls)
}

fn parse_server_name(host: &str) -> Result<ServerName<'static>> {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Ok(ServerName::IpAddress(ip.into())),
        Err(_) => {
            ServerName::try_from(host.to_string()).context("invalid upstream hostname for TLS")
        }
    }
}

fn should_retry_without_resumption(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(rustls::Error::AlertReceived(desc)) = cause.downcast_ref::<rustls::Error>()
            && *desc == AlertDescription::InternalError
        {
            return true;
        }
    }
    err.to_string().contains("InternalError")
}
