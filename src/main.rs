use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use bytes::BytesMut;
use clap::Parser;
use notify::{RecursiveMode, Watcher};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
    ServerName,
};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, info};
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let config = Config::parse();
    let acl = load_acl(&config.acl)?;
    let (acl_tx, acl_rx) = watch::channel(Arc::new(acl));

    let server_config = build_server_config(&config)?;
    let client_config = build_client_config(&config)?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let connector = TlsConnector::from(Arc::new(client_config));

    let listener = TcpListener::bind(&config.listen)
        .await
        .with_context(|| format!("bind listen address {}", config.listen))?;

    info!("listening on {}", config.listen);

    let config = Arc::new(config);
    let _acl_watcher = start_acl_watcher(config.acl.clone(), acl_tx)?;

    loop {
        let (socket, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let connector = connector.clone();
        let acl_rx = acl_rx.clone();
        let config = config.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(socket, acceptor, connector, acl_rx, config).await {
                error!("connection error: {err:#}");
            }
        });
    }
}

async fn handle_connection(
    socket: TcpStream,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    acl_rx: watch::Receiver<Arc<HashMap<String, String>>>,
    config: Arc<Config>,
) -> Result<()> {
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

    let upstream_socket = timeout(handshake_timeout, TcpStream::connect(upstream_addr))
        .await
        .context("upstream TCP connect timeout")??;

    let server_name = match upstream_host.parse::<std::net::IpAddr>() {
        Ok(ip) => ServerName::IpAddress(ip.into()),
        Err(_) => ServerName::try_from(upstream_host.clone())
            .context("invalid upstream hostname for TLS")?,
    };

    let mut upstream_tls = timeout(
        handshake_timeout,
        connector.connect(server_name, upstream_socket),
    )
    .await
    .context("upstream TLS handshake timeout")??;

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
                    match msg {
                        Some(payload) => downstream_writer.write_all(&payload).await?,
                        None => continue,
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
                let frame = match parse_command_frame(&buffer)? {
                    Some(frame) => frame,
                    None => break,
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
        let setuser_index = match setuser_index {
            Some(idx) => idx,
            None => continue,
        };
        if setuser_index + 1 >= tokens.len() {
            continue;
        }
        let user = tokens[setuser_index + 1].to_string();
        let mut password: Option<String> = None;
        for token in tokens.iter().skip(setuser_index + 2) {
            if let Some(rest) = token.strip_prefix('>') {
                if !rest.is_empty() {
                    password = Some(rest.to_string());
                }
            }
        }
        let password = match password {
            Some(pw) => pw,
            None => continue,
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

fn build_client_config(config: &Config) -> Result<ClientConfig> {
    let certs = load_certs(&config.upstream_cert)?;
    let key = load_private_key(&config.upstream_key)?;
    let mut roots = RootCertStore::empty();
    for cert in load_certs(&config.upstream_ca)? {
        roots.add(cert).context("add upstream CA")?;
    }
    let client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .context("build upstream TLS config")?;
    Ok(client_config)
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
    let line_end = match find_crlf(buf) {
        Some(pos) => pos,
        None => return Ok(None),
    };
    let line = &buf[..line_end];
    let mut iter = line
        .split(|b| b.is_ascii_whitespace())
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
    let line_end = match find_crlf_from(buf, idx) {
        Some(pos) => pos,
        None => return Ok(None),
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
        let bulk_len_end = match find_crlf_from(buf, idx) {
            Some(pos) => pos,
            None => return Ok(None),
        };
        let bulk_len = parse_number(&buf[idx..bulk_len_end])?;
        if bulk_len < 0 {
            bail!("null bulk not supported for command");
        }
        let bulk_len = bulk_len as usize;
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
