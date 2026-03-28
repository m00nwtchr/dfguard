use std::collections::HashMap;
use std::io;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_profile_ping_through_proxy() {
    let pki = TestPki::generate().expect("generate test PKI");
    let upstream = start_mock_upstream(&pki)
        .await
        .expect("start upstream server");

    let proxy_port = free_port();
    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    let mut child = spawn_proxy(&pki, &proxy_addr, upstream.addr.port());
    let _proxy_guard = ChildGuard::new(&mut child);

    let downstream_connector = build_downstream_connector(&pki);
    wait_for_proxy_ready(&downstream_connector, &proxy_addr)
        .await
        .expect("proxy ready");

    let clients = env_usize("DFGUARD_ITEST_LOAD_CLIENTS", 24);
    let requests_per_client = env_usize("DFGUARD_ITEST_LOAD_REQUESTS", 200);
    let expected_ping_count = clients * requests_per_client;

    let started = Instant::now();
    let mut tasks = JoinSet::new();
    for _ in 0..clients {
        let connector = downstream_connector.clone();
        let proxy_addr = proxy_addr.clone();
        tasks.spawn(async move {
            run_ping_load_client(&connector, &proxy_addr, requests_per_client).await
        });
    }

    while let Some(res) = tasks.join_next().await {
        res.expect("load task join").expect("load task succeeded");
    }
    let elapsed = started.elapsed();

    wait_for_ping_count(&upstream.ping_count, expected_ping_count)
        .await
        .expect("upstream saw full ping load");

    assert!(
        elapsed < Duration::from_secs(20),
        "load test took too long: {elapsed:?}"
    );
    assert_eq!(
        upstream.ping_count.load(Ordering::Relaxed),
        expected_ping_count,
        "upstream should receive all forwarded PING commands"
    );

    upstream.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn load_profile_mixed_command_classes_and_reset_reauth() {
    let pki = TestPki::generate().expect("generate test PKI");
    let upstream = start_mock_upstream(&pki)
        .await
        .expect("start upstream server");

    let proxy_port = free_port();
    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    let mut child = spawn_proxy(&pki, &proxy_addr, upstream.addr.port());
    let _proxy_guard = ChildGuard::new(&mut child);

    let downstream_connector = build_downstream_connector(&pki);
    wait_for_proxy_ready(&downstream_connector, &proxy_addr)
        .await
        .expect("proxy ready");

    let server_name = ServerName::try_from("localhost")
        .expect("valid server name")
        .to_owned();
    let tcp = TcpStream::connect(&proxy_addr)
        .await
        .expect("connect to proxy");
    let mut tls = downstream_connector
        .connect(server_name, tcp)
        .await
        .expect("complete downstream tls");

    let cycles = env_usize("DFGUARD_ITEST_MIXED_CYCLES", 1);
    for _ in 0..cycles {
        send_command_expect_simple(&mut tls, &["PING"], "+PONG").await;
        send_command_expect_simple(&mut tls, &["MULTI"], "+OK").await;
        send_command_expect_simple(&mut tls, &["PING"], "+PONG").await;
        send_command_expect_simple(&mut tls, &["EXEC"], "+OK").await;
        send_command_expect_simple(&mut tls, &["BLPOP", "queue", "0"], "+OK").await;
        send_command_expect_simple(&mut tls, &["SUBSCRIBE", "chan"], "+OK").await;
        send_command_expect_simple(&mut tls, &["PING"], "+PONG").await;
        send_command_expect_simple(&mut tls, &["RESET"], "+OK").await;
        send_command_expect_simple(&mut tls, &["PING"], "+PONG").await;
    }

    let auth_count = upstream.command_count("AUTH");
    assert_eq!(
        auth_count,
        1 + cycles,
        "each RESET should trigger one re-auth upstream"
    );
    assert_eq!(upstream.command_count("MULTI"), cycles);
    assert_eq!(upstream.command_count("EXEC"), cycles);
    assert_eq!(upstream.command_count("BLPOP"), cycles);
    assert_eq!(upstream.command_count("SUBSCRIBE"), cycles);
    assert_eq!(upstream.command_count("RESET"), cycles);
    assert_eq!(upstream.command_count("PING"), cycles * 4);

    upstream.shutdown();
}

fn spawn_proxy(pki: &TestPki, listen_addr: &str, upstream_port: u16) -> Child {
    Command::new(env!("CARGO_BIN_EXE_dfguard"))
        .arg("--listen")
        .arg(listen_addr)
        .arg("--upstream")
        .arg(format!("127.0.0.1:{upstream_port}"))
        .arg("--acl")
        .arg(&pki.acl_path)
        .arg("--server-cert")
        .arg(&pki.server_cert_path)
        .arg("--server-key")
        .arg(&pki.server_key_path)
        .arg("--server-ca")
        .arg(&pki.ca_cert_path)
        .arg("--upstream-cert")
        .arg(&pki.upstream_client_cert_path)
        .arg("--upstream-key")
        .arg(&pki.upstream_client_key_path)
        .arg("--upstream-ca")
        .arg(&pki.ca_cert_path)
        .arg("--insecure-upstream")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn dfguard")
}

async fn wait_for_proxy_ready(connector: &TlsConnector, proxy_addr: &str) -> io::Result<()> {
    let server_name = ServerName::try_from("localhost")
        .expect("valid server name")
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "proxy did not become ready in time",
            ));
        }

        match TcpStream::connect(proxy_addr).await {
            Ok(stream) => {
                if connector.connect(server_name.clone(), stream).await.is_ok() {
                    return Ok(());
                }
            }
            Err(_) => {}
        }

        sleep(Duration::from_millis(50)).await;
    }
}

async fn run_ping_load_client(
    connector: &TlsConnector,
    proxy_addr: &str,
    requests: usize,
) -> io::Result<()> {
    let server_name = ServerName::try_from("localhost")
        .expect("valid server name")
        .to_owned();
    let tcp = TcpStream::connect(proxy_addr).await?;
    let mut tls = connector.connect(server_name, tcp).await?;

    for _ in 0..requests {
        tls.write_all(b"*1\r\n$4\r\nPING\r\n").await?;
        let mut response = [0u8; 7];
        tls.read_exact(&mut response).await?;
        if &response != b"+PONG\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unexpected response: {}",
                    String::from_utf8_lossy(&response)
                ),
            ));
        }
    }

    Ok(())
}

async fn wait_for_ping_count(counter: &AtomicUsize, expected: usize) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if counter.load(Ordering::Relaxed) >= expected {
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "upstream ping count did not reach expected count: got {}, want {expected}",
                    counter.load(Ordering::Relaxed)
                ),
            ));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

struct UpstreamFixture {
    addr: std::net::SocketAddr,
    ping_count: Arc<AtomicUsize>,
    command_counts: Arc<Mutex<HashMap<String, usize>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl UpstreamFixture {
    fn command_count(&self, command: &str) -> usize {
        self.command_counts
            .lock()
            .get(command)
            .copied()
            .unwrap_or(0)
    }

    fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn start_mock_upstream(pki: &TestPki) -> io::Result<UpstreamFixture> {
    let certs = vec![CertificateDer::from(pki.upstream_server.cert_der.clone())];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        pki.upstream_server.key_der.clone(),
    ));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build upstream tls server config");
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let ping_count = Arc::new(AtomicUsize::new(0));
    let command_counts = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    let ping_count_for_task = ping_count.clone();
    let command_counts_for_task = command_counts.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((socket, _)) = accepted else { break; };
                    let acceptor = acceptor.clone();
                    let ping_count = ping_count_for_task.clone();
                    let command_counts = command_counts_for_task.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(socket).await else {
                            return;
                        };
                        loop {
                            let Ok(frame) = read_resp_array(&mut tls).await else {
                                break;
                            };
                            let Some(frame) = frame else {
                                break;
                            };
                            if frame.is_empty() {
                                let _ = tls.write_all(b"-ERR empty command\r\n").await;
                                continue;
                            }

                            let command = uppercase(&frame[0]);
                            {
                                let mut counts = command_counts.lock();
                                *counts.entry(command.clone()).or_insert(0) += 1;
                            }
                            match command.as_str() {
                                "AUTH" => {
                                    if tls.write_all(b"+OK\r\n").await.is_err() {
                                        break;
                                    }
                                }
                                "PING" => {
                                    ping_count.fetch_add(1, Ordering::Relaxed);
                                    if tls.write_all(b"+PONG\r\n").await.is_err() {
                                        break;
                                    }
                                }
                                "MULTI" | "EXEC" | "BLPOP" | "SUBSCRIBE" | "RESET" => {
                                    if tls.write_all(b"+OK\r\n").await.is_err() {
                                        break;
                                    }
                                }
                                _ => {
                                    if tls.write_all(b"-ERR unsupported command\r\n").await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    });

    Ok(UpstreamFixture {
        addr,
        ping_count,
        command_counts,
        shutdown_tx: Some(shutdown_tx),
    })
}

async fn send_command_expect_simple<S>(stream: &mut S, parts: &[&str], expected_simple: &str)
where
    S: AsyncRead + AsyncWriteExt + Unpin,
{
    send_resp_command(stream, parts)
        .await
        .expect("write RESP command");
    let line = read_line(stream).await.expect("read simple response line");
    let expected = expected_simple
        .strip_prefix('+')
        .unwrap_or(expected_simple)
        .to_string();
    let actual = line.strip_prefix('+').unwrap_or(&line).to_string();
    assert_eq!(actual, expected, "unexpected response for {parts:?}");
}

async fn send_resp_command<S>(stream: &mut S, parts: &[&str]) -> io::Result<()>
where
    S: AsyncWriteExt + Unpin,
{
    let mut payload = Vec::new();
    payload.extend_from_slice(format!("*{}\r\n", parts.len()).as_bytes());
    for part in parts {
        payload.extend_from_slice(format!("${}\r\n", part.len()).as_bytes());
        payload.extend_from_slice(part.as_bytes());
        payload.extend_from_slice(b"\r\n");
    }
    stream.write_all(&payload).await
}

async fn read_resp_array<R>(reader: &mut R) -> io::Result<Option<Vec<Vec<u8>>>>
where
    R: AsyncRead + Unpin,
{
    let mut first = [0u8; 1];
    let n = reader.read(&mut first).await?;
    if n == 0 {
        return Ok(None);
    }
    if first[0] != b'*' {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected array frame",
        ));
    }

    let count = read_line_i64(reader).await?;
    let count: usize = usize::try_from(count).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid array count: {count}"),
        )
    })?;

    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        let mut marker = [0u8; 1];
        reader.read_exact(&mut marker).await?;
        if marker[0] != b'$' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected bulk string frame",
            ));
        }

        let len = read_line_i64(reader).await?;
        let len: usize = usize::try_from(len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid bulk length: {len}"),
            )
        })?;

        let mut bytes = vec![0u8; len];
        reader.read_exact(&mut bytes).await?;

        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        if crlf != [b'\r', b'\n'] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bulk payload missing CRLF",
            ));
        }

        parts.push(bytes);
    }

    Ok(Some(parts))
}

async fn read_line_i64<R>(reader: &mut R) -> io::Result<i64>
where
    R: AsyncRead + Unpin,
{
    let line = read_line(reader).await?;
    line.parse::<i64>().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid RESP number {line:?}: {err}"),
        )
    })
}

async fn read_line<R>(reader: &mut R) -> io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut out = Vec::new();
    loop {
        let mut b = [0u8; 1];
        reader.read_exact(&mut b).await?;
        out.push(b[0]);
        if out.len() >= 2 && out[out.len() - 2..] == [b'\r', b'\n'] {
            out.truncate(out.len() - 2);
            return String::from_utf8(out).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("non UTF-8 RESP line: {err}"),
                )
            });
        }
    }
}

fn uppercase(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input {
        out.push(char::from(byte).to_ascii_uppercase());
    }
    out
}

fn build_downstream_connector(pki: &TestPki) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(pki.ca.cert_der.clone()))
        .expect("add CA cert to downstream roots");

    let certs = vec![CertificateDer::from(pki.downstream_client.cert_der.clone())];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        pki.downstream_client.key_der.clone(),
    ));

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .expect("build downstream client config");
    TlsConnector::from(Arc::new(config))
}

fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read ephemeral port")
        .port()
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

struct ChildGuard {
    child: *mut Child,
}

impl ChildGuard {
    fn new(child: &mut Child) -> Self {
        Self {
            child: child as *mut Child,
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // SAFETY: child pointer is valid for the whole test scope where this guard lives.
        let child = unsafe { &mut *self.child };
        let _ = child.kill();
        let _ = child.wait();
    }
}

struct TestPki {
    _dir: TempDir,
    acl_path: PathBuf,
    ca_cert_path: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    upstream_client_cert_path: PathBuf,
    upstream_client_key_path: PathBuf,
    ca: GeneratedCert,
    downstream_client: GeneratedCert,
    upstream_server: GeneratedCert,
}

impl TestPki {
    fn generate() -> io::Result<Self> {
        let dir = tempfile::tempdir()?;

        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "dfguard-test-ca");
        let ca_key = KeyPair::generate().map_err(to_io_err)?;
        let ca_cert = ca_params.self_signed(&ca_key).map_err(to_io_err)?;
        let ca = export_generated_cert(&ca_cert, &ca_key);

        let proxy_server =
            generate_signed_cert(&ca_cert, &ca_key, "dfguard-proxy", &["localhost"])?;
        let downstream_client =
            generate_signed_cert(&ca_cert, &ca_key, "load-user", &["load-user"])?;
        let upstream_client =
            generate_signed_cert(&ca_cert, &ca_key, "dfguard-upstream-client", &["proxy"])?;
        let upstream_server =
            generate_signed_cert(&ca_cert, &ca_key, "mock-upstream", &["localhost"])?;

        let acl_path = write_text(
            dir.path(),
            "acl.conf",
            "USER load-user ON >loadsecret +@all ~*\n",
        )?;
        let ca_cert_path = write_text(dir.path(), "ca.crt", &ca.cert_pem)?;
        let server_cert_path = write_text(dir.path(), "server.crt", &proxy_server.cert_pem)?;
        let server_key_path = write_text(dir.path(), "server.key", &proxy_server.key_pem)?;
        let upstream_client_cert_path =
            write_text(dir.path(), "upstream-client.crt", &upstream_client.cert_pem)?;
        let upstream_client_key_path =
            write_text(dir.path(), "upstream-client.key", &upstream_client.key_pem)?;

        Ok(Self {
            _dir: dir,
            acl_path,
            ca_cert_path,
            server_cert_path,
            server_key_path,
            upstream_client_cert_path,
            upstream_client_key_path,
            ca,
            downstream_client,
            upstream_server,
        })
    }
}

fn write_text(dir: &Path, name: &str, contents: &str) -> io::Result<PathBuf> {
    let path = dir.join(name);
    std::fs::write(&path, contents)?;
    Ok(path)
}

struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

fn generate_signed_cert(
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    common_name: &str,
    sans: &[&str],
) -> io::Result<GeneratedCert> {
    let mut params = CertificateParams::new(
        sans.iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
    )
    .map_err(to_io_err)?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::NoCa;

    let key = KeyPair::generate().map_err(to_io_err)?;
    let cert = params.signed_by(&key, ca_cert, ca_key).map_err(to_io_err)?;
    Ok(export_generated_cert(&cert, &key))
}

fn export_generated_cert(cert: &Certificate, key: &KeyPair) -> GeneratedCert {
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().to_vec(),
        key_der: key.serialize_der(),
    }
}

fn to_io_err(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(err.to_string())
}
