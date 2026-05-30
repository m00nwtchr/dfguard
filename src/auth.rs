use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

pub async fn send_auth(
    upstream: &mut TlsStream<TcpStream>,
    user: &str,
    password: Option<&str>,
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

pub fn build_auth_command(user: &str, password: Option<&str>) -> Vec<u8> {
    if let Some(password) = password {
        let mut out = Vec::with_capacity(64 + user.len() + password.len());
        out.extend_from_slice(b"*3\r\n");
        push_bulk(&mut out, b"AUTH");
        push_bulk(&mut out, user.as_bytes());
        push_bulk(&mut out, password.as_bytes());
        out
    } else {
        let mut out = Vec::with_capacity(48 + user.len());
        out.extend_from_slice(b"*2\r\n");
        push_bulk(&mut out, b"AUTH");
        push_bulk(&mut out, user.as_bytes());
        out
    }
}

fn push_bulk(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(b"$");
    out.extend_from_slice(data.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

pub fn extract_dns_user(tls: &tokio_rustls::server::TlsStream<TcpStream>) -> Result<String> {
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

fn find_crlf(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}
