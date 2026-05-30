use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{Context, Result, anyhow};

pub fn parse_host_port(input: &str) -> Result<(String, u16)> {
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

pub fn resolve_addr(addr: &str) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .context("resolve upstream address")?
        .collect();
    addrs
        .into_iter()
        .find(SocketAddr::is_ipv4)
        .ok_or_else(|| anyhow!("no IPv4 address resolved"))
}

pub fn parse_server_name(host: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Ok(rustls::pki_types::ServerName::IpAddress(ip.into())),
        Err(_) => rustls::pki_types::ServerName::try_from(host.to_string())
            .context("invalid upstream hostname for TLS"),
    }
}

pub fn should_retry_without_resumption(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(rustls::Error::AlertReceived(desc)) = cause.downcast_ref::<rustls::Error>()
            && *desc == rustls::AlertDescription::InternalError
        {
            return true;
        }
    }
    err.to_string().contains("InternalError")
}

pub fn is_tls_handshake_eof(err: &dyn std::error::Error) -> bool {
    let mut current: Option<&dyn std::error::Error> = Some(err);
    while let Some(cause) = current {
        if cause.to_string().contains("tls handshake eof") {
            return true;
        }
        current = cause.source();
    }
    false
}
