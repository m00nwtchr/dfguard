use std::collections::HashMap;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use notify::{RecursiveMode, Watcher};
use tokio::sync::{mpsc, watch};
use tracing::{Instrument, debug, error, info, info_span};

use crate::cli::ProxyConfig;
use crate::telemetry::Telemetry;
use crate::tls::build_client_config;
use crate::tls::build_server_config;
use crate::types::AclEntry;
use crate::types::ClientConfigs;

pub fn load_acl(path: &Path) -> Result<HashMap<String, AclEntry>> {
    let file = File::open(path).with_context(|| format!("open ACL file {}", path.display()))?;
    let reader = BufReader::new(file);
    parse_acl_lines(reader.lines())
}

pub fn parse_acl_lines<I>(lines: I) -> Result<HashMap<String, AclEntry>>
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
        if tokens.len() < 2 {
            bail!("invalid ACL line {}: expected 'USER <name>'", line_num + 1);
        }
        if !tokens[0].eq_ignore_ascii_case("USER") {
            bail!(
                "invalid ACL line {}: only USER entries are supported",
                line_num + 1
            );
        }
        let user = tokens[1].to_string();
        let mut password: Option<String> = None;
        let mut saw_nopass = false;
        for token in tokens.iter().skip(2) {
            if let Some(rest) = token.strip_prefix('>')
                && !rest.is_empty()
            {
                password = Some(rest.to_string());
            }
            if token.eq_ignore_ascii_case("nopass") {
                saw_nopass = true;
            }
        }
        if !saw_nopass && password.is_none() {
            bail!("invalid ACL line {}: missing password", line_num + 1);
        }

        if map.contains_key(&user) {
            bail!("duplicate ACL entry for user {user}");
        }
        map.insert(user, AclEntry { password });
    }

    Ok(map)
}

pub fn start_acl_watcher(
    path: std::path::PathBuf,
    acl_tx: watch::Sender<Arc<HashMap<String, AclEntry>>>,
    telemetry: Arc<Telemetry>,
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
            debug!("ACL change detected, reloading");
            tokio::time::sleep(Duration::from_millis(200)).await;
            match async { load_acl(&path) }
                .instrument(info_span!("acl_reload", path = %path.display()))
                .await
            {
                Ok(map) => {
                    telemetry.set_acl_entries(map.len());
                    let _ = acl_tx.send(Arc::new(map));
                    telemetry.reload_event("acl", "success");
                    info!("ACL reloaded");
                }
                Err(err) => {
                    telemetry.connection_error("reload", "downstream");
                    telemetry.reload_event("acl", "error");
                    error!("ACL reload failed: {err:#}");
                }
            }
        }
    });

    Ok(watcher)
}

pub fn start_tls_watcher(
    config: Arc<ProxyConfig>,
    server_tx: watch::Sender<Arc<rustls::ServerConfig>>,
    client_tx: watch::Sender<Arc<ClientConfigs>>,
    telemetry: Arc<Telemetry>,
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
            debug!("TLS change detected, reloading");
            tokio::time::sleep(Duration::from_millis(200)).await;
            match async { build_server_config(config.as_ref()) }
                .instrument(info_span!("tls_reload_server"))
                .await
            {
                Ok(server_config) => {
                    let _ = server_tx.send(Arc::new(server_config));
                    telemetry.reload_event("tls_server", "success");
                    info!("server TLS config reloaded");
                }
                Err(err) => {
                    telemetry.connection_error("reload", "downstream");
                    telemetry.reload_event("tls_server", "error");
                    error!("server TLS reload failed: {err:#}");
                }
            }

            match async {
                (
                    build_client_config(config.as_ref(), false),
                    build_client_config(config.as_ref(), true),
                )
            }
            .instrument(info_span!("tls_reload_upstream"))
            .await
            {
                (Ok(with_resumption), Ok(no_resumption)) => {
                    let configs = ClientConfigs {
                        with_resumption: Arc::new(with_resumption),
                        no_resumption: Arc::new(no_resumption),
                    };
                    let _ = client_tx.send(Arc::new(configs));
                    telemetry.set_tls_resumption_enabled(true);
                    telemetry.reload_event("tls_upstream", "success");
                    info!("upstream TLS config reloaded");
                }
                (Err(err), _) | (_, Err(err)) => {
                    telemetry.connection_error("reload", "upstream");
                    telemetry.reload_event("tls_upstream", "error");
                    error!("upstream TLS reload failed: {err:#}");
                }
            }
        }
    });

    Ok(watcher)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(command: &str, args: &[&str]) -> crate::protocol::FrameInfo {
        crate::protocol::FrameInfo {
            len: 0,
            is_auth: false,
            command: command.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        }
    }
    fn acl_last_password_wins() {
        let input = vec![
            Ok("USER svc ON >first >second +@all ~*".to_string()),
            Ok("# comment".to_string()),
        ];
        let map = parse_acl_lines(input.into_iter()).expect("parse ACL");
        assert_eq!(
            map.get("svc").and_then(|entry| entry.password.as_deref()),
            Some("second")
        );
    }

    #[test]
    fn acl_duplicate_user_errors() {
        let input = vec![
            Ok("USER svc ON >one +@all ~*".to_string()),
            Ok("USER svc ON >two +@all ~*".to_string()),
        ];
        let err = parse_acl_lines(input.into_iter()).expect_err("duplicate user should error");
        assert!(err.to_string().contains("duplicate ACL entry"));
    }

    #[test]
    fn acl_namespace_token_supported() {
        let input = vec![Ok(
            "USER user1 NAMESPACE:namespace1 ON >user_pass +@all ~*".to_string()
        )];
        let map = parse_acl_lines(input.into_iter()).expect("parse ACL");
        assert_eq!(
            map.get("user1").and_then(|entry| entry.password.as_deref()),
            Some("user_pass")
        );
    }

    #[test]
    fn acl_rejects_setuser_format() {
        let input = vec![Ok("ACL SETUSER user1 ON >user_pass +@all ~*".to_string())];
        let err = parse_acl_lines(input.into_iter()).expect_err("invalid ACL format should error");
        assert!(err.to_string().contains("only USER entries are supported"));
    }
}
