use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    Proxy(ProxyConfig),
    Tunnel(TunnelConfig),
}

#[derive(Parser, Debug, Clone)]
#[command(name = "dfguard", version, about = "mTLS auth proxy for DragonflyDB")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Parser, Debug, Clone)]
pub struct ProxyConfig {
    #[arg(long, env = "DFGUARD_PROXY_LISTEN", default_value = "[::]:6379")]
    pub listen: SocketAddr,
    #[arg(long, env = "DFGUARD_PROXY_UPSTREAM")]
    pub upstream: String,
    #[arg(long, value_name = "FILE", env = "DFGUARD_PROXY_ACL")]
    pub acl: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_PROXY_SERVER_CERT")]
    pub server_cert: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_PROXY_SERVER_KEY")]
    pub server_key: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_PROXY_SERVER_CA")]
    pub server_ca: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_PROXY_UPSTREAM_CERT")]
    pub upstream_cert: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_PROXY_UPSTREAM_KEY")]
    pub upstream_key: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_PROXY_UPSTREAM_CA")]
    pub upstream_ca: PathBuf,
    #[arg(
        long,
        env = "DFGUARD_PROXY_HANDSHAKE_TIMEOUT_SECS",
        default_value = "10"
    )]
    pub handshake_timeout_secs: u64,
    #[arg(long, env = "DFGUARD_PROXY_IDLE_TIMEOUT_SECS", default_value = "0")]
    pub idle_timeout_secs: u64,
    #[arg(long, env = "DFGUARD_PROXY_MAX_FRAME_SIZE", default_value = "16777216")]
    pub max_frame_size: usize,
    #[arg(
        long,
        env = "DFGUARD_PROXY_POOL_MAX_IDLE_PER_USER",
        default_value = "64"
    )]
    pub pool_max_idle_per_user: usize,
    #[arg(long, env = "DFGUARD_PROXY_INSECURE_UPSTREAM", default_value_t = false)]
    pub insecure_upstream: bool,
    #[arg(long, env = "DFGUARD_PROXY_METRICS_LISTEN")]
    pub metrics_listen: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct TunnelConfig {
    #[arg(long, env = "DFGUARD_TUNNEL_LISTEN", default_value = "[::1]:6379")]
    pub listen: SocketAddr,
    #[arg(long, env = "DFGUARD_TUNNEL_UPSTREAM")]
    pub upstream: String,
    #[arg(long, value_name = "FILE", env = "DFGUARD_TUNNEL_CERT")]
    pub cert: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_TUNNEL_KEY")]
    pub key: PathBuf,
    #[arg(long, value_name = "FILE", env = "DFGUARD_TUNNEL_CA")]
    pub ca: PathBuf,
    #[arg(long, env = "DFGUARD_TUNNEL_TCP_NODELAY", default_value_t = false)]
    pub tcp_nodelay: bool,
    #[arg(
        long,
        env = "DFGUARD_TUNNEL_CONNECT_TIMEOUT_SECS",
        default_value = "10"
    )]
    pub connect_timeout_secs: u64,
    #[arg(
        long,
        env = "DFGUARD_TUNNEL_SHUTDOWN_TIMEOUT_SECS",
        default_value = "30"
    )]
    pub shutdown_timeout_secs: u64,
    #[arg(long, env = "DFGUARD_TUNNEL_METRICS_LISTEN")]
    pub metrics_listen: Option<String>,
}
