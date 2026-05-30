#![warn(clippy::pedantic, clippy::disallowed_types)]

mod auth;
mod cli;
mod metrics_server;
mod protocol;
mod proxy;
mod telemetry;
mod tls;
mod tunnel;
mod types;
mod utils;
mod watcher;

use clap::Parser;
use cli::{Cli, Commands};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Proxy(config)) => proxy::run_proxy(config).await,
        Some(Commands::Tunnel(config)) => tunnel::run_tunnel(config).await,
        None => {
            let config = cli::ProxyConfig::parse();
            proxy::run_proxy(config).await
        }
    }
}
