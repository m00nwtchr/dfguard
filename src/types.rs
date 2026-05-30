use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use bytes::BytesMut;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;

use crate::telemetry::Telemetry;

#[derive(Clone, Debug)]
pub struct AclEntry {
    pub password: Option<String>,
}

#[derive(Clone)]
pub struct ClientConfigs {
    pub with_resumption: Arc<rustls::ClientConfig>,
    pub no_resumption: Arc<rustls::ClientConfig>,
}

#[derive(Clone)]
pub struct UpstreamPool {
    pub idle: Arc<parking_lot::Mutex<std::collections::HashMap<PoolKey, Vec<UpstreamConn>>>>,
    pub upstream_addr: std::net::SocketAddr,
    pub server_name: ServerName<'static>,
    pub handshake_timeout: Duration,
    pub max_idle_per_user: usize,
    pub client_rx: watch::Receiver<Arc<ClientConfigs>>,
    pub resumption_enabled: Arc<AtomicBool>,
    pub telemetry: Arc<Telemetry>,
}

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct PoolKey {
    pub user: String,
}

pub struct UpstreamConn {
    pub tls: TlsStream<TcpStream>,
    pub read_buf: BytesMut,
}

#[derive(Default)]
pub struct SessionState {
    pub txn: TxnState,
    pub watch: WatchState,
    pub tracking: TrackingState,
    pub blocking: BlockingState,
    pub sticky: StickyState,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum TxnState {
    #[default]
    None,
    InMulti,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum WatchState {
    #[default]
    Off,
    On,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum TrackingState {
    #[default]
    Off,
    On,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum BlockingState {
    #[default]
    Idle,
    Waiting,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum StickyState {
    #[default]
    Off,
    On,
}

impl SessionState {
    pub fn can_unpin(&self) -> bool {
        self.txn == TxnState::None
            && self.watch == WatchState::Off
            && self.tracking == TrackingState::Off
            && self.sticky == StickyState::Off
            && self.blocking == BlockingState::Idle
    }
}

pub struct PinnedConn {
    pub conn: UpstreamConn,
    pub state: SessionState,
    pub pinned_at: PinnedAt,
}

pub enum RouteState {
    Stateless,
    Pinned(Box<PinnedConn>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandClass {
    Stateless,
    PinTemporary,
    PinForever,
    PinWhileBlocking,
}

impl CommandClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stateless => "stateless",
            Self::PinTemporary => "pin_temporary",
            Self::PinForever => "pin_forever",
            Self::PinWhileBlocking => "pin_while_blocking",
        }
    }
}

#[derive(Clone, Copy)]
pub enum PoolDropReason {
    ReadBufNotEmpty,
    PoolFull,
}

impl PoolDropReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadBufNotEmpty => "read_buf_not_empty",
            Self::PoolFull => "pool_full",
        }
    }
}

pub struct PinnedAt {
    pub started: Instant,
}

pub struct FrameInfo {
    pub len: usize,
    pub is_auth: bool,
    pub command: String,
    pub args: Vec<String>,
}
