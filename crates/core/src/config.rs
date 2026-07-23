use crate::trackers::DEFAULT_TRACKERS;
use seednet_common::Seed;
use seednet_config::StateDir;

pub struct SeedNetConfig {
    pub seed: Seed,
    pub port: u16,
    pub state_dir: StateDir,
    /// Which transport protocols to enable. Defaults to all.
    pub transports: Vec<seednet_transport::TransportKind>,
    /// BitTorrent tracker URLs (HTTP or UDP) to announce to and discover
    /// peers from. Faster than DHT for initial connection.
    /// Example: "udp://tracker.opentrackr.org:1337"
    pub tracker_urls: Vec<String>,
    /// Known direct peer addresses to connect to immediately on startup
    /// (bypasses DHT and tracker latency entirely).
    pub direct_peers: Vec<std::net::SocketAddr>,
}

impl SeedNetConfig {
    pub fn new(seed: Seed, port: u16, state_dir: StateDir) -> Self {
        Self {
            seed,
            port,
            state_dir,
            transports: vec![
                seednet_transport::TransportKind::Udp,
                seednet_transport::TransportKind::Tcp,
                seednet_transport::TransportKind::Ws,
            ],
            tracker_urls: DEFAULT_TRACKERS.iter().map(|s| s.to_string()).collect(),
            direct_peers: Vec::new(),
        }
    }
}
