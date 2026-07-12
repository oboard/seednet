//! BitTorrent Mainline DHT peer discovery for SeedNet.
//!
//! SeedNet uses the DHT **only** to find other devices sharing the same seed.
//! It is not a BitTorrent client: no torrents, no magnet links, no pieces, no
//! trackers, no file transfer.
//!
//! ## How it works
//!
//! 1. The network [`NetworkSecret`](seednet_common::NetworkSecret) is hashed
//!    (SHA-1) into a 20-byte [`InfoHash`](seednet_common::InfoHash).
//! 2. Each device **announces** itself under that infohash, advertising the UDP
//!    port it listens on for SeedNet traffic.
//! 3. Each device periodically **looks up** the same infohash to discover the
//!    `SocketAddr`s of other devices.
//!
//! ## Crate choice
//!
//! This wraps the [`mainline`](https://crates.io/crates/mainline) crate
//! (v7.0.0), the actively maintained successor to the now-removed
//! `bittorrent-dht`. It provides the exact BEP_0005 Mainline DHT
//! announce/get-peers API SeedNet needs, fully async.

use std::net::SocketAddr;
use std::net::SocketAddrV4;

use futures_lite::StreamExt as _;
use mainline::async_dht::AsyncDht;
use mainline::{Dht, Id};
use seednet_common::{Error, InfoHash, Result};

/// A discovered peer's transport address. Today we learn only the address from
/// the DHT (BEP_0005 announces carry no extra payload); the peer's [`PeerId`]
/// is exchanged later during the Noise XX handshake.
pub type PeerAddr = SocketAddr;

/// SeedNet's DHT discovery engine. Owns a [`mainline`] async DHT node.
///
/// Cloneable and cheap to share across tasks (the underlying DHT runs on its
/// own actor thread; the [`AsyncDht`] handle is a thin channel wrapper).
#[derive(Clone)]
pub struct DhtDiscovery {
    dht: AsyncDht,
}

impl std::fmt::Debug for DhtDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtDiscovery").finish_non_exhaustive()
    }
}

impl DhtDiscovery {
    /// Start a DHT node bound to `0.0.0.0:port`, joining the public Mainline
    /// network using the default bootstrap nodes.
    pub fn start(port: u16) -> Result<Self> {
        let dht = Dht::builder()
            .port(port)
            .build()
            .map_err(|e| Error::Dht(format!("bind failed: {e}")))?
            .as_async();
        Ok(Self { dht })
    }

    /// Start a DHT node for tests/local networks using an explicit list of
    /// bootstrap `host:port` strings and binding to a specific address.
    pub fn start_with(
        port: u16,
        bind: std::net::Ipv4Addr,
        bootstrap: &[String],
    ) -> Result<Self> {
        let mut builder = Dht::builder();
        builder.port(port).bind_address(bind);
        if !bootstrap.is_empty() {
            builder.bootstrap(bootstrap);
        }
        let dht = builder
            .build()
            .map_err(|e| Error::Dht(format!("bind failed: {e}")))?
            .as_async();
        Ok(Self { dht })
    }

    /// Access the underlying [`AsyncDht`] for advanced use.
    pub fn raw(&self) -> &AsyncDht {
        &self.dht
    }

    /// Block until the node has bootstrapped (knows at least one close node).
    /// Returns `true` if bootstrapping succeeded.
    pub async fn bootstrapped(&self) -> bool {
        self.dht.bootstrapped().await
    }

    /// Announce this device under `info_hash`, advertising `listen_port` as the
    /// UDP port other SeedNet devices should contact.
    ///
    /// Uses `Some(port)` (explicit) rather than implied-port mode so that we
    /// work correctly even when the DHT socket and the SeedNet transport
    /// socket differ (they may, once NAT traversal is in place).
    pub async fn announce(&self, info_hash: &InfoHash, listen_port: u16) -> Result<()> {
        let id = id_from_infohash(info_hash)?;
        self.dht
            .announce_peer(id, Some(listen_port))
            .await
            .map_err(|e| Error::Dht(format!("announce failed: {e}")))?;
        Ok(())
    }

    /// Look up peers announced under `info_hash`. Collects all peer addresses
    /// observed on the stream until it ends (the `mainline` stream completes
    /// once the lookup query is done).
    pub async fn lookup(&self, info_hash: &InfoHash) -> Result<Vec<PeerAddr>> {
        let id = id_from_infohash(info_hash)?;
        let mut stream = self.dht.get_peers(id);
        let mut out: Vec<PeerAddr> = Vec::new();
        while let Some(batch) = stream.next().await {
            for sa in batch {
                out.push(SocketAddr::V4(SocketAddrV4::new(*sa.ip(), sa.port())));
            }
        }
        // De-duplicate while preserving a stable order.
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Run a discovery cycle: announce, then lookup. Convenience wrapper used
    /// by the CLI `discover` command and by the orchestration loop later.
    pub async fn discover(
        &self,
        info_hash: &InfoHash,
        listen_port: u16,
    ) -> Result<Vec<PeerAddr>> {
        self.announce(info_hash, listen_port).await?;
        self.lookup(info_hash).await
    }
}

/// Convert a SeedNet [`InfoHash`] (20 raw bytes) into a mainline [`Id`].
fn id_from_infohash(info_hash: &InfoHash) -> Result<Id> {
    Id::from_bytes(info_hash.as_bytes())
        .map_err(|e| Error::Dht(format!("invalid infohash length: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use seednet_crypto::{derive_infohash, derive_network_secret};
    use seednet_common::Seed;

    #[test]
    fn id_from_infohash_is_infallible_for_20_bytes() {
        let secret = derive_network_secret(&Seed::from_passphrase("test"));
        let ih = derive_infohash(&secret);
        let id = id_from_infohash(&ih).expect("20-byte infohash must convert");
        let back: [u8; 20] = id.into();
        assert_eq!(back.as_slice(), ih.as_bytes());
    }

    /// End-to-end local test: two DHT nodes on a private `Testnet`-style local
    /// bootstrap. We start a "server" node on an ephemeral port to act as the
    /// only bootstrap node, then verify announce→lookup between two others.
    ///
    /// This avoids depending on the public Internet DHT for CI reliability.
    #[tokio::test(flavor = "current_thread")]
    async fn two_nodes_discover_each_other_locally() {
        // 1. Spin a bootstrap-only DHT node on an ephemeral localhost port.
        let bootstrap_node = Dht::builder()
            .bind_address(std::net::Ipv4Addr::LOCALHOST)
            .server_mode()
            .build()
            .expect("bootstrap bind")
            .as_async();
        let bootstrap_addr = bootstrap_node
            .info()
            .await
            .local_addr()
            .to_string();
        // Give the bootstrap node a moment to be ready.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let secret = derive_network_secret(&Seed::from_passphrase("local-test"));
        let info_hash = derive_infohash(&secret);

        // 2. Announcer
        let announcer = DhtDiscovery::start_with(
            0,
            std::net::Ipv4Addr::LOCALHOST,
            std::slice::from_ref(&bootstrap_addr),
        )
        .expect("announcer start");
        announcer.bootstrapped().await;
        announcer
            .announce(&info_hash, 4242)
            .await
            .expect("announce");

        // 3. Looker
        let looker = DhtDiscovery::start_with(
            0,
            std::net::Ipv4Addr::LOCALHOST,
            &[bootstrap_addr],
        )
        .expect("looker start");
        looker.bootstrapped().await;

        // Allow DHT propagation.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        let peers = looker.lookup(&info_hash).await.expect("lookup");
        assert!(
            peers.iter().any(|p| p.port() == 4242),
            "expected to discover the announced peer (port 4242), got {peers:?}"
        );

        // Keep the bootstrap node alive until the end of the test.
        drop(bootstrap_node);
        drop(announcer);
        drop(looker);
    }
}
