use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use seednet_common::{Error, STUN_SERVERS};

use seednet_dht::DhtDiscovery;
use seednet_nat::is_publicly_routable;
use seednet_peer::Message;
use seednet_transport::{MultiTransport, Transport, UdpTransport};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

mod config;
mod discovery;
mod engine;
mod handshake;
mod inbound;
mod net;
mod outbound;
mod peers_snapshot;
mod trackers;

pub use config::SeedNetConfig;
pub use engine::SeedNetEngine;

use engine::{AddrIndex, RelayCandidates, RelayPaths, Sessions};
use net::{local_hostname, local_public_ip};

const DHT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const PEER_DIRECTORY_BROADCAST_INTERVAL: Duration = Duration::from_secs(30);

impl SeedNetEngine {
    pub async fn run(&self) -> std::result::Result<(), Error> {
        let port = self.config.port;

        tracing::info!(
            target: "seednet",
            infohash = %self.infohash,
            overlay = %self.our_overlay,
            peer_id = %self.our_peer_id.short(),
            port,
            "SeedNet engine starting"
        );

        let our_hostname = local_hostname();
        let our_overlay_si = self.our_overlay;
        let our_overlay_ipv6_si = self.our_overlay_ipv6;
        let our_hostname_si = our_hostname;

        let mut alloc_table = self.allocation_table.write().await;
        alloc_table.allocate(self.our_peer_id);
        drop(alloc_table);

        let tun_config =
            seednet_tun::TunConfig::new(self.our_overlay).with_ipv6(self.our_overlay_ipv6);
        let tun_device = seednet_tun::AsyncTunDevice::create(&tun_config)?;
        let tun_name = tun_device.name().to_string();
        let (tun_reader, tun_writer, _) = tun_device.into_split();
        let tun_writer = Arc::new(Mutex::new(tun_writer));

        if let Err(e) = seednet_tun::platform::configure_interface_full(
            &tun_name,
            self.our_overlay.ip(),
            seednet_tun::subnet_mask(seednet_common::OVERLAY_SUBNET_PREFIX),
            Some(&tun_config),
        )
        .await
        {
            tracing::warn!(target: "seednet", error = %e, "platform IP config failed (may need manual ifconfig/ip)");
        }

        // Bind UDP socket with port fallback.
        let udp_socket = {
            let mut last_err = None;
            let mut bound = None;
            for offset in 0u16..10 {
                let try_port = port.saturating_add(offset);
                match UdpSocket::bind(format!("0.0.0.0:{try_port}")).await {
                    Ok(sock) => {
                        // Increase UDP receive buffer to 16 MiB to handle burst traffic.
                        // Uses SO_RCVBUFFORCE (root) to bypass system limit, falls back to SO_RCVBUF.
                        #[cfg(unix)]
                        {
                            use std::os::unix::io::AsRawFd;
                            let fd = sock.as_raw_fd();
                            let rcvbuf: libc::c_int = 16 * 1024 * 1024;
                            unsafe {
                                // SO_RCVBUFFORCE = 33 on Linux (bypasses rmem_max limit, requires root).
                                // Falls back to SO_RCVBUF if not privileged.
                                const SO_RCVBUFFORCE: libc::c_int = 33;
                                let r = libc::setsockopt(
                                    fd,
                                    libc::SOL_SOCKET,
                                    SO_RCVBUFFORCE,
                                    &rcvbuf as *const _ as *const libc::c_void,
                                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                                );
                                if r != 0 {
                                    libc::setsockopt(
                                        fd,
                                        libc::SOL_SOCKET,
                                        libc::SO_RCVBUF,
                                        &rcvbuf as *const _ as *const libc::c_void,
                                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                                    );
                                }
                            }
                        }
                        if offset > 0 {
                            tracing::info!(
                                target: "seednet",
                                preferred = port,
                                actual = try_port,
                                "preferred port in use, bound to next available port",
                            );
                        }
                        bound = Some(sock);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            bound.ok_or_else(|| Error::Io(last_err.unwrap()))?
        };
        let udp_transport = UdpTransport::new(Arc::new(udp_socket));
        let bound_port = udp_transport.local_addr().socket_addr().port();
        tracing::info!(target: "seednet", port = bound_port, "UDP data socket bound");

        // Build MultiTransport.
        let mut builder = MultiTransport::builder().udp(udp_transport);
        let mut next_stream_port = bound_port;
        for kind in &self.config.transports {
            match kind {
                seednet_transport::TransportKind::Tcp => {
                    let mut bound = false;
                    for offset in 0u16..10 {
                        let try_port = next_stream_port.saturating_add(offset);
                        match seednet_transport::TcpTransport::bind(std::net::SocketAddr::from((
                            [0, 0, 0, 0],
                            try_port,
                        )))
                        .await
                        {
                            Ok(t) => {
                                tracing::info!(target: "seednet", port = try_port, "TCP listener bound");
                                builder = builder.tcp(t);
                                next_stream_port = try_port + 1;
                                bound = true;
                                break;
                            }
                            Err(_) if offset < 9 => continue,
                            Err(e) => {
                                tracing::warn!(target: "seednet", error = %e, "TCP bind failed after retries, skipping");
                            }
                        }
                    }
                    if !bound {
                        next_stream_port += 1;
                    }
                }
                seednet_transport::TransportKind::Ws => {
                    let mut bound = false;
                    for offset in 0u16..10 {
                        let try_port = next_stream_port.saturating_add(offset);
                        match seednet_transport::WsTransport::bind(std::net::SocketAddr::from((
                            [0, 0, 0, 0],
                            try_port,
                        )))
                        .await
                        {
                            Ok(t) => {
                                tracing::info!(target: "seednet", port = try_port, "WS listener bound");
                                builder = builder.ws(t);
                                next_stream_port = try_port + 1;
                                bound = true;
                                break;
                            }
                            Err(_) if offset < 9 => continue,
                            Err(e) => {
                                tracing::warn!(target: "seednet", error = %e, "WS bind failed after retries, skipping");
                            }
                        }
                    }
                    if !bound {
                        next_stream_port += 1;
                    }
                }
                _ => {}
            }
        }
        let transport = Arc::new(builder.build());

        // STUN + DHT + tracker discovery all run in the background so the engine
        // starts immediately without waiting for network round-trips.
        // stun_public_addr starts None and is updated once STUN completes.
        let stun_public_addr: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));
        // can_relay is set once STUN result is known; start as false.
        let can_relay_flag: Arc<std::sync::atomic::AtomicBool> =
            Arc::new(std::sync::atomic::AtomicBool::new(false));

        // tracker_addrs starts with direct_peers and gets tracker results appended async.
        let tracker_addrs: Arc<tokio::sync::Mutex<Vec<SocketAddr>>> =
            Arc::new(tokio::sync::Mutex::new(self.config.direct_peers.clone()));

        // Background STUN task — runs right after engine starts, before sessions are active.
        // stun_public_addr and can_relay_flag are updated when done.
        // Post-STUN PeerDirectory broadcast is deferred to after sessions are initialized.
        {
            let stun_addr = stun_public_addr.clone();
            let relay_flag = can_relay_flag.clone();
            let transport_stun = transport.clone();
            let port_for_stun = bound_port;
            tokio::spawn(async move {
                let mut addr = seednet_nat::stun::query_public_addr_with_fallback(
                    transport_stun.udp().unwrap().inner(),
                    STUN_SERVERS,
                )
                .await
                .ok();
                if addr.is_none() {
                    addr = local_public_ip(port_for_stun);
                }
                if let Some(a) = addr {
                    let cr = is_publicly_routable(a);
                    tracing::info!(target: "seednet", public_addr = %a, can_relay = cr, "public address discovered");
                    relay_flag.store(cr, std::sync::atomic::Ordering::Relaxed);
                    *stun_addr.write().await = Some(a);
                } else {
                    tracing::warn!(target: "seednet", "STUN discovery failed; hole-punching and relay will be limited");
                }
            });
        }

        let can_relay = can_relay_flag.load(std::sync::atomic::Ordering::Relaxed);
        let _ = can_relay; // used only for logging below

        // DHT background task — bootstraps, announces, then hands off to periodic re-announce.
        let dht = DhtDiscovery::start_with(0, std::net::Ipv4Addr::UNSPECIFIED, &[])
            .map_err(|e| Error::Dht(format!("DHT start failed: {e}")))?;

        let infohash_bytes: [u8; 20] = {
            let b = self.infohash.as_bytes();
            let mut arr = [0u8; 20];
            arr.copy_from_slice(b);
            arr
        };
        let peer_id_bytes: [u8; 20] = {
            let pk = self.our_peer_id.as_bytes();
            let mut id = [0u8; 20];
            id.copy_from_slice(&pk[..20]);
            id
        };

        // Background DHT bootstrap + announce.
        {
            let dht_bg = dht.clone();
            let infohash = self.infohash;
            let stun_addr = stun_public_addr.clone();
            tokio::spawn(async move {
                tracing::info!(target: "seednet", "DHT bootstrap starting (background)…");
                let bootstrapped =
                    tokio::time::timeout(Duration::from_secs(15), dht_bg.bootstrapped()).await;
                match bootstrapped {
                    Ok(true) => tracing::info!(target: "seednet", "DHT bootstrapped"),
                    Ok(false) => tracing::warn!(target: "seednet", "DHT bootstrap returned false"),
                    Err(_) => tracing::warn!(target: "seednet", "DHT bootstrap timed out after 15s"),
                }
                let ap = stun_addr.read().await.map(|a| a.port()).unwrap_or(bound_port);
                if let Err(e) = dht_bg.announce(&infohash, ap).await {
                    tracing::warn!(target: "seednet", error = %e, "DHT announce failed");
                } else {
                    tracing::info!(target: "seednet", port = ap, "Announced on DHT");
                }
            });
        }

        // Background tracker queries — appends discovered peers to tracker_addrs.
        if !self.config.tracker_urls.is_empty() {
            let urls = self.config.tracker_urls.clone();
            let addrs = tracker_addrs.clone();
            let ih = infohash_bytes;
            let pid = peer_id_bytes;
            tokio::spawn(async move {
                let mut futs = Vec::new();
                for url in urls {
                    let ih2 = ih;
                    let pid2 = pid;
                    futs.push(tokio::spawn(async move {
                        seednet_tracker::announce(&url, &ih2, &pid2, bound_port).await
                    }));
                }
                let mut discovered = Vec::new();
                for fut in futs {
                    if let Ok(peers) = fut.await {
                        discovered.extend(peers);
                    }
                }
                if !discovered.is_empty() {
                    let mut locked = addrs.lock().await;
                    for p in discovered {
                        if !locked.contains(&p) {
                            locked.push(p);
                        }
                    }
                    tracing::info!(target: "seednet", total = locked.len(), "tracker peers added to discovery");
                }
            });
        }

        let relay_candidates: RelayCandidates = Arc::new(DashMap::new());
        let relay_paths: RelayPaths = Arc::new(DashMap::new());
        let sessions: Sessions = Arc::new(DashMap::new());
        let addr_index: AddrIndex = Arc::new(DashMap::new());
        let pending_handshakes: Arc<
            RwLock<HashMap<SocketAddr, tokio::sync::oneshot::Sender<Vec<u8>>>>,
        > = Arc::new(RwLock::new(HashMap::new()));

        // Outbound TUN → network task.
        let outbound_handle = {
            let oa = outbound::OutboundArgs {
                routing_table: self.routing_table.clone(),
                sessions: sessions.clone(),
                transport: transport.clone(),
                our_overlay: self.our_overlay,
                our_peer_id: self.our_peer_id,
                tun_writer: tun_writer.clone(),
                relay_candidates: relay_candidates.clone(),
                relay_paths: relay_paths.clone(),
            };
            tokio::spawn(outbound::run_outbound_loop(oa, tun_reader))
        };

        // Inbound network → TUN / handshake task.
        let inbound_handle = {
            let ia = inbound::InboundArgs {
                tun_writer: tun_writer.clone(),
                transport: transport.clone(),
                sessions: sessions.clone(),
                addr_index: addr_index.clone(),
                pending: pending_handshakes.clone(),
                network_secret: self.network_secret,
                device_keys: self.device_keys.clone(),
                routing_table: self.routing_table.clone(),
                peer_mgr: self.peer_manager.clone(),
                stun_addr: stun_public_addr.clone(),
                si_overlay: our_overlay_si,
                si_overlay_ipv6: our_overlay_ipv6_si,
                si_hostname: our_hostname_si.clone(),
                relay_candidates: relay_candidates.clone(),
                relay_paths: relay_paths.clone(),
                our_peer_id: self.our_peer_id,
                can_relay_flag: can_relay_flag.clone(),
            };
            tokio::spawn(inbound::run_inbound_loop(ia))
        };

        // Discovery + per-peer handshake task.
        let infohash = self.infohash;
        let discovery_handle = {
            let da = discovery::DiscoveryArgs {
                dht: dht.clone(),
                infohash,
                tracker_addrs,
                transport: transport.clone(),
                sessions: sessions.clone(),
                addr_index: addr_index.clone(),
                stun_addr: stun_public_addr.clone(),
                pending: pending_handshakes.clone(),
                peer_mgr: self.peer_manager.clone(),
                routing_table: self.routing_table.clone(),
                relay_cands: relay_candidates.clone(),
                relay_paths: relay_paths.clone(),
                network_secret: self.network_secret,
                device_keys: self.device_keys.clone(),
                si_overlay: our_overlay_si,
                si_overlay_ipv6: our_overlay_ipv6_si,
                si_hostname: our_hostname_si.clone(),
                our_id: self.our_peer_id,
                can_relay_flag: can_relay_flag.clone(),
            };
            tokio::spawn(discovery::run_discovery_loop(da))
        };

        // Post-STUN PeerDirectory broadcast: once STUN completes and this node is confirmed
        // as a relay, broadcast PeerDirectory to all already-connected peers so they can
        // discover each other (handles the race where peers connected before STUN finished).
        {
            let relay_flag = can_relay_flag.clone();
            let sessions_ps = sessions.clone();
            let relay_paths_ps = relay_paths.clone();
            let peer_mgr_ps = self.peer_manager.clone();
            let transport_ps = transport.clone();
            let our_peer_id_ps = self.our_peer_id;
            let stun_addr_ps = stun_public_addr.clone();
            tokio::spawn(async move {
                // Wait up to 5s for STUN, then broadcast regardless.
                for _ in 0..10 {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    if stun_addr_ps.read().await.is_some() {
                        break;
                    }
                }
                // Broadcast whenever we have 2+ sessions — STUN success is not required.
                if sessions_ps.len() < 2 {
                    return;
                }
                let all_peers: Vec<(seednet_common::PeerId, std::net::SocketAddr, u8)> = {
                    let mut v: Vec<(seednet_common::PeerId, std::net::SocketAddr, u8)> =
                        sessions_ps
                            .iter()
                            .filter_map(|e| {
                                if let seednet_transport::TransportAddr::Udp(sa) = e.underlay {
                                    Some((*e.key(), sa, 1u8))
                                } else {
                                    None
                                }
                            })
                            .collect();
                    for entry in relay_paths_ps.iter() {
                        let rp_peer = *entry.key();
                        if rp_peer != our_peer_id_ps && !v.iter().any(|(id, _, _)| *id == rp_peer)
                        {
                            if let Some(p) = peer_mgr_ps.get(&rp_peer) {
                                if let Some(pub_addr) = p.public_addr().await {
                                    v.push((rp_peer, pub_addr, entry.value().1));
                                }
                            }
                        }
                    }
                    v
                };
                let peer_ids: Vec<seednet_common::PeerId> =
                    sessions_ps.iter().map(|e| *e.key()).collect();
                let mut notified = 0usize;
                for recipient in &peer_ids {
                    let entries: Vec<(seednet_common::PeerId, std::net::SocketAddr, u8)> =
                        all_peers
                            .iter()
                            .filter(|(id, _, _)| id != recipient)
                            .copied()
                            .collect();
                    if entries.is_empty() {
                        continue;
                    }
                    let dir = seednet_peer::message::serialize_message(
                        &seednet_peer::Message::PeerDirectory { entries },
                    );
                    if let Some(mut s) = sessions_ps.get_mut(recipient)
                        && let Ok(enc) = s.transport.encrypt(&dir)
                    {
                        let uaddr = s.underlay.clone();
                        drop(s);
                        let _ = transport_ps.send_to(&enc, uaddr).await;
                        notified += 1;
                    }
                }
                if notified > 0 {
                    tracing::info!(
                        target: "seednet",
                        peers = notified,
                        "post-STUN PeerDirectory broadcast to existing peers"
                    );
                }
            });
        }

        // Periodic DHT re-announce task.
        let stun_addr_announce = stun_public_addr.clone();
        let announce_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DHT_ANNOUNCE_INTERVAL);
            loop {
                interval.tick().await;
                let ap = stun_addr_announce
                    .read()
                    .await
                    .map(|a| a.port())
                    .unwrap_or(port);
                if let Err(e) = dht.announce(&infohash, ap).await {
                    tracing::debug!(target: "seednet", error = %e, "periodic DHT announce failed");
                }
            }
        });

        // Heartbeat task.
        let heartbeat_handle = {
            let sessions_hb = sessions.clone();
            let udp_hb = transport.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
                let heartbeat_payload =
                    seednet_peer::message::serialize_message(&Message::Heartbeat);
                loop {
                    interval.tick().await;
                    for mut entry in sessions_hb.iter_mut() {
                        let addr = entry.underlay.clone();
                        match entry.transport.encrypt(&heartbeat_payload) {
                            Ok(encrypted) => {
                                let _ = udp_hb.send_to(&encrypted, addr).await;
                            }
                            Err(e) => {
                                tracing::debug!(target: "seednet", peer = %entry.key().short(), error = %e, "heartbeat encrypt failed");
                            }
                        }
                    }
                }
            })
        };

        // Periodic peer-directory broadcast (relay nodes only).
        // Ensures every connected peer learns about all others regardless of join order.
        let can_relay_for_pdb = can_relay_flag.clone();
        let peer_dir_broadcast_handle = if can_relay_flag.load(std::sync::atomic::Ordering::Relaxed) || true {
            // Always spawn the task; it will check can_relay dynamically on each tick.
            let sessions_pdb = sessions.clone();
            let stun_pdb = stun_public_addr.clone();
            let udp_pdb = transport.clone();
            let our_peer_id_pdb = self.our_peer_id;
            let can_relay_pdb = can_relay_for_pdb.clone();
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(PEER_DIRECTORY_BROADCAST_INTERVAL);
                interval.tick().await; // skip first tick
                loop {
                    interval.tick().await;
                    // Only broadcast if this node is confirmed as a relay.
                    if !can_relay_pdb.load(std::sync::atomic::Ordering::Relaxed) {
                        continue;
                    }
                    if stun_pdb.read().await.is_none() {
                        continue;
                    }
                    let all_peers: Vec<(seednet_common::PeerId, SocketAddr, u8)> = sessions_pdb
                        .iter()
                        .filter_map(|e| {
                            if let seednet_transport::TransportAddr::Udp(a) = e.underlay {
                                Some((*e.key(), a, 1u8))
                            } else {
                                None
                            }
                        })
                        .collect();
                    if all_peers.len() < 2 {
                        continue;
                    }
                    for entry in sessions_pdb.iter() {
                        let recipient_id = *entry.key();
                        let entries: Vec<(seednet_common::PeerId, SocketAddr, u8)> = all_peers
                            .iter()
                            .filter(|(id, _, _)| *id != recipient_id)
                            .copied()
                            .collect();
                        if entries.is_empty() {
                            continue;
                        }
                        let dir =
                            seednet_peer::message::serialize_message(&Message::PeerDirectory {
                                entries,
                            });
                        if let Some(mut s) = sessions_pdb.get_mut(&recipient_id)
                            && let Ok(enc) = s.transport.encrypt(&dir)
                        {
                            let addr = s.underlay.clone();
                            drop(s);
                            let _ = udp_pdb.send_to(&enc, addr).await;
                        }
                    }
                    tracing::debug!(
                        target: "seednet",
                        peers = all_peers.len(),
                        relay = %our_peer_id_pdb.short(),
                        "broadcast peer directory to all connected peers"
                    );
                }
            }))
        } else {
            None
        };

        // Health-check (ping/RTT + path_kind update) task.
        const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(5);
        let healthcheck_handle = {
            let sessions_hc = sessions.clone();
            let udp_hc = transport.clone();
            let peer_mgr_hc = self.peer_manager.clone();
            let relay_paths_hc = relay_paths.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(HEALTHCHECK_INTERVAL);
                loop {
                    interval.tick().await;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let ping = seednet_peer::message::serialize_message(&Message::Ping {
                        sent_ms: now_ms,
                    });
                    for mut entry in sessions_hc.iter_mut() {
                        let peer_id = *entry.key();
                        let addr = entry.underlay.clone();
                        if let Ok(enc) = entry.transport.encrypt(&ping) {
                            drop(entry);
                            let _ = udp_hc.send_to(&enc, addr).await;
                        }
                        if let Some(peer) = peer_mgr_hc.get(&peer_id) {
                            let new_path = if relay_paths_hc.contains_key(&peer_id) {
                                let relay_id = relay_paths_hc.get(&peer_id).map(|r| r.0).unwrap();
                                seednet_peer::PathKind::Relay(relay_id)
                            } else {
                                seednet_peer::PathKind::Direct
                            };
                            peer.set_path_kind(new_path).await;
                        }
                    }
                }
            })
        };

        // STUN refresh task.
        let stun_refresh_handle = {
            let stun_addr_refresh = stun_public_addr.clone();
            let relay_flag_refresh = can_relay_flag.clone();
            let udp_stun = transport.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(DHT_ANNOUNCE_INTERVAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    if let Ok(addr) = seednet_nat::stun::query_public_addr_with_fallback(
                        udp_stun.udp().unwrap().inner(),
                        STUN_SERVERS,
                    )
                    .await
                    {
                        let mut w = stun_addr_refresh.write().await;
                        if *w != Some(addr) {
                            tracing::info!(target: "seednet", %addr, "public address changed");
                            *w = Some(addr);
                            let cr = is_publicly_routable(addr);
                            relay_flag_refresh.store(cr, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            })
        };

        // Peers snapshot task.
        let local_id = self.our_peer_id;
        let local_overlay = self.our_overlay;
        let local_ipv6 = self.our_overlay_ipv6;
        let local_hostname_str = local_hostname();
        let local_public_addr = *stun_public_addr.read().await;
        let local_json = format!(
            concat!(
                r#"{{"id":"{id}","id_short":"{short}","#,
                r#""overlay":"{overlay}","overlay_ipv6":"{ipv6}","#,
                r#""hostname":"{hostname}","public_addr":"{pub_addr}","#,
                r#""connection":"direct","underlay":""}}"#,
            ),
            id = local_id,
            short = local_id.short(),
            overlay = local_overlay,
            ipv6 = local_ipv6,
            hostname = local_hostname_str,
            pub_addr = local_public_addr.map(|a| a.to_string()).unwrap_or_default(),
        );
        let peer_events = self.peer_manager.subscribe();
        let peers_file_handle = {
            let psa = peers_snapshot::PeersSnapshotArgs {
                peer_mgr: self.peer_manager.clone(),
                routing_table: self.routing_table.clone(),
                state_dir: self.config.state_dir.clone(),
                relay_paths: relay_paths.clone(),
                sessions: sessions.clone(),
                addr_index: addr_index.clone(),
                local_json,
            };
            tokio::spawn(peers_snapshot::run_peers_file_loop(psa, peer_events))
        };

        tokio::signal::ctrl_c()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;

        tracing::info!(target: "seednet", "Shutting down …");
        outbound_handle.abort();
        inbound_handle.abort();
        discovery_handle.abort();
        announce_handle.abort();
        heartbeat_handle.abort();
        if let Some(h) = peer_dir_broadcast_handle {
            h.abort();
        }
        healthcheck_handle.abort();
        stun_refresh_handle.abort();
        peers_file_handle.abort();
        let _ = self.config.state_dir.clear_peers_json();

        Ok(())
    }
}

pub fn print_status(engine: &SeedNetEngine) {
    println!("SeedNet status");
    println!("──────────────────────────────────────────────────");
    println!("  Infohash    : {}", engine.infohash());
    println!("  PeerId      : {}", engine.our_peer_id());
    println!("  Overlay IP  : {}", engine.our_overlay());
    println!("  Port        : {}", engine.port());
    println!("  State dir   : {}", engine.state_dir().path().display());
    println!("──────────────────────────────────────────────────");
}

#[cfg(test)]
mod tests {
    use super::*;
    use seednet_common::Seed;
    use seednet_config::StateDir;

    fn temp_state_dir() -> StateDir {
        let dir = std::env::temp_dir().join(format!(
            "seednet-core-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        StateDir::new(&dir).expect("create temp state dir")
    }

    #[test]
    fn engine_new_derives_identity() {
        let state_dir = temp_state_dir();
        let config = SeedNetConfig::new(Seed::from_passphrase("test engine"), 4242, state_dir);
        let engine = SeedNetEngine::new(config).unwrap();
        assert_eq!(engine.our_overlay().ip().octets()[0], 10);
        assert_eq!(engine.our_overlay().ip().octets()[1], 88);
        assert_ne!(engine.infohash().as_bytes(), [0; 20]);
    }

    #[tokio::test]
    async fn allocation_works() {
        let state_dir = temp_state_dir();
        let config = SeedNetConfig::new(Seed::from_passphrase("alloc test"), 4242, state_dir);
        let engine = SeedNetEngine::new(config).unwrap();
        let mut table = engine.allocation_table().write().await;
        let addr = table.allocate(engine.our_peer_id());
        assert_eq!(addr, engine.our_overlay());
        let alloc = table.lookup_by_peer(&engine.our_peer_id());
        assert!(alloc.is_some());
    }

    #[test]
    fn print_status_does_not_panic() {
        let state_dir = temp_state_dir();
        let config = SeedNetConfig::new(Seed::from_passphrase("status test"), 4242, state_dir);
        let engine = SeedNetEngine::new(config).unwrap();
        print_status(&engine);
    }
}
