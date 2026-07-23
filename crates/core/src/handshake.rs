use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use seednet_common::{NetworkSecret, OverlayAddr, PeerId};
use seednet_crypto::{DeviceKeys, InitiatorHandshake, derive_overlay_addr};
use seednet_peer::{Message, PeerManager, PeerState};
use seednet_routing::RoutingTable;
use seednet_transport::{MultiTransport, Transport, TransportAddr};
use tokio::sync::{RwLock, oneshot};

use crate::engine::{AddrIndex, PeerSession, RelayCandidates, RelayPaths, Sessions};

pub(crate) const NOISE_HANDSHAKE_INITIATOR_PREFIX: &[u8] = b"seednet-hs-a";
pub(crate) const NOISE_HANDSHAKE_RESPONDER_PREFIX: &[u8] = b"seednet-hs-b";
/// How long to wait for a direct handshake before falling back to relay.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) struct InitiatorArgs {
    pub addr: SocketAddr,
    pub network_secret: NetworkSecret,
    pub device_keys: DeviceKeys,
    pub udp: Arc<MultiTransport>,
    pub sessions: Sessions,
    pub addr_index: AddrIndex,
    pub pending: Arc<RwLock<HashMap<SocketAddr, oneshot::Sender<Vec<u8>>>>>,
    pub stun_addr: Arc<RwLock<Option<SocketAddr>>>,
    pub peer_mgr: Arc<PeerManager>,
    pub routing_table: Arc<RwLock<RoutingTable>>,
    pub relay_cands: RelayCandidates,
    pub relay_paths: RelayPaths,
    pub si_peer_id: PeerId,
    pub si_overlay: OverlayAddr,
    pub si_overlay_ipv6: std::net::Ipv6Addr,
    pub si_hostname: String,
    pub our_id: PeerId,
    pub our_relay_id: PeerId,
    pub can_relay: bool,
}

pub(crate) async fn do_initiator_handshake(a: InitiatorArgs) {
    let addr = a.addr;
    tracing::info!(target: "seednet", addr = %addr, "initiating handshake to discovered peer");

    let mut initiator = match InitiatorHandshake::new(&a.network_secret, &a.device_keys) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(target: "seednet", error = %e, "initiator create failed");
            return;
        }
    };
    let msg_a = match initiator.write_message_a(&[]) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(target: "seednet", error = %e, "write_message_a failed");
            return;
        }
    };
    let mut tagged_a = NOISE_HANDSHAKE_INITIATOR_PREFIX.to_vec();
    tagged_a.extend_from_slice(&msg_a);

    let (tx, rx) = oneshot::channel();
    {
        let mut p = a.pending.write().await;
        if p.contains_key(&addr) {
            return;
        }
        p.insert(addr, tx);
    }
    if let Err(e) = a.udp.send_to(&tagged_a, TransportAddr::Udp(addr)).await {
        a.pending.write().await.remove(&addr);
        tracing::warn!(target: "seednet", error = %e, "send msg A failed");
        return;
    }

    match tokio::time::timeout(HANDSHAKE_TIMEOUT, rx).await {
        Ok(Ok(msg_b_tagged)) => {
            if !msg_b_tagged.starts_with(NOISE_HANDSHAKE_RESPONDER_PREFIX) {
                tracing::warn!(target: "seednet", "msg B has wrong prefix");
                return;
            }
            let msg_b = &msg_b_tagged[NOISE_HANDSHAKE_RESPONDER_PREFIX.len()..];
            if let Err(e) = initiator.read_message_b(msg_b) {
                tracing::warn!(target: "seednet", error = %e, "read_message_b failed");
                return;
            }
            let init_result = match initiator.finish(&[]) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(target: "seednet", error = %e, "initiator finish failed");
                    return;
                }
            };
            if let Err(e) = a
                .udp
                .send_to(&init_result.msg_bytes, TransportAddr::Udp(addr))
                .await
            {
                tracing::warn!(target: "seednet", error = %e, "send msg C failed");
                return;
            }
            let remote_static = *init_result.transport.remote_static_key();
            let peer_id = PeerId::from_bytes(remote_static);
            if peer_id == a.our_id {
                return;
            }
            tracing::info!(target: "seednet", peer = %peer_id.short(), addr = %addr, "handshake completed (initiator)");
            // Direct → remove any relay path.
            if a.relay_paths.remove(&peer_id).is_some() {
                tracing::info!(target: "seednet", peer = %peer_id.short(), "upgraded from relay to direct connection");
            }
            a.sessions.insert(
                peer_id,
                PeerSession {
                    transport: init_result.transport,
                    underlay: TransportAddr::Udp(addr),
                },
            );
            a.addr_index.insert(TransportAddr::Udp(addr), peer_id);
            let overlay = derive_overlay_addr(&peer_id);
            {
                let mut rt = a.routing_table.write().await;
                rt.add_route(overlay, peer_id);
            }
            // Send SessionInit.
            let our_public = *a.stun_addr.read().await;
            let si_bytes = seednet_peer::message::serialize_message(&Message::SessionInit {
                peer_id: a.si_peer_id,
                overlay: a.si_overlay,
                overlay_ipv6: Some(a.si_overlay_ipv6.octets()),
                hostname: a.si_hostname.clone(),
                public_addr: our_public,
            });
            if let Some(mut session) = a.sessions.get_mut(&peer_id)
                && let Ok(enc) = session.transport.encrypt(&si_bytes)
            {
                let _ = a.udp.send_to(&enc, TransportAddr::Udp(addr)).await;
            }
            // Advertise relay + send peer directory if we are a relay.
            if a.can_relay
                && let Some(our_pub) = *a.stun_addr.read().await
            {
                let announce = seednet_peer::message::serialize_message(&Message::RelayAnnounce {
                    relay_peer_id: a.our_relay_id,
                    public_addr: our_pub,
                });
                if let Some(mut session) = a.sessions.get_mut(&peer_id)
                    && let Ok(enc) = session.transport.encrypt(&announce)
                {
                    let _ = a.udp.send_to(&enc, TransportAddr::Udp(addr)).await;
                }
                let entries: Vec<(PeerId, SocketAddr)> = a
                    .sessions
                    .iter()
                    .filter(|e| *e.key() != peer_id)
                    .filter_map(|e| {
                        if let TransportAddr::Udp(sa) = e.underlay {
                            Some((*e.key(), sa))
                        } else {
                            None
                        }
                    })
                    .collect();
                if !entries.is_empty() {
                    let dir = seednet_peer::message::serialize_message(&Message::PeerDirectory {
                        entries,
                    });
                    if let Some(mut session) = a.sessions.get_mut(&peer_id)
                        && let Ok(enc) = session.transport.encrypt(&dir)
                    {
                        let _ = a.udp.send_to(&enc, TransportAddr::Udp(addr)).await;
                    }
                }
            }
            let _peer = a.peer_mgr.discover(peer_id, addr).await;
            let _ = a
                .peer_mgr
                .transition_peer(&peer_id, PeerState::Connecting)
                .await;
            let _ = a
                .peer_mgr
                .transition_peer(&peer_id, PeerState::Handshaking)
                .await;
            let _ = a
                .peer_mgr
                .transition_peer(&peer_id, PeerState::Connected)
                .await;
            tracing::info!(target: "seednet", peer = %peer_id.short(), overlay = %overlay, addr = %addr, "peer route registered (initiator)");
        }
        Ok(Err(_)) => {
            tracing::warn!(target: "seednet", addr = %addr, "msg B channel dropped");
        }
        Err(_) => {
            let mut p = a.pending.write().await;
            p.remove(&addr);
            tracing::warn!(target: "seednet", addr = %addr, "initiator handshake timed out waiting for msg B");
            drop(p);
            // Request relay on timeout.
            let maybe_peer_id = a.addr_index.get(&TransportAddr::Udp(addr)).map(|r| *r);
            if let Some(target_id) = maybe_peer_id {
                for relay_entry in a.relay_cands.iter() {
                    let relay_id = *relay_entry.key();
                    if relay_id == target_id {
                        continue;
                    }
                    if let Some(mut relay_session) = a.sessions.get_mut(&relay_id) {
                        let req =
                            seednet_peer::message::serialize_message(&Message::RelayRequest {
                                dst_peer_id: target_id,
                            });
                        if let Ok(enc) = relay_session.transport.encrypt(&req) {
                            let raddr = relay_session.underlay.clone();
                            drop(relay_session);
                            let _ = a.udp.send_to(&enc, raddr).await;
                            tracing::info!(target: "seednet", peer = %target_id.short(), relay = %relay_id.short(), "requested relay after direct timeout");
                        }
                    }
                }
            }
            // Hole-punch attempt.
            let peer_id_candidate = a.addr_index.get(&TransportAddr::Udp(addr)).map(|r| *r);
            if let Some(pid) = peer_id_candidate
                && let Some(peer) = a.peer_mgr.get(&pid)
                && let Some(pub_addr) = peer.public_addr().await
                && pub_addr != addr
            {
                tracing::info!(target: "seednet", addr = %pub_addr, peer = %pid.short(), "attempting hole-punch");
                let token = rand::random::<u64>();
                let probe = [
                    seednet_common::HOLE_PUNCH_PROBE_PREFIX,
                    &seednet_peer::message::serialize_message(&Message::HolePunchProbe { token }),
                ]
                .concat();
                let _ = a.udp.send_to(&probe, TransportAddr::Udp(pub_addr)).await;
            }
        }
    }
}
