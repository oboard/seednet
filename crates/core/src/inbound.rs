use std::borrow::Cow;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use seednet_common::{OverlayAddr, PeerId};
use seednet_crypto::{DeviceKeys, NetworkSecret, ResponderHandshake, derive_overlay_addr};
use seednet_peer::{Message, PeerManager, PeerState};
use seednet_routing::RoutingTable;
use seednet_transport::{MultiTransport, Transport, TransportAddr};
use tokio::sync::{Mutex, RwLock};

use crate::engine::{AddrIndex, PeerSession, RelayCandidates, RelayPaths, Sessions};
use crate::handshake::{
    HANDSHAKE_TIMEOUT, NOISE_HANDSHAKE_INITIATOR_PREFIX, NOISE_HANDSHAKE_RESPONDER_PREFIX,
};
use seednet_tun::TunWriter;

pub(crate) struct InboundArgs {
    pub tun_writer: Arc<Mutex<TunWriter>>,
    pub transport: Arc<MultiTransport>,
    pub sessions: Sessions,
    pub addr_index: AddrIndex,
    pub pending: Arc<RwLock<HashMap<SocketAddr, tokio::sync::oneshot::Sender<Vec<u8>>>>>,
    pub network_secret: NetworkSecret,
    pub device_keys: DeviceKeys,
    pub routing_table: Arc<RwLock<RoutingTable>>,
    pub peer_mgr: Arc<PeerManager>,
    pub stun_addr: Arc<RwLock<Option<SocketAddr>>>,
    pub si_overlay: OverlayAddr,
    pub si_overlay_ipv6: std::net::Ipv6Addr,
    pub si_hostname: String,
    pub relay_candidates: RelayCandidates,
    pub relay_paths: RelayPaths,
    pub our_peer_id: PeerId,
    pub can_relay: bool,
}

pub(crate) async fn run_inbound_loop(args: InboundArgs) {
    let mut pending_responders: HashMap<SocketAddr, (ResponderHandshake, std::time::Instant)> =
        HashMap::new();
    let mut recv_buf = vec![0u8; seednet_transport::MAX_UDP];
    let mut plain_buf = vec![0u8; seednet_transport::MAX_UDP];

    loop {
        match args.transport.recv_into(&mut recv_buf).await {
            Ok((n, from)) => {
                let data = &recv_buf[..n];
                let from_sa = from.socket_addr();

                pending_responders.retain(|_, (_, t)| t.elapsed() < HANDSHAKE_TIMEOUT);

                // --- hole-punch probes ---
                if data.starts_with(seednet_common::HOLE_PUNCH_PROBE_PREFIX) {
                    let payload = &data[seednet_common::HOLE_PUNCH_PROBE_PREFIX.len()..];
                    match seednet_peer::message::deserialize_message(payload) {
                        Ok(Message::HolePunchProbe { token }) => {
                            tracing::debug!(target: "seednet", from = %from, token, "hole-punch probe received, sending ack+probe");
                            let ack = [
                                seednet_common::HOLE_PUNCH_PROBE_PREFIX,
                                &seednet_peer::message::serialize_message(&Message::HolePunchAck {
                                    token,
                                }),
                            ]
                            .concat();
                            let probe = [
                                seednet_common::HOLE_PUNCH_PROBE_PREFIX,
                                &seednet_peer::message::serialize_message(
                                    &Message::HolePunchProbe { token },
                                ),
                            ]
                            .concat();
                            let _ = args.transport.send_to(&ack, from.clone()).await;
                            let _ = args.transport.send_to(&probe, from.clone()).await;
                        }
                        Ok(Message::HolePunchAck { token }) => {
                            tracing::debug!(target: "seednet", from = %from, token, "hole-punch ack received");
                        }
                        _ => {}
                    }
                    continue;
                }

                // --- msg B dispatch to initiator ---
                if data.starts_with(NOISE_HANDSHAKE_RESPONDER_PREFIX) {
                    let mut pending = args.pending.write().await;
                    if let Some(sender) = pending.remove(&from_sa) {
                        drop(pending);
                        tracing::debug!(target: "seednet", from = %from, "dispatching msg B to pending initiator");
                        let _ = sender.send(data.to_vec());
                        continue;
                    }
                    drop(pending);
                }

                // --- msg C: complete pending responder handshake ---
                if let Some((responder, _)) = pending_responders.remove(&from_sa) {
                    match responder.finish(data) {
                        Ok(resp_result) => {
                            let remote_static = *resp_result.transport.remote_static_key();
                            let peer_id = PeerId::from_bytes(remote_static);

                            tracing::info!(
                                target: "seednet",
                                peer = %peer_id.short(),
                                addr = %from,
                                "handshake completed (responder)"
                            );

                            if args.relay_paths.remove(&peer_id).is_some() {
                                tracing::info!(
                                    target: "seednet",
                                    peer = %peer_id.short(),
                                    "upgraded from relay to direct connection (responder)"
                                );
                            }

                            args.sessions.insert(
                                peer_id,
                                PeerSession {
                                    transport: resp_result.transport,
                                    underlay: from.clone(),
                                },
                            );
                            args.addr_index.insert(from.clone(), peer_id);

                            let overlay = derive_overlay_addr(&peer_id);
                            let mut rt = args.routing_table.write().await;
                            rt.add_route(overlay, peer_id);
                            drop(rt);

                            let our_public = *args.stun_addr.read().await;
                            let si_bytes =
                                seednet_peer::message::serialize_message(&Message::SessionInit {
                                    overlay: args.si_overlay,
                                    overlay_ipv6: Some(args.si_overlay_ipv6.octets()),
                                    hostname: args.si_hostname.clone(),
                                    public_addr: our_public,
                                });
                            if let Some(mut session) = args.sessions.get_mut(&peer_id)
                                && let Ok(enc) = session.transport.encrypt(&si_bytes)
                            {
                                let _ = args.transport.send_to(&enc, from.clone()).await;
                            }

                            if args.can_relay
                                && let Some(our_pub) = *args.stun_addr.read().await
                            {
                                let announce = seednet_peer::message::serialize_message(
                                    &Message::RelayAnnounce {
                                        relay_peer_id: args.our_peer_id,
                                        public_addr: our_pub,
                                    },
                                );
                                if let Some(mut session) = args.sessions.get_mut(&peer_id)
                                    && let Ok(enc) = session.transport.encrypt(&announce)
                                {
                                    let _ = args.transport.send_to(&enc, from.clone()).await;
                                }

                                // PeerDirectory broadcast is deferred to handle_session_init
                                // so that the correct (non-Noise-derived) peer_id is used.
                            }

                            let _peer = args.peer_mgr.discover(peer_id, from_sa).await;
                            let _ = args
                                .peer_mgr
                                .transition_peer(&peer_id, PeerState::Connecting)
                                .await;
                            let _ = args
                                .peer_mgr
                                .transition_peer(&peer_id, PeerState::Handshaking)
                                .await;
                            let _ = args
                                .peer_mgr
                                .transition_peer(&peer_id, PeerState::Connected)
                                .await;

                            tracing::info!(
                                target: "seednet",
                                peer = %peer_id.short(),
                                overlay = %overlay,
                                addr = %from,
                                "peer route registered (responder)"
                            );
                        }
                        Err(e) => {
                            tracing::debug!(target: "seednet", from = %from, error = %e, "responder finish (msg C) failed");
                        }
                    }
                    continue;
                }

                // --- data from established peer ---
                if let Some(peer_id) = args.addr_index.get(&from).map(|r| *r) {
                    if let Some(mut session) = args.sessions.get_mut(&peer_id) {
                        match session.transport.decrypt_into(data, &mut plain_buf) {
                            Ok(plain_n) => {
                                drop(session);
                                let decrypted = &plain_buf[..plain_n];
                                match seednet_peer::message::deserialize_message(decrypted) {
                                    Ok(Message::Heartbeat) => {
                                        tracing::trace!(target: "seednet", from = %from, "heartbeat received");
                                    }
                                    Ok(Message::Ping { sent_ms }) => {
                                        let pong = seednet_peer::message::serialize_message(
                                            &Message::Pong { sent_ms },
                                        );
                                        let pid = args.addr_index.get(&from).map(|r| *r);
                                        if let Some(pid) = pid
                                            && let Some(mut session) = args.sessions.get_mut(&pid)
                                            && let Ok(enc) = session.transport.encrypt(&pong)
                                        {
                                            drop(session);
                                            let _ =
                                                args.transport.send_to(&enc, from.clone()).await;
                                        }
                                    }
                                    Ok(Message::Pong { sent_ms }) => {
                                        let now_ms = std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_millis()
                                            as u64;
                                        let rtt = now_ms.saturating_sub(sent_ms) as u32;
                                        let pid = args.addr_index.get(&from).map(|r| *r);
                                        if let Some(pid) = pid
                                            && let Some(peer) = args.peer_mgr.get(&pid)
                                        {
                                            peer.set_latency_ms(rtt).await;
                                            tracing::debug!(
                                                target: "seednet",
                                                peer = %pid.short(),
                                                rtt_ms = rtt,
                                                "pong received"
                                            );
                                        }
                                    }
                                    Ok(Message::Data(payload)) => {
                                        let mut writer = args.tun_writer.lock().await;
                                        let _ = writer.send(&payload).await;
                                    }
                                    Ok(Message::SessionInit {
                                        overlay,
                                        overlay_ipv6,
                                        hostname,
                                        public_addr,
                                    }) => {
                                        handle_session_init(
                                            &args,
                                            &from,
                                            from_sa,
                                            SessionInitPayload {
                                                overlay,
                                                overlay_ipv6,
                                                hostname,
                                                public_addr,
                                            },
                                        )
                                        .await;
                                    }
                                    Ok(Message::RelayAnnounce {
                                        relay_peer_id,
                                        public_addr,
                                    }) => {
                                        args.relay_candidates.insert(relay_peer_id, public_addr);
                                        tracing::info!(target: "seednet", relay = %relay_peer_id.short(), addr = %public_addr, "relay candidate registered");
                                    }
                                    Ok(Message::PeerDirectory { entries }) => {
                                        handle_peer_directory(&args, &from, &entries).await;
                                    }
                                    Ok(Message::RelayRequest { dst_peer_id }) => {
                                        handle_relay_request(&args, &from, dst_peer_id).await;
                                    }
                                    Ok(Message::RelayReady {
                                        relay_peer_id,
                                        dst_peer_id,
                                    }) => {
                                        args.relay_paths.insert(dst_peer_id, (relay_peer_id, 1u8));
                                        let overlay = derive_overlay_addr(&dst_peer_id);
                                        {
                                            let mut rt = args.routing_table.write().await;
                                            rt.add_route(overlay, dst_peer_id);
                                        }
                                        // Register in peer manager so it shows up in peers.json.
                                        let fake_addr: std::net::SocketAddr =
                                            "0.0.0.0:0".parse().unwrap();
                                        let _ =
                                            args.peer_mgr.discover(dst_peer_id, fake_addr).await;
                                        let _ = args
                                            .peer_mgr
                                            .transition_peer(&dst_peer_id, PeerState::Connecting)
                                            .await;
                                        let _ = args
                                            .peer_mgr
                                            .transition_peer(&dst_peer_id, PeerState::Handshaking)
                                            .await;
                                        let _ = args
                                            .peer_mgr
                                            .transition_peer(&dst_peer_id, PeerState::Connected)
                                            .await;
                                        tracing::info!(target: "seednet", dst = %dst_peer_id.short(), relay = %relay_peer_id.short(), overlay = %overlay, "relay path established, route added");
                                    }
                                    Ok(Message::RelayData {
                                        src_peer_id,
                                        dst_peer_id,
                                        payload,
                                    }) => {
                                        handle_relay_data(&args, src_peer_id, dst_peer_id, payload)
                                            .await;
                                    }
                                    Ok(msg) => {
                                        tracing::info!(target: "seednet", from = %from, ?msg, "unhandled message type");
                                    }
                                    Err(e) => {
                                        tracing::info!(target: "seednet", from = %from, error = %e, "malformed message, dropping");
                                    }
                                }
                            }
                            Err(_) => {
                                tracing::debug!(target: "seednet", from = %from, "decrypt failed for established peer");
                            }
                        }
                    }
                    continue;
                }

                // --- msg A: start responder handshake ---
                if data.starts_with(NOISE_HANDSHAKE_INITIATOR_PREFIX) {
                    let noise_payload = &data[NOISE_HANDSHAKE_INITIATOR_PREFIX.len()..];
                    match ResponderHandshake::new(&args.network_secret, &args.device_keys) {
                        Ok(mut responder) => {
                            if responder.read_message_a(noise_payload).is_ok() {
                                match responder.write_message_b(&[]) {
                                    Ok(msg_b) => {
                                        let mut tagged = NOISE_HANDSHAKE_RESPONDER_PREFIX.to_vec();
                                        tagged.extend_from_slice(&msg_b);
                                        tracing::info!(target: "seednet", from = %from, "received handshake msg A, sending msg B");
                                        let _ = args.transport.send_to(&tagged, from.clone()).await;
                                        pending_responders.insert(
                                            from_sa,
                                            (responder, std::time::Instant::now()),
                                        );
                                    }
                                    Err(e) => {
                                        tracing::debug!(target: "seednet", from = %from, error = %e, "write_message_b failed");
                                    }
                                }
                            } else {
                                tracing::debug!(target: "seednet", from = %from, "read_message_a failed (wrong network?)");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(target: "seednet", error = %e, "responder create failed");
                        }
                    }
                }
            }
            Err(e) => {
                tracing::debug!(target: "seednet", error = %e, "UDP recv error");
            }
        }
    }
}

struct SessionInitPayload {
    overlay: OverlayAddr,
    overlay_ipv6: Option<[u8; 16]>,
    hostname: String,
    public_addr: Option<SocketAddr>,
}

async fn handle_session_init(
    args: &InboundArgs,
    from: &TransportAddr,
    from_sa: SocketAddr,
    init: SessionInitPayload,
) {
    let SessionInitPayload {
        overlay,
        overlay_ipv6,
        hostname,
        public_addr,
    } = init;

    // peer_id is always the X25519 key from the Noise handshake — no migration needed.
    let peer_id = match args.addr_index.get(from).map(|r| *r) {
        Some(id) => id,
        None => {
            tracing::debug!(target: "seednet", from = %from, "SessionInit from unknown addr, ignoring");
            return;
        }
    };

    {
        let mut rt = args.routing_table.write().await;
        rt.add_route(overlay, peer_id);
    }

    // PeerDirectory broadcast so peers discover each other through this relay.
    if args.can_relay
        && let TransportAddr::Udp(new_peer_addr) = *from
    {
        // Collect existing direct-session peers (hop_count=1).
        let mut existing_peers: Vec<(PeerId, SocketAddr, u8)> = args
            .sessions
            .iter()
            .filter(|e| *e.key() != peer_id)
            .filter_map(|e| {
                if let TransportAddr::Udp(a) = e.underlay {
                    Some((*e.key(), a, 1u8))
                } else {
                    None
                }
            })
            .collect();
        // Also include peers reachable via relay_paths (multi-hop), with their known hop count.
        for entry in args.relay_paths.iter() {
            let rp_peer = *entry.key();
            let rp_hops = entry.value().1;
            if rp_peer != peer_id && !existing_peers.iter().any(|(id, _, _)| *id == rp_peer) {
                if let Some(p) = args.peer_mgr.get(&rp_peer) {
                    if let Some(pub_addr) = p.public_addr().await {
                        existing_peers.push((rp_peer, pub_addr, rp_hops));
                    }
                }
            }
        }

        // Send the new peer a directory of all existing peers.
        if !existing_peers.is_empty() {
            let dir = seednet_peer::message::serialize_message(&Message::PeerDirectory {
                entries: existing_peers,
            });
            if let Some(mut s) = args.sessions.get_mut(&peer_id)
                && let Ok(enc) = s.transport.encrypt(&dir)
            {
                let addr = s.underlay.clone();
                drop(s);
                let _ = args.transport.send_to(&enc, addr).await;
            }
        }

        // Tell all existing peers about the new peer (hop_count=1, direct neighbor of this relay).
        let new_entry = vec![(peer_id, new_peer_addr, 1u8)];
        let dir = seednet_peer::message::serialize_message(&Message::PeerDirectory {
            entries: new_entry,
        });
        let existing_ids: Vec<PeerId> = args
            .sessions
            .iter()
            .filter(|e| *e.key() != peer_id)
            .map(|e| *e.key())
            .collect();
        for existing_id in existing_ids {
            if let Some(mut s) = args.sessions.get_mut(&existing_id)
                && let Ok(enc) = s.transport.encrypt(&dir)
            {
                let addr = s.underlay.clone();
                drop(s);
                let _ = args.transport.send_to(&enc, addr).await;
                tracing::info!(
                    target: "seednet",
                    new_peer = %peer_id.short(),
                    notified = %existing_id.short(),
                    "notified existing peer about new peer"
                );
            }
        }
    }

    tracing::info!(target: "seednet", peer = %peer_id.short(), overlay = %overlay, "SessionInit: overlay registered");

    if let Some(peer) = args.peer_mgr.get(&peer_id) {
        if let Some(bytes) = overlay_ipv6 {
            peer.set_overlay_ipv6(std::net::Ipv6Addr::from(bytes)).await;
        }
        if !hostname.is_empty() {
            peer.set_hostname(hostname).await;
        }
        if let Some(addr) = public_addr {
            peer.set_public_addr(addr).await;
        }
    }
    let _ = from_sa;
    tracing::debug!(target: "seednet", from = %from, "SessionInit received");
}

const MAX_HOP_REBROADCAST: u8 = 8;

async fn handle_peer_directory(
    args: &InboundArgs,
    from: &TransportAddr,
    entries: &[(PeerId, SocketAddr, u8)],
) {
    let relay_id = args.addr_index.get(from).map(|r| *r);
    tracing::info!(target: "seednet", from = %from, relay = ?relay_id.map(|r| r.short()), entries = entries.len(), "peer directory received");
    if let Some(rid) = relay_id {
        for (pid, pub_addr, hop_count) in entries {
            if *pid == args.our_peer_id {
                continue;
            }
            // effective hops from us = hop_count_from_sender + 1
            let effective_hops = hop_count.saturating_add(1);

            let p = args.peer_mgr.discover(*pid, *pub_addr).await;
            p.set_public_addr(*pub_addr).await;

            if !args.sessions.contains_key(pid) {
                // Only insert/update if this path is better (fewer hops) than existing.
                let should_update = match args.relay_paths.get(pid) {
                    None => true,
                    Some(existing) => effective_hops < existing.1,
                };
                if should_update {
                    args.relay_paths.insert(*pid, (rid, effective_hops));
                    let overlay = derive_overlay_addr(pid);
                    {
                        let mut rt = args.routing_table.write().await;
                        rt.add_route(overlay, *pid);
                    }

                    if let Some(mut rsession) = args.sessions.get_mut(&rid) {
                        let req = seednet_peer::message::serialize_message(&Message::RelayRequest {
                            dst_peer_id: *pid,
                        });
                        if let Ok(enc) = rsession.transport.encrypt(&req) {
                            let raddr = rsession.underlay.clone();
                            drop(rsession);
                            let _ = args.transport.send_to(&enc, raddr).await;
                            tracing::info!(
                                target: "seednet",
                                peer = %pid.short(),
                                relay = %rid.short(),
                                hops = effective_hops,
                                pub_addr = %pub_addr,
                                "requested relay via peer directory"
                            );
                        }
                    }
                }
            }
        }

        // Relay nodes re-broadcast received entries to other direct peers (OSPF-like propagation).
        if args.can_relay {
            let rebroadcast: Vec<(PeerId, SocketAddr, u8)> = entries
                .iter()
                .filter(|(pid, _, h)| *pid != args.our_peer_id && *h < MAX_HOP_REBROADCAST)
                .map(|(pid, addr, h)| (*pid, *addr, h.saturating_add(1)))
                .collect();
            if !rebroadcast.is_empty() {
                let dir = seednet_peer::message::serialize_message(&Message::PeerDirectory {
                    entries: rebroadcast,
                });
                let recipients: Vec<PeerId> = args
                    .sessions
                    .iter()
                    .filter(|e| *e.key() != rid)
                    .map(|e| *e.key())
                    .collect();
                for recipient in recipients {
                    if let Some(mut s) = args.sessions.get_mut(&recipient)
                        && let Ok(enc) = s.transport.encrypt(&dir)
                    {
                        let addr = s.underlay.clone();
                        drop(s);
                        let _ = args.transport.send_to(&enc, addr).await;
                    }
                }
            }
        }
    }
}

async fn handle_relay_request(args: &InboundArgs, from: &TransportAddr, dst_peer_id: PeerId) {
    if args.can_relay {
        let requesting_id = args.addr_index.get(from).map(|r| *r);
        if let Some(req_id) = requesting_id {
            // Check if we can reach dst: direct session or via relay_paths.
            let dst_direct = args.sessions.contains_key(&dst_peer_id);
            let dst_next_relay = args.relay_paths.get(&dst_peer_id).map(|r| r.0);

            if !dst_direct && dst_next_relay.is_none() {
                tracing::debug!(target: "seednet", dst = %dst_peer_id.short(), "relay request: dst unreachable, ignoring");
                return;
            }

            if dst_direct {
                // Tell the requesting peer: relay is ready.
                if let Some(mut req_session) = args.sessions.get_mut(&req_id) {
                    let ready = seednet_peer::message::serialize_message(&Message::RelayReady {
                        relay_peer_id: args.our_peer_id,
                        dst_peer_id,
                    });
                    if let Ok(enc) = req_session.transport.encrypt(&ready) {
                        let addr = req_session.underlay.clone();
                        drop(req_session);
                        let _ = args.transport.send_to(&enc, addr).await;
                        tracing::info!(target: "seednet", req = %req_id.short(), dst = %dst_peer_id.short(), "relay ready sent to requester");
                    }
                }
                // Tell the destination peer: relay is ready.
                if let Some(mut dst_session) = args.sessions.get_mut(&dst_peer_id) {
                    let ready = seednet_peer::message::serialize_message(&Message::RelayReady {
                        relay_peer_id: args.our_peer_id,
                        dst_peer_id: req_id,
                    });
                    if let Ok(enc) = dst_session.transport.encrypt(&ready) {
                        let addr = dst_session.underlay.clone();
                        drop(dst_session);
                        let _ = args.transport.send_to(&enc, addr).await;
                        tracing::info!(target: "seednet", dst = %dst_peer_id.short(), req = %req_id.short(), "relay ready sent to destination");
                    }
                }
            } else if let Some(next_relay_id) = dst_next_relay {
                // Multi-hop: we reach dst through next_relay. Tell the requester that this relay
                // is the entry point (relay_peer_id = us), so traffic flows src→us→next_relay→dst.
                if let Some(mut req_session) = args.sessions.get_mut(&req_id) {
                    let ready = seednet_peer::message::serialize_message(&Message::RelayReady {
                        relay_peer_id: args.our_peer_id,
                        dst_peer_id,
                    });
                    if let Ok(enc) = req_session.transport.encrypt(&ready) {
                        let addr = req_session.underlay.clone();
                        drop(req_session);
                        let _ = args.transport.send_to(&enc, addr).await;
                        tracing::info!(target: "seednet", req = %req_id.short(), dst = %dst_peer_id.short(), next = %next_relay_id.short(), "relay ready sent to requester (multi-hop)");
                    }
                }
                // Also tell next_relay about the requester so the return path works.
                if let Some(mut next_session) = args.sessions.get_mut(&next_relay_id) {
                    let req_fwd = seednet_peer::message::serialize_message(&Message::RelayRequest {
                        dst_peer_id: req_id,
                    });
                    if let Ok(enc) = next_session.transport.encrypt(&req_fwd) {
                        let addr = next_session.underlay.clone();
                        drop(next_session);
                        let _ = args.transport.send_to(&enc, addr).await;
                        tracing::info!(target: "seednet", next = %next_relay_id.short(), dst = %req_id.short(), "forwarded relay request for return path (multi-hop)");
                    }
                }
            }
        }
    } else {
        // Non-relay node received a RelayRequest forwarded by relay.
        // Record the relay path so we can send data back via relay.
        let relay_id = args.addr_index.get(from).map(|r| *r);
        if let Some(rid) = relay_id {
            args.relay_paths.insert(dst_peer_id, (rid, 1u8));
            let overlay = derive_overlay_addr(&dst_peer_id);
            {
                let mut rt = args.routing_table.write().await;
                rt.add_route(overlay, dst_peer_id);
            }
            tracing::info!(
                target: "seednet",
                peer = %dst_peer_id.short(),
                relay = %rid.short(),
                overlay = %overlay,
                "relay path recorded (as destination), route added"
            );
        }
    }
}

async fn handle_relay_data(
    args: &InboundArgs,
    src_peer_id: PeerId,
    dst_peer_id: PeerId,
    payload: Cow<'_, [u8]>,
) {
    if dst_peer_id == args.our_peer_id
        || (!args.sessions.contains_key(&dst_peer_id) && !args.can_relay)
    {
        // We are the destination (either by exact match or because we can't forward and
        // the dst is not a known session — covers peer_id aliasing from SessionInit migration).
        if let Ok(Message::Data(ip_pkt)) = seednet_peer::message::deserialize_message(&payload) {
            let mut w = args.tun_writer.lock().await;
            let _ = w.send(&ip_pkt).await;
            tracing::debug!(target: "seednet", src = %src_peer_id.short(), bytes = ip_pkt.len(), "relayed packet written to TUN");
        }
    } else if args.can_relay {
        if let Some(mut dst_session) = args.sessions.get_mut(&dst_peer_id) {
            // Direct session to dst: forward immediately.
            let fwd = seednet_peer::message::serialize_message(&Message::RelayData {
                src_peer_id,
                dst_peer_id,
                payload: Cow::Owned(payload.into_owned()),
            });
            if let Ok(outer) = dst_session.transport.encrypt(&fwd) {
                let addr = dst_session.underlay.clone();
                drop(dst_session);
                let _ = args.transport.send_to(&outer, addr).await;
                tracing::info!(target: "seednet", src = %src_peer_id.short(), dst = %dst_peer_id.short(), "relayed packet forwarded");
            } else {
                tracing::info!(target: "seednet", dst = %dst_peer_id.short(), "relay encrypt failed");
            }
        } else if let Some(next_relay_id) = args.relay_paths.get(&dst_peer_id).map(|r| r.0) {
            // No direct session to dst, but we have a relay path via another relay — forward there.
            if let Some(mut next_session) = args.sessions.get_mut(&next_relay_id) {
                let fwd = seednet_peer::message::serialize_message(&Message::RelayData {
                    src_peer_id,
                    dst_peer_id,
                    payload: Cow::Owned(payload.into_owned()),
                });
                if let Ok(outer) = next_session.transport.encrypt(&fwd) {
                    let addr = next_session.underlay.clone();
                    drop(next_session);
                    let _ = args.transport.send_to(&outer, addr).await;
                    tracing::info!(target: "seednet", src = %src_peer_id.short(), dst = %dst_peer_id.short(), next = %next_relay_id.short(), "relayed packet forwarded (multi-hop)");
                }
            }
        } else {
            tracing::info!(target: "seednet", dst = %dst_peer_id.short(), "relay: no session or next-hop for dst");
        }
    }
}
