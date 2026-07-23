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
    pub si_peer_id: PeerId,
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
                                    peer_id: args.si_peer_id,
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

                                let entries: Vec<(PeerId, SocketAddr)> = args
                                    .sessions
                                    .iter()
                                    .filter(|e| *e.key() != peer_id)
                                    .filter_map(|e| {
                                        if let TransportAddr::Udp(a) = e.underlay {
                                            Some((*e.key(), a))
                                        } else {
                                            None
                                        }
                                    })
                                    .collect();
                                if !entries.is_empty() {
                                    let dir = seednet_peer::message::serialize_message(
                                        &Message::PeerDirectory { entries },
                                    );
                                    if let Some(mut session) = args.sessions.get_mut(&peer_id)
                                        && let Ok(enc) = session.transport.encrypt(&dir)
                                    {
                                        let _ = args.transport.send_to(&enc, from.clone()).await;
                                    }
                                }
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
                                        peer_id,
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
                                                peer_id,
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
                                        args.relay_paths.insert(dst_peer_id, relay_peer_id);
                                        let overlay = derive_overlay_addr(&dst_peer_id);
                                        {
                                            let mut rt = args.routing_table.write().await;
                                            rt.add_route(overlay, dst_peer_id);
                                        }
                                        tracing::info!(target: "seednet", dst = %dst_peer_id.short(), relay = %relay_peer_id.short(), overlay = %overlay, "relay path established, route added");
                                    }
                                    Ok(Message::RelayData {
                                        dst_peer_id,
                                        payload,
                                    }) => {
                                        handle_relay_data(&args, &from, dst_peer_id, payload).await;
                                    }
                                    Ok(msg) => {
                                        tracing::debug!(target: "seednet", from = %from, ?msg, "unhandled message type");
                                    }
                                    Err(e) => {
                                        tracing::debug!(target: "seednet", from = %from, error = %e, "malformed message, dropping");
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
    peer_id: PeerId,
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
        peer_id,
        overlay,
        overlay_ipv6,
        hostname,
        public_addr,
    } = init;
    let x25519_peer_id = args.addr_index.get(from).map(|r| *r);
    if let Some(old_id) = x25519_peer_id
        && old_id != peer_id
    {
        if let Some((_, session)) = args.sessions.remove(&old_id) {
            args.sessions.insert(peer_id, session);
        }
        args.addr_index.insert(from.clone(), peer_id);

        let stale = derive_overlay_addr(&old_id);
        {
            let mut rt = args.routing_table.write().await;
            rt.remove_route(&stale);
            rt.add_route(overlay, peer_id);
        }

        if let Some(old_peer) = args.peer_mgr.remove(&old_id) {
            let addr = old_peer.underlay_addr().await.unwrap_or(from_sa);
            let new_peer = args.peer_mgr.discover(peer_id, addr).await;
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
            let _ = new_peer;
        }
    } else {
        let mut rt = args.routing_table.write().await;
        rt.add_route(overlay, peer_id);
        drop(rt);
    }
    tracing::info!(target: "seednet",
        peer = %peer_id.short(),
        overlay = %overlay,
        "peer overlay updated from SessionInit");
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
    tracing::debug!(target: "seednet", from = %from, "SessionInit received");
}

async fn handle_peer_directory(
    args: &InboundArgs,
    from: &TransportAddr,
    entries: &[(PeerId, SocketAddr)],
) {
    let relay_id = args.addr_index.get(from).map(|r| *r);
    if let Some(rid) = relay_id {
        for (pid, pub_addr) in entries {
            if *pid == args.our_peer_id {
                continue;
            }
            let p = args.peer_mgr.discover(*pid, *pub_addr).await;
            p.set_public_addr(*pub_addr).await;

            if !args.sessions.contains_key(pid) {
                args.relay_paths.insert(*pid, rid);
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
                            pub_addr = %pub_addr,
                            "requested relay via peer directory"
                        );
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
            if let Some(mut dst_session) = args.sessions.get_mut(&dst_peer_id) {
                let fwd = seednet_peer::message::serialize_message(&Message::RelayRequest {
                    dst_peer_id: req_id,
                });
                if let Ok(enc) = dst_session.transport.encrypt(&fwd) {
                    let addr = dst_session.underlay.clone();
                    drop(dst_session);
                    let _ = args.transport.send_to(&enc, addr).await;
                }
            }
            if let Some(mut req_session) = args.sessions.get_mut(&req_id) {
                let ready = seednet_peer::message::serialize_message(&Message::RelayReady {
                    relay_peer_id: args.our_peer_id,
                    dst_peer_id,
                });
                if let Ok(enc) = req_session.transport.encrypt(&ready) {
                    let addr = req_session.underlay.clone();
                    drop(req_session);
                    let _ = args.transport.send_to(&enc, addr).await;
                }
            }
        }
    } else {
        let relay_id = args.addr_index.get(from).map(|r| *r);
        if let Some(rid) = relay_id {
            args.relay_paths.insert(dst_peer_id, rid);
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
    from: &TransportAddr,
    dst_peer_id: PeerId,
    payload: Cow<'_, [u8]>,
) {
    if dst_peer_id == args.our_peer_id {
        let sender_id = args.addr_index.get(from).map(|r| *r);
        if let Some(sid) = sender_id
            && let Some(mut session) = args.sessions.get_mut(&sid)
            && let Ok(plain) = session.transport.decrypt(&payload)
        {
            drop(session);
            if let Ok(Message::Data(ip_pkt)) = seednet_peer::message::deserialize_message(&plain) {
                let mut w = args.tun_writer.lock().await;
                let _ = w.send(&ip_pkt).await;
                tracing::debug!(target: "seednet", bytes = ip_pkt.len(), "relayed packet written to TUN");
            }
        }
    } else if args.can_relay {
        let sender_id = args.addr_index.get(from).map(|r| *r);
        let inner = if let Some(sid) = sender_id {
            args.sessions
                .get_mut(&sid)
                .and_then(|mut s| s.transport.decrypt(&payload).ok())
        } else {
            None
        };
        if let Some(decrypted) = inner
            && let Some(mut dst_session) = args.sessions.get_mut(&dst_peer_id)
            && let Ok(re_enc) = dst_session.transport.encrypt(&decrypted)
        {
            let fwd = seednet_peer::message::serialize_message(&Message::RelayData {
                dst_peer_id,
                payload: Cow::Owned(re_enc),
            });
            if let Ok(outer) = dst_session.transport.encrypt(&fwd) {
                let addr = dst_session.underlay.clone();
                drop(dst_session);
                let _ = args.transport.send_to(&outer, addr).await;
                tracing::debug!(target: "seednet", dst = %dst_peer_id.short(), "relayed packet forwarded (re-encrypted)");
            }
        }
    }
}
