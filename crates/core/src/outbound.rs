use std::borrow::Cow;
use std::sync::Arc;

use seednet_common::{OVERLAY_MTU, OverlayAddr, PeerId};
use seednet_peer::Message;
use seednet_routing::RoutingTable;
use seednet_transport::{MultiTransport, Transport};
use tokio::sync::{Mutex, RwLock};

use crate::engine::{RelayCandidates, RelayPaths, Sessions};
use seednet_tun::TunWriter;

pub(crate) struct OutboundArgs {
    pub routing_table: Arc<RwLock<RoutingTable>>,
    pub sessions: Sessions,
    pub transport: Arc<MultiTransport>,
    pub our_overlay: OverlayAddr,
    pub our_peer_id: PeerId,
    pub tun_writer: Arc<Mutex<TunWriter>>,
    pub relay_candidates: RelayCandidates,
    pub relay_paths: RelayPaths,
}

pub(crate) async fn run_outbound_loop(args: OutboundArgs, mut tun_reader: seednet_tun::TunReader) {
    let mut buf = vec![0u8; OVERLAY_MTU + 100];
    let mut ser_buf: Vec<u8> = Vec::with_capacity(OVERLAY_MTU + 64);
    let mut enc_buf: Vec<u8> =
        Vec::with_capacity(OVERLAY_MTU + 64 + seednet_crypto::TRANSPORT_OVERHEAD);

    loop {
        match tun_reader.recv(&mut buf).await {
            Ok(n) => {
                let packet = &buf[..n];
                if packet.is_empty() {
                    continue;
                }

                let dst_ip = seednet_routing::parse_ipv4_packet(packet)
                    .map(|p| p.dst_ip)
                    .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

                if dst_ip == args.our_overlay.ip() {
                    let mut writer = args.tun_writer.lock().await;
                    let _ = writer.send(packet).await;
                    continue;
                }
                let rt = args.routing_table.read().await;
                if let Some(peer_id) = rt.lookup(dst_ip) {
                    let peer_id = *peer_id;
                    drop(rt);
                    if let Some(mut session) = args.sessions.get_mut(&peer_id) {
                        seednet_peer::message::serialize_message_into(
                            &Message::Data(Cow::Owned(packet.to_vec())),
                            &mut ser_buf,
                        );
                        enc_buf.resize(ser_buf.len() + seednet_crypto::TRANSPORT_OVERHEAD, 0);
                        match session.transport.encrypt_into(&ser_buf, &mut enc_buf) {
                            Ok(enc_n) => {
                                let addr = session.underlay.clone();
                                drop(session);
                                let _ = args.transport.send_to(&enc_buf[..enc_n], addr).await;
                            }
                            Err(e) => {
                                tracing::debug!(target: "seednet", peer = %peer_id.short(), error = %e, "encrypt failed");
                            }
                        }
                    } else if let Some(relay_id) = args.relay_paths.get(&peer_id).map(|r| *r) {
                        if let Some(mut relay_session) = args.sessions.get_mut(&relay_id) {
                            seednet_peer::message::serialize_message_into(
                                &Message::Data(Cow::Owned(packet.to_vec())),
                                &mut ser_buf,
                            );
                            let relay_pkt =
                                seednet_peer::message::serialize_message(&Message::RelayData {
                                    src_peer_id: args.our_peer_id,
                                    dst_peer_id: peer_id,
                                    payload: Cow::Owned(ser_buf.clone()),
                                });
                            if let Ok(outer_enc) = relay_session.transport.encrypt(&relay_pkt) {
                                let addr = relay_session.underlay.clone();
                                drop(relay_session);
                                tracing::info!(target: "seednet", dst = %peer_id.short(), relay = %relay_id.short(), to = %addr, "sending relay packet");
                                let _ = args.transport.send_to(&outer_enc, addr).await;
                            }
                        } else {
                            tracing::info!(target: "seednet", dst = %peer_id.short(), relay = %relay_id.short(), "relay path exists but relay has no session");
                        }
                    } else {
                        tracing::debug!(target: "seednet", peer = %peer_id.short(), "no session or relay for peer");
                        // Remove stale route.
                        {
                            let mut rt = args.routing_table.write().await;
                            if let Some(overlay) = rt.lookup_peer_ip(&peer_id) {
                                rt.remove_route(&seednet_common::OverlayAddr::new(overlay));
                                tracing::debug!(target: "seednet", peer = %peer_id.short(), "removed stale route");
                            }
                        }
                        // Request relay setup if we have a candidate.
                        if let Some(relay_entry) = args.relay_candidates.iter().next() {
                            let relay_id = *relay_entry.key();
                            if let Some(mut relay_session) = args.sessions.get_mut(&relay_id) {
                                let req = seednet_peer::message::serialize_message(
                                    &Message::RelayRequest {
                                        dst_peer_id: peer_id,
                                    },
                                );
                                if let Ok(enc) = relay_session.transport.encrypt(&req) {
                                    let addr = relay_session.underlay.clone();
                                    drop(relay_session);
                                    let _ = args.transport.send_to(&enc, addr).await;
                                    tracing::info!(target: "seednet", peer = %peer_id.short(), relay = %relay_id.short(), "requested relay");
                                }
                            }
                        }
                    }
                } else {
                    tracing::trace!(target: "seednet", dst = %dst_ip, "no route for TUN packet");
                }
            }
            Err(e) => {
                tracing::debug!(target: "seednet", error = %e, "TUN recv error");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}
