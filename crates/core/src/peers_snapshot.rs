use std::sync::Arc;

use seednet_common::PeerId;
use seednet_config::StateDir;
use seednet_peer::{PeerEvent, PeerManager, PeerState};
use seednet_routing::RoutingTable;
use tokio::sync::RwLock;

use crate::engine::{AddrIndex, RelayPaths, Sessions};

pub(crate) struct PeersSnapshotArgs {
    pub peer_mgr: Arc<PeerManager>,
    pub routing_table: Arc<RwLock<RoutingTable>>,
    pub state_dir: StateDir,
    pub relay_paths: RelayPaths,
    pub sessions: Sessions,
    pub addr_index: AddrIndex,
    pub local_json: String,
}

pub(crate) async fn run_peers_file_loop(
    args: PeersSnapshotArgs,
    mut peer_events: tokio::sync::broadcast::Receiver<PeerEvent>,
) {
    let _ = args
        .state_dir
        .write_peers_json(&format!(r#"{{"local":{},"peers":[]}}"#, args.local_json));

    loop {
        match peer_events.recv().await {
            Ok(PeerEvent::Removed { id }) => {
                if let Some((_, session)) = args.sessions.remove(&id) {
                    args.addr_index.remove(&session.underlay);
                    tracing::debug!(target: "seednet", peer = %id.short(), "session removed, addr_index cleaned");
                }
                let json = build_peers_json(&args).await;
                let _ = args.state_dir.write_peers_json(&json);
            }
            Ok(PeerEvent::StateChanged {
                to: PeerState::Connected,
                ..
            }) => {
                let json = build_peers_json(&args).await;
                let _ = args.state_dir.write_peers_json(&json);
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(target: "seednet", skipped = n, "peer event channel lagged");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn build_peers_json(args: &PeersSnapshotArgs) -> String {
    let connected = args.peer_mgr.connected_peers().await;
    let rt = args.routing_table.read().await;
    let mut entries = Vec::with_capacity(connected.len());

    for id in &connected {
        let entry = build_peer_entry(id, &rt, args).await;
        entries.push(entry);
    }
    drop(rt);

    format!(
        r#"{{"local":{},"peers":[{}]}}"#,
        args.local_json,
        entries.join(",")
    )
}

async fn build_peer_entry(
    id: &PeerId,
    rt: &seednet_routing::RoutingTable,
    args: &PeersSnapshotArgs,
) -> String {
    let overlay = rt
        .lookup_peer_ip(id)
        .map(|ip| ip.to_string())
        .unwrap_or_default();

    let (underlay, overlay_ipv6, hostname, public_addr_str) =
        if let Some(peer) = args.peer_mgr.get(id) {
            let u = peer
                .underlay_addr()
                .await
                .map(|a| a.to_string())
                .unwrap_or_default();
            let v6 = peer
                .overlay_ipv6()
                .await
                .map(|a| a.to_string())
                .unwrap_or_default();
            let h = peer.hostname().await;
            let pa = peer
                .public_addr()
                .await
                .map(|a| a.to_string())
                .unwrap_or_default();
            (u, v6, h, pa)
        } else {
            (String::new(), String::new(), String::new(), String::new())
        };

    let (connection, relay_via) = if let Some(relay_id) = args.relay_paths.get(id) {
        ("relay", relay_id.short().to_string())
    } else {
        ("direct", String::new())
    };

    let latency = if let Some(peer) = args.peer_mgr.get(id) {
        peer.latency_ms()
            .await
            .map(|ms| ms.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };

    format!(
        concat!(
            r#"{{"id":"{id}","id_short":"{short}","#,
            r#""overlay":"{overlay}","overlay_ipv6":"{ipv6}","#,
            r#""hostname":"{hostname}","public_addr":"{pub_addr}","#,
            r#""connection":"{connection}","relay_via":"{relay_via}","#,
            r#""latency_ms":"{latency}","#,
            r#""underlay":"{underlay}"}}"#,
        ),
        id = id,
        short = id.short(),
        overlay = overlay,
        ipv6 = overlay_ipv6,
        hostname = hostname,
        pub_addr = public_addr_str,
        connection = connection,
        relay_via = relay_via,
        latency = latency,
        underlay = underlay,
    )
}
