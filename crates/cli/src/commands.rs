//! CLI command implementations.
//!
//! For Milestone 1, `identity` is fully functional: it derives the network
//! secret + infohash from the seed, loads (or creates) the per-device identity,
//! and prints a human-readable summary. `up`/`down`/`status` are wired to the
//! state directory and print informative messages; their full networking
//! implementations arrive in later milestones.

use anyhow::Result;
use seednet_common::{Seed, INFOHASH_LEN};
use seednet_config::StateDir;
use seednet_core::{SeedNetConfig, SeedNetEngine};
use seednet_crypto::{
    derive_infohash, derive_network_secret, derive_overlay_addr, DeviceKeys,
};

/// Print the derived network identity for the given seed.
pub async fn identity(state_dir: &StateDir, seed: &Seed) -> Result<()> {
    let secret = derive_network_secret(seed);
    let infohash = derive_infohash(&secret);
    let keys: DeviceKeys = state_dir.load_or_create_identity()?;
    let peer_id = keys.peer_id();
    let overlay = derive_overlay_addr(&peer_id);

    println!("SeedNet identity");
    println!("──────────────────────────────────────────────────────────");
    println!("State dir      : {}", state_dir.path().display());
    println!("Network secret : {}", short_hex(secret.as_bytes(), 8));
    println!(
        "DHT infohash   : {}  ({} bytes)",
        infohash,
        INFOHASH_LEN
    );
    println!("This device    :");
    println!("  PeerId (ed25519 pub) : {}", peer_id);
    println!("  X25519 pub (noise)   : {}", short_hex(&keys.x25519_public_key(), 32));
    println!("  Overlay IPv4         : {}", overlay);
    println!("  Identity file        : {}", state_dir.identity_path().display());
    println!("──────────────────────────────────────────────────────────");

    Ok(())
}

/// Bring the network up.
pub async fn up(state_dir: &StateDir, seed: &Seed, port: u16) -> Result<()> {
    let config = SeedNetConfig::new(seed.clone(), port, state_dir.clone());
    let engine = SeedNetEngine::new(config)?;

    println!("SeedNet starting …");
    println!("  infohash : {}", engine.infohash());
    println!("  overlay  : {} (this device)", engine.our_overlay());
    println!("  peer id  : {}", engine.our_peer_id());
    println!("  port     : {port}");
    println!("  identity : {}", state_dir.identity_path().display());
    println!();
    println!("  Creating TUN interface and starting overlay …");
    println!("  (requires root / CAP_NET_ADMIN)");

    state_dir.write_pid(std::process::id())?;

    if let Err(e) = engine.run().await {
        tracing::error!(target: "seednet", error = %e, "engine error");
    }

    println!("SeedNet shutting down …");
    state_dir.clear_pid()?;
    Ok(())
}

/// Bring the network down by signalling the running daemon via its PID file.
pub async fn down(state_dir: &StateDir) -> Result<()> {
    match state_dir.read_pid()? {
        Some(pid) => {
            println!("Stopping SeedNet (pid {pid}) …");
            signal_pid(pid)?;
            state_dir.clear_pid()?;
            println!("Stopped.");
        }
        None => {
            println!("SeedNet is not running (no PID file at {}).", state_dir.pid_path().display());
        }
    }
    Ok(())
}

/// Run a DHT discovery cycle: announce self, lookup peers, print results.
pub async fn discover(
    seed: &Seed,
    seednet_port: u16,
    dht_port: Option<u16>,
    duration_secs: u64,
) -> Result<()> {
    let secret = derive_network_secret(seed);
    let infohash = derive_infohash(&secret);

    println!("SeedNet discover");
    println!("──────────────────────────────────────────────────────────");
    println!("Infohash : {infohash}");
    println!("Port     : {seednet_port}");

    let bind_port = dht_port.unwrap_or(seednet_port);
    let dht = seednet_dht::DhtDiscovery::start(bind_port)
        .map_err(|e| anyhow::anyhow!("DHT start failed: {e}"))?;

    println!("DHT port : {bind_port}");
    println!("Bootstrap : default Mainline routers");
    println!();

    // Wait for the DHT to bootstrap.
    println!("Bootstrapping …");
    let bootstrapped = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        dht.bootstrapped(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("DHT bootstrap timed out (15s)"))?;

    if bootstrapped {
        println!("Bootstrapped successfully.");
    } else {
        println!("Warning: bootstrap returned false — DHT may not find peers.");
    }

    // Announce ourselves.
    println!("Announcing on port {seednet_port} …");
    dht.announce(&infohash, seednet_port)
        .await
        .map_err(|e| anyhow::anyhow!("announce failed: {e}"))?;
    println!("Announced.");

    // Run periodic lookups for the requested duration.
    let mut all_peers: std::collections::HashSet<std::net::SocketAddr> =
        std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(duration_secs);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));

    println!("Looking up peers for {duration_secs}s …");
    println!();

    while tokio::time::Instant::now() < deadline {
        interval.tick().await;
        let remaining = deadline
            .duration_since(tokio::time::Instant::now())
            .as_secs();
        tracing::info!(target: "seednet", "lookup cycle ({remaining}s remaining)");

        match dht.lookup(&infohash).await {
            Ok(peers) => {
                let before = all_peers.len();
                for p in &peers {
                    all_peers.insert(*p);
                }
                let new_count = all_peers.len() - before;
                println!(
                    "  Lookup: {} peers in this batch ({} new, {} total unique)",
                    peers.len(),
                    new_count,
                    all_peers.len()
                );
            }
            Err(e) => {
                tracing::warn!(target: "seednet", "lookup error: {e}");
                println!("  Lookup error: {e}");
            }
        }
    }

    println!();
    println!("──────────────────────────────────────────────────────────");
    println!("Discovery complete. {} unique peer(s) found:", all_peers.len());
    for peer in &all_peers {
        println!("  {peer}");
    }
    if all_peers.is_empty() {
        println!("  (none — no other devices are currently online with this seed)");
    }
    println!("──────────────────────────────────────────────────────────");

    Ok(())
}

/// Print the current running status.
pub async fn status(state_dir: &StateDir) -> Result<()> {
    match state_dir.read_pid()? {
        Some(pid) => {
            let alive = process_alive(pid);
            println!(
                "SeedNet: {} (pid {pid})",
                if alive { "running" } else { "stale PID" }
            );
            if !alive {
                println!("  (stale PID file left behind; run `seednet down` to clean up)");
            }
            println!("  state dir : {}", state_dir.path().display());
        }
        None => {
            println!("SeedNet: not running");
            println!("  state dir : {}", state_dir.path().display());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn short_hex(bytes: &[u8], take: usize) -> String {
    let n = bytes.len().min(take);
    let mut s = String::with_capacity(n * 2);
    for b in &bytes[..n] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn signal_pid(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        // Send SIGTERM for a graceful shutdown.
        let r = unsafe { libc_kill(pid, 15) };
        if r != 0 {
            anyhow::bail!("failed to signal pid {pid}: errno");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        anyhow::bail!("sending signals is not supported on this platform");
    }
    Ok(())
}

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: u32, sig: i32) -> i32;
}

fn process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // signal 0 = "check existence": returns 0 if the process exists.
        let r = unsafe { libc_kill(pid, 0) };
        r == 0
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}
