//! CLI command implementations.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context as _, Result};
use seednet_common::{INFOHASH_LEN, Seed};
use seednet_config::StateDir;
use seednet_core::{SeedNetConfig, SeedNetEngine};
use seednet_crypto::{DeviceKeys, derive_infohash, derive_network_secret, derive_overlay_addr};

// ---------------------------------------------------------------------------
// up — launch the engine as a background daemon
// ---------------------------------------------------------------------------

/// Bring the network up by re-execing this binary as a hidden `_daemon`
/// subcommand.  Returns to the shell immediately once the daemon has written
/// its PID file.
pub async fn up(
    state_dir: &StateDir,
    seed: &Seed,
    port: u16,
    explicit_state_dir: Option<&Path>,
) -> Result<()> {
    // Already running?
    if let Some(pid) = state_dir.read_pid()? {
        if process_alive(pid) {
            println!("SeedNet is already running (pid {pid}).");
            return Ok(());
        }
        // Stale PID file — clear it before re-launching.
        state_dir.clear_pid()?;
    }

    // Spawn ourselves as `_daemon <seed> --port <port> [--state-dir <path>]`.
    let exe = std::env::current_exe().context("could not determine current executable")?;
    let seed_str = String::from_utf8_lossy(seed.as_bytes()).into_owned();

    let log_path = state_dir.log_path();
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .context("could not open daemon log file")?;

    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("_daemon")
        .arg(&seed_str)
        .arg("--port")
        .arg(port.to_string());

    // Forward --state-dir only when it was explicitly set.
    if let Some(dir) = explicit_state_dir {
        cmd.arg("--state-dir").arg(dir);
    }

    // Detach stdin; redirect stdout+stderr to the log file so errors are
    // captured and can be shown to the user if startup fails.
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log_file);

    // On Unix: put the daemon in its own process group so it is not killed
    // when the user's shell session ends.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }

    let mut child = cmd.spawn().context("failed to launch SeedNet daemon")?;

    // Wait up to 5 s for the daemon to write its PID file.
    // If the child process exits before writing the PID we know it crashed.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        // Non-blocking check: did the daemon already die?
        match child.try_wait() {
            Ok(Some(status)) => {
                // Daemon exited before writing PID — it crashed.
                let log_tail = read_log_tail(&log_path, 20);
                anyhow::bail!(
                    "SeedNet daemon exited immediately ({})\n\
                     Log ({}):\n{}",
                    status,
                    log_path.display(),
                    log_tail,
                );
            }
            Ok(None) => {} // still running
            Err(_) => {}   // can't check; proceed
        }

        if let Some(pid) = state_dir.read_pid()?
            && process_alive(pid)
        {
            break; // daemon is up and healthy
            // If PID was written but process already exited — it crashed right
            // after writing the PID file.  Fall through so we pick up the
            // child.try_wait() path on the next tick.
        }

        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let log_tail = read_log_tail(&log_path, 20);
            anyhow::bail!(
                "daemon did not start within 5 s\n\
                 Log ({}):\n{}",
                log_path.display(),
                log_tail,
            );
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let pid = state_dir.read_pid()?.unwrap_or(0);

    // Derive the overlay address without touching the network.
    let keys = state_dir.load_or_create_identity()?;
    let overlay = derive_overlay_addr(&keys.peer_id());

    println!("SeedNet started  (pid {pid})");
    println!("  overlay : {overlay}  (this device)");
    println!("  port    : {port}");
    println!("  log     : {}", log_path.display());
    println!();
    println!("  seednet list   — show connected peers");
    println!("  seednet down   — stop");

    Ok(())
}

// ---------------------------------------------------------------------------
// daemon — the hidden subcommand that runs the engine in the foreground
// ---------------------------------------------------------------------------

/// Run the engine in the foreground.  Invoked by `up`; not intended for
/// direct use.
pub async fn daemon(state_dir: &StateDir, seed: &Seed, port: u16) -> Result<()> {
    let config = SeedNetConfig::new(seed.clone(), port, state_dir.clone());
    let engine = SeedNetEngine::new(config)?;

    // Write PID *before* starting network I/O so that `up` can detect us.
    state_dir.write_pid(std::process::id())?;

    let result = engine.run().await;

    state_dir.clear_pid()?;
    state_dir.clear_peers_json()?;

    // Propagate engine errors — this causes a non-zero exit code and writes
    // the error message to stderr (which `up` redirects to seednet.log).
    result.map_err(|e| anyhow::anyhow!("engine error: {e}"))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// down — signal the running daemon
// ---------------------------------------------------------------------------

/// Stop the running daemon.
pub async fn down(state_dir: &StateDir) -> Result<()> {
    match state_dir.read_pid()? {
        Some(pid) if process_alive(pid) => {
            println!("Stopping SeedNet (pid {pid}) …");
            signal_pid(pid)?;
            // Give the daemon a moment to clean up its own files; if it does
            // not, remove them here so the state dir stays tidy.
            std::thread::sleep(std::time::Duration::from_millis(500));
            let _ = state_dir.clear_pid();
            let _ = state_dir.clear_peers_json();
            println!("Stopped.");
        }
        Some(pid) => {
            println!("SeedNet has a stale PID file (pid {pid}); cleaning up.");
            let _ = state_dir.clear_pid();
            let _ = state_dir.clear_peers_json();
            // Also try to kill any orphaned daemon processes.
            kill_orphaned_daemons();
        }
        None => {
            // No PID file — look for orphaned daemon processes by name.
            let killed = kill_orphaned_daemons();
            if killed > 0 {
                let _ = state_dir.clear_pid();
                let _ = state_dir.clear_peers_json();
                println!("Stopped {killed} orphaned SeedNet daemon(s).");
            } else {
                println!("SeedNet is not running.");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// list — show connected peers
// ---------------------------------------------------------------------------

/// Print the list of currently connected overlay peers.
pub async fn list(state_dir: &StateDir) -> Result<()> {
    let running = state_dir.read_pid()?.map(process_alive).unwrap_or(false);

    if !running {
        println!("SeedNet is not running.");
        return Ok(());
    }

    let json_str = match state_dir.read_peers_json()? {
        Some(s) => s,
        None => {
            println!("No peers connected yet.");
            return Ok(());
        }
    };

    let data: serde_json::Value =
        serde_json::from_str(&json_str).context("peers.json is malformed")?;

    let peers = match data["peers"].as_array() {
        Some(a) => a.as_slice(),
        None => &[],
    };

    if peers.is_empty() {
        println!("No peers connected.");
        return Ok(());
    }

    let col_id = 10usize;
    let col_overlay = 16usize;
    let col_underlay = 26usize;

    println!(
        "{:<col_id$}  {:<col_overlay$}  {:<col_underlay$}",
        "PEER ID", "OVERLAY IP", "UNDERLAY ADDR"
    );
    println!(
        "{}",
        "─".repeat(col_id + 2 + col_overlay + 2 + col_underlay)
    );

    for p in peers {
        let short = p["id_short"].as_str().unwrap_or("?");
        let overlay = p["overlay"].as_str().unwrap_or("?");
        let under = p["underlay"].as_str().unwrap_or("?");
        println!(
            "{:<col_id$}  {:<col_overlay$}  {:<col_underlay$}",
            short, overlay, under
        );
    }
    println!();
    println!("{} peer(s) connected.", peers.len());

    Ok(())
}

// ---------------------------------------------------------------------------
// status — human-readable running state
// ---------------------------------------------------------------------------

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
                println!("  (stale PID file; run `seednet down` to clean up)");
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
// identity — print derived identity without joining the network
// ---------------------------------------------------------------------------

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
    println!("DHT infohash   : {}  ({} bytes)", infohash, INFOHASH_LEN);
    println!("This device    :");
    println!("  PeerId (ed25519 pub) : {}", peer_id);
    println!(
        "  X25519 pub (noise)   : {}",
        short_hex(&keys.x25519_public_key(), 32)
    );
    println!("  Overlay IPv4         : {}", overlay);
    println!(
        "  Identity file        : {}",
        state_dir.identity_path().display()
    );
    println!("──────────────────────────────────────────────────────────");

    Ok(())
}

// ---------------------------------------------------------------------------
// discover — one-shot DHT peer discovery
// ---------------------------------------------------------------------------

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

    println!("Bootstrapping …");
    let bootstrapped = tokio::time::timeout(std::time::Duration::from_secs(15), dht.bootstrapped())
        .await
        .map_err(|_| anyhow::anyhow!("DHT bootstrap timed out (15s)"))?;

    if bootstrapped {
        println!("Bootstrapped successfully.");
    } else {
        println!("Warning: bootstrap returned false — DHT may not find peers.");
    }

    println!("Announcing on port {seednet_port} …");
    dht.announce(&infohash, seednet_port)
        .await
        .map_err(|e| anyhow::anyhow!("announce failed: {e}"))?;
    println!("Announced.");

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
    println!(
        "Discovery complete. {} unique peer(s) found:",
        all_peers.len()
    );
    for peer in &all_peers {
        println!("  {peer}");
    }
    if all_peers.is_empty() {
        println!("  (none — no other devices are currently online with this seed)");
    }
    println!("──────────────────────────────────────────────────────────");

    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Read the last `n` lines from a file for error reporting.
fn read_log_tail(path: &std::path::Path, n: usize) -> String {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return "(log not available)".to_string(),
    };
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Find and SIGTERM any orphaned `seednet _daemon` processes.
/// Returns the number of processes signalled.
/// On non-Unix this is a no-op.
fn kill_orphaned_daemons() -> usize {
    #[cfg(unix)]
    {
        // `pgrep -f "seednet _daemon"` finds processes by full command line.
        let output = std::process::Command::new("pgrep")
            .args(["-f", "seednet _daemon"])
            .output();

        let pids: Vec<u32> = match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
                // Skip ourselves.
                .filter(|&p| p != std::process::id())
                .collect(),
            _ => return 0,
        };

        let mut killed = 0;
        for pid in pids {
            if signal_pid(pid).is_ok() {
                killed += 1;
            }
        }
        killed
    }
    #[cfg(not(unix))]
    {
        0
    }
}

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
        let r = unsafe { libc_kill(pid, 15) };
        if r != 0 {
            anyhow::bail!("failed to signal pid {pid}");
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
        let r = unsafe { libc_kill(pid, 0) };
        r == 0
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}
