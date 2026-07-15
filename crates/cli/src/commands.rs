//! CLI command implementations.

use std::path::Path;
#[cfg(not(target_os = "macos"))]
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

    let exe = std::env::current_exe().context("could not determine current executable")?;
    let seed_str = String::from_utf8_lossy(seed.as_bytes()).into_owned();
    let log_path = state_dir.log_path();

    // On macOS: spawn the daemon directly in this process's session (so it
    // inherits the Network Extension context and bypasses corporate filters),
    // then install a launchd plist so the *user* can re-run `seednet up` after
    // a reboot to get it back.  We do NOT use RunAtLoad because a System daemon
    // runs outside the user's Network Extension context and gets filtered.
    #[cfg(target_os = "macos")]
    {
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .context("could not open daemon log file")?;

        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("_daemon")
            .arg(&seed_str)
            .arg("--port")
            .arg(port.to_string())
            .arg("-v")
            .arg("--state-dir")
            .arg(state_dir.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(log_file);

        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);

        let mut child = cmd.spawn().context("failed to launch SeedNet daemon")?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let log_tail = read_log_tail(&log_path, 20);
                    anyhow::bail!(
                        "SeedNet daemon exited immediately ({})\nLog ({}):\n{}",
                        status,
                        log_path.display(),
                        log_tail,
                    );
                }
                Ok(None) => {}
                Err(_) => {}
            }
            if let Some(pid) = state_dir.read_pid()?
                && process_alive(pid)
            {
                break;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let log_tail = read_log_tail(&log_path, 20);
                anyhow::bail!(
                    "daemon did not start within 5 s\nLog ({}):\n{}",
                    log_path.display(),
                    log_tail,
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let pid = state_dir.read_pid()?.unwrap_or(0);
        let keys = state_dir.load_or_create_identity()?;
        let overlay = derive_overlay_addr(&keys.peer_id());

        println!("SeedNet started  (pid {pid})");
        println!("  overlay : {overlay}  (this device)");
        println!("  port    : {port}");
        println!("  log     : {}", log_path.display());
        println!();
        println!("  seednet list   — show connected peers");
        println!("  seednet down   — stop");

        // Install launchd plist (without RunAtLoad) so params are remembered.
        // After reboot, run `sudo seednet up <seed>` to restart.
        let _ = remove_launchd();
        match install_launchd(
            &exe,
            &seed_str,
            port,
            state_dir.path(),
            &log_path,
            explicit_state_dir,
        ) {
            Ok(()) => {
                println!("  boot    : plist saved — run `sudo seednet up oboard` after reboot")
            }
            Err(e) => println!("  boot    : plist install failed — {e}"),
        }

        Ok(())
    }

    // Non-macOS: spawn the daemon directly.
    #[cfg(not(target_os = "macos"))]
    {
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .context("could not open daemon log file")?;

        let mut cmd = std::process::Command::new(&exe);
        cmd.arg("_daemon")
            .arg(&seed_str)
            .arg("--port")
            .arg(port.to_string())
            .arg("-v");

        if let Some(dir) = explicit_state_dir {
            cmd.arg("--state-dir").arg(dir);
        }

        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log_file);

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            cmd.process_group(0);
        }

        let mut child = cmd.spawn().context("failed to launch SeedNet daemon")?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let log_tail = read_log_tail(&log_path, 20);
                    anyhow::bail!(
                        "SeedNet daemon exited immediately ({})\nLog ({}):\n{}",
                        status,
                        log_path.display(),
                        log_tail,
                    );
                }
                Ok(None) => {}
                Err(_) => {}
            }

            if let Some(pid) = state_dir.read_pid()?
                && process_alive(pid)
            {
                break;
            }

            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                let log_tail = read_log_tail(&log_path, 20);
                anyhow::bail!(
                    "daemon did not start within 5 s\nLog ({}):\n{}",
                    log_path.display(),
                    log_tail,
                );
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let pid = state_dir.read_pid()?.unwrap_or(0);
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
    } // end #[cfg(not(target_os = "macos"))]
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
    // Remove the boot service first so it doesn't restart the daemon we're about to stop.
    #[cfg(target_os = "macos")]
    let _ = remove_launchd();

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

    let col_id = 18usize;
    let col_overlay = 16usize;
    let col_ipv6 = 40usize;
    let col_conn = 10usize;
    let col_underlay = 26usize;

    println!(
        "{:<col_id$}  {:<col_overlay$}  {:<col_ipv6$}  {:<col_conn$}  {:<col_underlay$}",
        "PEER ID (hostname)", "OVERLAY IPv4", "OVERLAY IPv6", "CONN", "UNDERLAY ADDR"
    );
    println!(
        "{}",
        "─".repeat(col_id + 2 + col_overlay + 2 + col_ipv6 + 2 + col_conn + 2 + col_underlay)
    );

    for p in peers {
        let short = p["id_short"].as_str().unwrap_or("?");
        let overlay = p["overlay"].as_str().unwrap_or("?");
        let ipv6 = p["overlay_ipv6"].as_str().unwrap_or("");
        let hostname = p["hostname"].as_str().unwrap_or("");
        let connection = p["connection"].as_str().unwrap_or("direct");
        let relay_via = p["relay_via"].as_str().unwrap_or("");
        let under = p["underlay"].as_str().unwrap_or("?");
        let display_id = if hostname.is_empty() {
            short.to_string()
        } else {
            format!("{short} ({hostname})")
        };
        let conn_display = if connection == "relay" && !relay_via.is_empty() {
            format!("relay/{relay_via}")
        } else {
            connection.to_string()
        };
        println!(
            "{:<col_id$}  {:<col_overlay$}  {:<col_ipv6$}  {:<col_conn$}  {:<col_underlay$}",
            display_id, overlay, ipv6, conn_display, under
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
        // r == 0: process exists and we can signal it
        // EPERM (-1, errno=EPERM): process exists but we lack permission (e.g. root process)
        if r == 0 {
            return true;
        }
        #[cfg(target_os = "macos")]
        {
            r == -1 && unsafe { *libc::__error() } == libc::EPERM
        }
        #[cfg(not(target_os = "macos"))]
        {
            r == -1 && unsafe { *libc::__errno_location() } == libc::EPERM
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

// ---------------------------------------------------------------------------
// launchd integration (macOS only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
const LAUNCHD_LABEL: &str = "fun.oboard.seednet";
#[cfg(target_os = "macos")]
const LAUNCHD_PLIST: &str = "/Library/LaunchDaemons/fun.oboard.seednet.plist";

#[cfg(target_os = "macos")]
fn install_launchd(
    exe: &std::path::Path,
    seed_str: &str,
    port: u16,
    state_dir: &std::path::Path,
    log_path: &std::path::Path,
    explicit_state_dir: Option<&std::path::Path>,
) -> Result<()> {
    // Use the explicit state dir in the plist if provided, otherwise the default.
    let state_dir_arg = explicit_state_dir.unwrap_or(state_dir);
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>_daemon</string>
        <string>{seed}</string>
        <string>--port</string>
        <string>{port}</string>
        <string>-v</string>
        <string>--state-dir</string>
        <string>{state_dir_arg}</string>
    </array>
    <key>StandardErrorPath</key>
    <string>{log}</string>
</dict>
</plist>
"#,
        label = LAUNCHD_LABEL,
        exe = exe.display(),
        seed = seed_str,
        port = port,
        state_dir_arg = state_dir_arg.display(),
        log = log_path.display(),
    );

    std::fs::write(LAUNCHD_PLIST, plist.as_bytes())
        .with_context(|| format!("write {LAUNCHD_PLIST}"))?;

    // Modern macOS (Ventura+) uses `launchctl bootstrap system <plist>`.
    // Fall back to legacy `launchctl load -w` if bootstrap fails.
    let bootstrap_out = std::process::Command::new("launchctl")
        .args(["bootstrap", "system", LAUNCHD_PLIST])
        .output();
    match bootstrap_out {
        Ok(o) if o.status.success() => return Ok(()),
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if stderr.contains("already") || stderr.contains("exists") {
                return Ok(());
            }
            // bootstrap failed — try legacy load
            let _ = o; // suppress warning
        }
        Err(_) => {} // launchctl not found? fall through
    }
    // Legacy fallback (older macOS)
    let out = std::process::Command::new("launchctl")
        .args(["load", "-w", LAUNCHD_PLIST])
        .output()
        .context("launchctl load")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !stderr.to_lowercase().contains("already") {
            anyhow::bail!("launchctl load: {stderr}");
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_launchd() -> Result<()> {
    let plist = std::path::Path::new(LAUNCHD_PLIST);
    if !plist.exists() {
        return Ok(());
    }
    // Try modern bootout first, then legacy unload.
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", "system", LAUNCHD_PLIST])
        .output();
    let _ = std::process::Command::new("launchctl")
        .args(["unload", "-w", LAUNCHD_PLIST])
        .output();
    let _ = std::fs::remove_file(plist);
    Ok(())
}
