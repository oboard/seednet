//! `seednet` — command-line entry point.
//!
//! * `seednet` (no subcommand) — launch the interactive TUI.
//! * `seednet up <SEED>` — launch the overlay as a background daemon.
//! * `seednet down` — stop the running daemon.
//! * `seednet list` — list connected peers.
//! * `seednet status` — show running/stopped state.
//! * `seednet identity <SEED>` — print the derived network identity without
//!   joining the network.
//! * `seednet discover <SEED>` — one-shot DHT peer discovery.
//! * `seednet _daemon <SEED>` — internal: run the engine in the foreground
//!   (hidden from help; invoked by `up`).

mod commands;
mod logging;
mod tui;

use anyhow::Result;
use clap::{Parser, Subcommand};

use seednet_common::Seed;
use seednet_crypto::{derive_network_secret, derive_port};
/// SeedNet: a decentralized private overlay network. One seed. No accounts.
#[derive(Debug, Parser)]
#[command(
    name = "seednet",
    version,
    about = "Decentralized private overlay network (BitTorrent DHT peer discovery)",
    long_about = None
)]
struct Cli {
    /// Override the state directory (default: ~/.seednet).
    #[arg(long, global = true, env = "SEEDNET_STATE_DIR")]
    state_dir: Option<std::path::PathBuf>,

    /// Increase verbosity (`-v` info, `-vv` debug, `-vvv` trace).
    #[arg(long, short = 'v', global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Bring the overlay network up and run it in the background.
    Up {
        /// The network seed (passphrase). Every device with the same seed
        /// joins the same network.
        seed: String,
        /// UDP port to listen on. Defaults to a port derived from the seed
        /// so all peers on the same network use the same port automatically.
        #[arg(long)]
        port: Option<u16>,
        /// Comma-separated list of transport protocols to enable.
        /// Available: udp, tcp, ws  (default: all)
        /// Example: --transport udp,tcp,ws
        #[arg(long, default_value = "udp,tcp,ws")]
        transport: String,
        /// Comma-separated tracker addresses to connect to immediately
        /// on startup (bypasses DHT discovery latency).
        /// Example: --tracker 120.25.179.85:31211
        #[arg(long, default_value = "")]
        tracker: String,
        /// Comma-separated BitTorrent tracker URLs (HTTP or UDP).
        /// Example: --tracker-url udp://tracker.opentrackr.org:1337
        #[arg(long, default_value = "")]
        tracker_url: String,
    },
    /// Bring the overlay network down (stops the running daemon).
    Down,
    /// List connected peers in the overlay network.
    List,
    /// Print the current running status.
    Status,
    /// Derive and print the network identity for the given seed, then exit.
    /// Does not start the network.
    Identity {
        /// The network seed (passphrase).
        seed: String,
    },
    /// Join the DHT, announce this device, look up peers for the given seed,
    /// print discovered peers, then exit.
    Discover {
        /// The network seed (passphrase).
        seed: String,
        /// UDP port for SeedNet traffic. Defaults to the seed-derived port.
        #[arg(long)]
        port: Option<u16>,
        /// DHT port (bind). Defaults to the SeedNet port.
        #[arg(long)]
        dht_port: Option<u16>,
        /// How long to run the lookup before exiting (seconds, default 30).
        #[arg(long, default_value_t = 30)]
        duration: u64,
    },
    /// Internal: run the engine in the foreground as the background daemon.
    /// Invoked automatically by `seednet up`; not shown in help.
    #[command(hide = true, name = "_daemon")]
    Daemon {
        /// The network seed (passphrase).
        seed: String,
        /// UDP port to listen on.
        #[arg(long)]
        port: Option<u16>,
        /// Comma-separated transport protocols.
        #[arg(long, default_value = "udp,tcp,ws")]
        transport: String,
        /// Comma-separated direct peer addresses.
        #[arg(long, default_value = "")]
        tracker: String,
        /// Comma-separated BitTorrent tracker URLs.
        #[arg(long, default_value = "")]
        tracker_url: String,
    },
}

fn parse_trackers(s: &str) -> Vec<std::net::SocketAddr> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .filter_map(|t| {
            let addr = t.trim();
            match addr.parse::<std::net::SocketAddr>() {
                Ok(a) => Some(a),
                Err(_) => {
                    eprintln!("invalid tracker address '{addr}', ignoring");
                    None
                }
            }
        })
        .collect()
}

fn parse_tracker_urls(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(',')
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect()
}

fn parse_transports(s: &str) -> Vec<seednet_transport::TransportKind> {
    s.split(',')
        .filter_map(|t| match t.trim().to_ascii_lowercase().as_str() {
            "udp" => Some(seednet_transport::TransportKind::Udp),
            "tcp" => Some(seednet_transport::TransportKind::Tcp),
            "ws" => Some(seednet_transport::TransportKind::Ws),
            "wss" => Some(seednet_transport::TransportKind::Wss),
            other => {
                eprintln!("unknown transport '{other}', ignoring");
                None
            }
        })
        .collect()
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let state_dir = match cli.state_dir.clone() {
        Some(p) => seednet_config::StateDir::new(p)?,
        None => seednet_config::StateDir::default_user()?,
    };

    // No subcommand → launch TUI.
    let Some(command) = cli.command else {
        let state_path = state_dir.path().to_path_buf();
        let exe = std::env::current_exe()?;
        return tui::run(state_path, exe);
    };

    logging::init(cli.verbose);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    match command {
        Command::Identity { seed } => {
            let seed = Seed::from_passphrase(&seed);
            rt.block_on(commands::identity(&state_dir, &seed))?;
        }
        Command::Status => {
            rt.block_on(commands::status(&state_dir))?;
        }
        Command::Down => {
            rt.block_on(commands::down(&state_dir))?;
        }
        Command::Up {
            seed,
            port,
            transport,
            tracker,
            tracker_url,
        } => {
            let state_dir_path = cli.state_dir;
            let seed = Seed::from_passphrase(&seed);
            let port = port.unwrap_or_else(|| derive_port(&derive_network_secret(&seed)));
            let transports = parse_transports(&transport);
            let direct_peers = parse_trackers(&tracker);
            let tracker_urls = parse_tracker_urls(&tracker_url);
            rt.block_on(commands::up(
                &state_dir,
                &seed,
                port,
                state_dir_path.as_deref(),
                transports,
                direct_peers,
                tracker_urls,
            ))?;
        }
        Command::List => {
            rt.block_on(commands::list(&state_dir))?;
        }
        Command::Discover {
            seed,
            port,
            dht_port,
            duration,
        } => {
            let seed = Seed::from_passphrase(&seed);
            let port = port.unwrap_or_else(|| derive_port(&derive_network_secret(&seed)));
            rt.block_on(commands::discover(&seed, port, dht_port, duration))?;
        }
        Command::Daemon {
            seed,
            port,
            transport,
            tracker,
            tracker_url,
        } => {
            let seed = Seed::from_passphrase(&seed);
            let port = port.unwrap_or_else(|| derive_port(&derive_network_secret(&seed)));
            let transports = parse_transports(&transport);
            let direct_peers = parse_trackers(&tracker);
            let tracker_urls = parse_tracker_urls(&tracker_url);
            rt.block_on(commands::daemon(
                &state_dir,
                &seed,
                port,
                transports,
                direct_peers,
                tracker_urls,
            ))?;
        }
    }

    Ok(())
}
