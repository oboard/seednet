//! `seednet` — command-line entry point.
//!
//! Milestone 1 implements:
//!   * `seednet up <SEED>`        — bring the network up (stubbed for now; full
//!                                   wiring arrives in later milestones).
//!   * `seednet down`             — bring the network down.
//!   * `seednet status`           — show running state.
//!   * `seednet identity <SEED>`  — print the derived network identity
//!                                   (infohash, this device's PeerId and overlay
//!                                   address) without joining the network.

mod logging;
mod commands;

use anyhow::Result;
use clap::{Parser, Subcommand};

use seednet_common::Seed;

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
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Bring the overlay network up and keep it running in the foreground.
    Up {
        /// The network seed (passphrase). Every device with the same seed
        /// joins the same network.
        seed: String,
        /// UDP port to listen on (default 4242).
        #[arg(long, default_value_t = seednet_common::DEFAULT_PORT)]
        port: u16,
    },
    /// Bring the overlay network down (stops a running `up` daemon).
    Down,
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
        /// UDP port for SeedNet traffic (default 4242).
        #[arg(long, default_value_t = seednet_common::DEFAULT_PORT)]
        port: u16,
        /// DHT port (bind). Defaults to the SeedNet port.
        #[arg(long)]
        dht_port: Option<u16>,
        /// How long to run the lookup before exiting (seconds, default 30).
        #[arg(long, default_value_t = 30)]
        duration: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let state_dir = match cli.state_dir.clone() {
        Some(p) => seednet_config::StateDir::new(p)?,
        None => seednet_config::StateDir::default_user()?,
    };

    logging::init(cli.verbose);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    match cli.command {
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
        Command::Up { seed, port } => {
            let seed = Seed::from_passphrase(&seed);
            rt.block_on(commands::up(&state_dir, &seed, port))?;
        }
        Command::Discover {
            seed,
            port,
            dht_port,
            duration,
        } => {
            let seed = Seed::from_passphrase(&seed);
            rt.block_on(commands::discover(&seed, port, dht_port, duration))?;
        }
    }

    Ok(())
}
