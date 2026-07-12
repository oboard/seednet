# SeedNet

A decentralized private overlay network. One seed. No accounts. No cloud controller. No database.

```
seednet up "correct horse battery staple"
```

Every device using the same seed automatically joins the same network, discovered
via BitTorrent Mainline DHT and secured with Noise XX (ChaCha20-Poly1305).

## Architecture

```
Seed ──HKDF-SHA256──▶ NetworkSecret (32 bytes)
                    ├── SHA-1 ──▶ InfoHash  ──▶ BitTorrent Mainline DHT (peer discovery only)
                    └── Noise prologue (session authentication)

Per-device (random, persisted):
    Ed25519 keypair  → PeerId, overlay IP
    X25519 static key → Noise XX static key
```

- **DHT** is used *only* for peer discovery. SeedNet is not a BitTorrent client.
- **Per-device keys** are generated randomly on first run and persisted to
  `~/.seednet/identity.bin`. The shared seed does **not** derive device keys —
  that would give every device an identical private key, breaking mutual
  authentication. The seed only gates *network membership* (via the Noise
  prologue) and produces the DHT infohash.

## Building

Requires Rust 1.93.1 (see `rust-toolchain.toml`).

```sh
cargo build --release
```

## Crates

| Crate | Purpose |
|---|---|
| `seednet-common` | Shared types, errors, constants |
| `seednet-crypto` | HKDF derivation, Ed25519/X25519 keys, overlay IP |
| `seednet-config` | Identity persistence, state directory |
| `seednet-dht` | BitTorrent Mainline DHT wrapper (announce/lookup) |
| `seednet-peer` | Peer state machine, message layer |
| `seednet-tun` | Cross-platform TUN interface |
| `seednet-overlay` | Overlay IP allocation and collision detection |
| `seednet-routing` | TUN ↔ peer packet routing |
| `seednet-core` | Orchestration engine |
| `seednet-cli` | Command-line interface (`seednet` binary) |

## CLI

```
seednet up <SEED>          Bring the network up (foreground)
seednet down               Bring the network down
seednet status             Show running state
seednet identity <SEED>    Print derived identity (does not start network)
```

Options:
- `--state-dir <PATH>` — override `~/.seednet` (env: `SEEDNET_STATE_DIR`)
- `-v / -vv / -vvv` — increase log verbosity (info / debug / trace)

## Dependency Note

The spec named `bittorrent-dht`, which no longer exists on crates.io. SeedNet
uses **[`mainline` 7.0.0](https://crates.io/crates/mainline)**, the actively
maintained successor that provides the same BEP\_0005 Mainline DHT
announce/lookup API, fully async.

---

## Milestone Verification

Each milestone must compile, pass tests, and be verifiable before proceeding.

### Milestone 1 — CLI + Identity from Seed ✓

```sh
cargo build --workspace
cargo test --workspace          # 30 tests pass

cargo run -- identity "correct horse battery staple" --state-dir /tmp/sn1
# → prints infohash, PeerId, overlay IP

# Verify determinism: same seed → same infohash
cargo run -- identity "correct horse battery staple" --state-dir /tmp/sn1
# → identical infohash, same PeerId (persisted)

# Verify different seed → different infohash
cargo run -- identity "other seed" --state-dir /tmp/sn2
# → different infohash
```

### Milestone 2 — DHT announce/lookup ✓

```sh
cargo build --workspace
cargo test --workspace          # 32 tests pass (includes local 2-node DHT discovery)

# Live DHT discovery (5s quick run):
cargo run -- discover "correct horse battery staple" --duration 5 --state-dir /tmp/sn

# Two terminals, same seed (discover each other):
cargo run -- discover "test net" --duration 30 --state-dir /tmp/sn-a --port 4242
cargo run -- discover "test net" --duration 30 --state-dir /tmp/sn-b --port 4243
# → both announce the same infohash, discover each other
```

### Milestone 3 — Peer state machine

```sh
cargo test --workspace  # PeerState transition tests
```

### Milestone 4 — Noise XX handshake

```sh
cargo test --workspace  # handshake + encrypt/decrypt roundtrip tests
```

### Milestone 5 — Reliable message layer

```sh
cargo test --workspace  # heartbeat, session expiry, fragmentation tests
```

### Milestone 6 — Cross-platform TUN

```sh
cargo build --workspace -p seednet-tun  # must compile for linux, macos, windows targets
```

### Milestone 7 — Overlay IP allocation

```sh
cargo test --workspace  # deterministic, collision resolution tests
```

### Milestone 8 — Routing

```sh
cargo test --workspace  # packet parse, route lookup, encrypt/decrypt-through-router
```

### Milestone 9 — Peer management

```sh
cargo run -- up "correct horse battery staple"
# → TUN up, DHT joined, peers connected, keepalive running
```

### Milestone 10 — Cross-platform integration

```sh
# Two machines, same seed:
cargo run -- up "correct horse battery staple"   # machine A
cargo run -- up "correct horse battery staple"   # machine B
ping <overlay-ip-of-B>   # from A → succeeds over encrypted UDP
```

## License

MIT OR Apache-2.0
