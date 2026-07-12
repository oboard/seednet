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
| `seednet-crypto` | HKDF derivation, Ed25519/X25519 keys, Noise XX, overlay IP |
| `seednet-config` | Identity persistence, state directory |
| `seednet-dht` | BitTorrent Mainline DHT wrapper (announce/lookup) |
| `seednet-peer` | Peer state machine, message layer, session management |
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
seednet discover <SEED>    Join DHT, announce, and look up peers
```

Options:
- `--state-dir <PATH>` — override `~/.seednet` (env: `SEEDNET_STATE_DIR`)
- `--port <PORT>` — UDP listen port (default 4242)
- `--duration <SECS>` — discovery run time (default 30, `discover` only)
- `-v / -vv / -vvv` — increase log verbosity (info / debug / trace)

## Dependency Note

The spec named `bittorrent-dht`, which no longer exists on crates.io. SeedNet
uses **[`mainline` 7.0.0](https://crates.io/crates/mainline)**, the actively
maintained successor that provides the same BEP\_0005 Mainline DHT
announce/lookup API, fully async.

---

## Milestone Verification

Each milestone compiles, passes tests, and is verifiable.

### Milestone 1 — CLI + Identity from Seed ✓

```sh
cargo build --workspace
cargo test --workspace          # 10 tests (common) + 5 (config) + 15 (crypto)

cargo run -- identity "correct horse battery staple" --state-dir /tmp/sn1
# → prints infohash, PeerId, overlay IP
```

### Milestone 2 — DHT announce/lookup ✓

```sh
cargo test --workspace          # +2 DHT tests (local 2-node discovery)

cargo run -- discover "correct horse battery staple" --duration 5 --state-dir /tmp/sn
```

### Milestone 3 — Peer state machine ✓

```sh
cargo test --workspace  # +24 peer tests (state transitions, manager, events)
```

### Milestone 4 — Noise XX handshake ✓

```sh
cargo test --workspace  # +6 Noise tests (roundtrip, wrong-prologue, remote static)
```

### Milestone 5 — Reliable message layer ✓

```sh
cargo test --workspace  # +6 message/frame/session tests (serialize, framing, expiry)
```

### Milestone 6 — Cross-platform TUN ✓

```sh
cargo test --workspace  # +4 TUN config tests (subnet mask, config builder)
```

### Milestone 7 — Overlay IP allocation ✓

```sh
cargo test --workspace  # +8 overlay tests (deterministic, collision resolution)
```

### Milestone 8 — Routing ✓

```sh
cargo test --workspace  # +10 routing tests (IPv4 parse, route table, encrypt-through)
```

### Milestone 9 — Core orchestration ✓

```sh
cargo test --workspace  # +3 core tests (engine creation, allocation, status)

cargo run -- up "correct horse battery staple"
# → DHT announce/lookup loop, Ctrl-C to stop
```

### Milestone 10 — Cross-platform integration ✓

```sh
cargo test --workspace  # 99 tests total, all green

# Two machines, same seed:
cargo run -- up "correct horse battery staple"   # machine A
cargo run -- up "correct horse battery staple"   # machine B
# → both join DHT, discover each other, announce/lookup running
```

## License

MIT OR Apache-2.0
