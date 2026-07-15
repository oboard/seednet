---
title: CLI Reference
---

# CLI Reference

## Synopsis

```
seednet [OPTIONS] [COMMAND]
```

Running with no command opens the [interactive TUI](/en/guide/tui).

## Global Options

| Option | Env | Default | Description |
|---|---|---|---|
| `--state-dir <PATH>` | `SEEDNET_STATE_DIR` | `~/.seednet` | State directory for identity, logs, PID |
| `-v` | — | — | Info-level logging |
| `-vv` | — | — | Debug-level logging |
| `-vvv` | — | — | Trace-level logging |

## Commands

### `seednet up <SEED>`

Start the overlay network as a background daemon.

```sh
seednet up "my network" [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--port <PORT>` | derived from seed | UDP listen port |
| `--transport <LIST>` | `udp,tcp,ws` | Comma-separated transports to enable |
| `--tracker <ADDR>` | — | Direct peer socket address (repeatable) |
| `--tracker-url <URL>` | built-in | BitTorrent tracker URL (repeatable) |

### `seednet down`

Stop the running daemon.

```sh
seednet down
```

### `seednet list`

List connected peers with overlay IPs, connection type, RTT, and underlay address.

```sh
seednet list
```

### `seednet status`

Show daemon running state and PID.

```sh
seednet status
```

### `seednet identity <SEED>`

Print network identity without joining.

```sh
seednet identity "my network"
```

Output: infohash, PeerId, overlay IPv4, overlay IPv6, X25519 public key.

### `seednet discover <SEED>`

Run a one-shot DHT announce and lookup, then exit.

```sh
seednet discover "my network" [OPTIONS]
```

| Option | Default | Description |
|---|---|---|
| `--port <PORT>` | derived from seed | SeedNet port |
| `--dht-port <PORT>` | random | DHT bind port |
| `--duration <SECS>` | `30` | How long to run discovery |

## State files

All files live in `~/.seednet/` (or `--state-dir`):

| File | Description |
|---|---|
| `identity.bin` | Per-device Ed25519 keypair (generated once, never changes) |
| `seednet.pid` | PID of the running daemon |
| `peers.json` | Last known peer list |
| `seednet.log` | Daemon log (tailed by the TUI log panel) |
