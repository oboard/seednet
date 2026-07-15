---
title: Using the CLI
---

# Using the CLI

All SeedNet functionality is available via the `seednet` command.

## Start the network

```sh
seednet up "my secret network"
```

This starts SeedNet as a background daemon and returns immediately. Your device will begin discovering peers with the same seed.

### Options

```sh
seednet up "my secret network" \
  --port 51820 \
  --transport udp,tcp,ws \
  --tracker 203.0.113.5:51820 \
  --tracker-url udp://tracker.opentrackr.org:1337
```

| Flag | Default | Description |
|---|---|---|
| `--port` | derived from seed | UDP listen port |
| `--transport` | `udp,tcp,ws` | Enabled transports (comma-separated) |
| `--tracker` | — | Direct peer addresses, bypasses DHT |
| `--tracker-url` | built-in list | Extra BitTorrent tracker URLs |

## Stop the network

```sh
seednet down
```

## List connected peers

```sh
seednet list
```

Shows each connected peer's overlay IPv4, IPv6, connection type (direct / relay), round-trip time, and underlay address.

## Check daemon status

```sh
seednet status
```

Prints whether the daemon is running and its PID.

## Show network identity

```sh
seednet identity "my secret network"
```

Prints your device's identity for that network (infohash, PeerId, overlay IPs, X25519 public key) without actually joining.

## Global flags

| Flag | Description |
|---|---|
| `--state-dir <PATH>` | Override default `~/.seednet` state directory |
| `-v / -vv / -vvv` | Increase log verbosity (info / debug / trace) |
