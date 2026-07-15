---
title: Connecting Peers
---

# Connecting Peers

## Basic peer discovery (DHT)

By default, SeedNet finds peers via the **BitTorrent Mainline DHT** — the same distributed hash table used by BitTorrent clients worldwide. No setup required; it works as long as your device has internet access.

```sh
# Device A
seednet up "my secret network"

# Device B (same phrase, different machine, anywhere on the internet)
seednet up "my secret network"
```

Peers typically appear within 10–60 seconds.

## Speeding up discovery with trackers

BitTorrent trackers provide instant peer lists without waiting for DHT propagation. SeedNet includes a built-in list of public trackers, but you can add more:

```sh
seednet up "my secret network" \
  --tracker-url udp://tracker.opentrackr.org:1337 \
  --tracker-url udp://open.demonii.com:1337
```

## Direct peer address (zero-latency discovery)

If you already know a peer's IP and port, skip DHT entirely:

```sh
seednet up "my secret network" --tracker 203.0.113.5:51820
```

This connects directly on start — useful for LAN setups or when one machine has a static IP.

## Connection types

The `seednet list` output shows the connection type for each peer:

| Type | Meaning |
|---|---|
| `direct` | Direct UDP/TCP connection — lowest latency |
| `relay via <peer>` | Traffic is relayed through another peer — used when direct connection fails (NAT, firewall) |

SeedNet always tries a direct connection first. If it fails within 2 seconds, it falls back to relay and continues upgrading to direct in the background.

## Checking connectivity

Once peers appear in `seednet list`, use their overlay IP to communicate:

```sh
# Get peer IPs
seednet list

# Ping a peer
ping 10.0.1.2

# SSH to a peer
ssh user@10.0.1.2

# Any port, any protocol — it's a virtual LAN
curl http://10.0.1.3:8080
```

## Firewall tips

- SeedNet defaults to a UDP port **derived from your seed phrase** — the same port on all devices in your network.
- If peers are stuck on `relay`, try opening the UDP port in your firewall or router.
- TCP and WebSocket transports are also supported as fallbacks (`--transport udp,tcp,ws`).
