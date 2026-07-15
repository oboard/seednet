---
title: Introduction
---

# What is SeedNet?

SeedNet is a **decentralized private overlay network**. It lets you connect any number of devices into a single virtual LAN using nothing but a shared passphrase — your *seed*.

## How it works (in one sentence)

Every device that runs `seednet up "my secret phrase"` with the same phrase automatically discovers each other via the BitTorrent DHT network and forms an encrypted peer-to-peer tunnel — no accounts, no cloud controller, no port forwarding required.

## Key concepts

| Concept | What it means |
|---|---|
| **Seed phrase** | The only shared secret. Anyone with the same phrase joins the same network. Keep it private. |
| **Overlay IP** | Each device gets a stable virtual IP (e.g. `10.x.x.x`) derived from its identity. Use it like a LAN address. |
| **Identity** | A per-device Ed25519 keypair stored in `~/.seednet/identity.bin`. Not derived from the seed — each device is unique. |

## What can I use it for?

- Access your home server from anywhere
- Build a secure link between machines across different networks
- Connect devices for gaming, file sharing, or remote desktop — without exposing ports

## Next step

→ [Quick Start](/en/guide/quick-start) — up and running in under a minute.
