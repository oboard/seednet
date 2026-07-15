---
layout: home

hero:
  name: SeedNet
  text: Private Network, One Seed
  tagline: Connect any device with just a passphrase — no accounts, no servers, no configuration.
  image:
    src: /logo.svg
    alt: SeedNet
  actions:
    - theme: brand
      text: Quick Start
      link: /en/guide/quick-start
    - theme: alt
      text: Download
      link: https://github.com/oboard/seednet/releases
    - theme: alt
      text: GitHub
      link: https://github.com/oboard/seednet

features:
  - icon: 🌱
    title: Seed-based Networking
    details: Share one passphrase with your devices — they automatically find each other and form a private encrypted network. No registration, no cloud account.
  - icon: 🔒
    title: End-to-End Encrypted
    details: All traffic is secured with Noise XX (ChaCha20-Poly1305). Devices outside your seed can never join or decrypt your network.
  - icon: 🌐
    title: Decentralized Discovery
    details: Uses BitTorrent DHT to find peers without a central server. Works as long as the internet does.
  - icon: ⚡
    title: Multi-transport
    details: Supports UDP, TCP, WebSocket and WSS. Automatically picks the best path and falls back gracefully behind NAT.
  - icon: 🖥️
    title: Interactive TUI
    details: Run seednet with no arguments to open a full-screen terminal UI — no command memorization needed.
  - icon: 🛜
    title: Virtual Overlay IP
    details: Every device gets a stable overlay IPv4 and IPv6 address derived from its identity. Use it like a LAN.
---
