---
title: Quick Start
---

# Quick Start

Get two devices on the same private network in under a minute.

## Step 1 — Download

Go to the [Releases page](https://github.com/oboard/seednet/releases) and download the binary for your platform.

| Platform | File |
|---|---|
| macOS (Apple Silicon) | `seednet-aarch64-apple-darwin` |
| macOS (Intel) | `seednet-x86_64-apple-darwin` |
| Linux (x86_64) | `seednet-x86_64-unknown-linux-musl` |
| Windows | `seednet-x86_64-pc-windows-msvc.exe` |

Rename it to `seednet` (or `seednet.exe` on Windows) and place it somewhere in your `$PATH`, or just run it from the download folder.

> **macOS users:** you may need to allow the binary in **System Settings → Privacy & Security** the first time.

## Step 2 — Start the network

Run the same command on **every device** you want to connect:

```sh
seednet up "my secret network"
```

Replace `"my secret network"` with any passphrase you like. Any device using the exact same phrase will join your network.

## Step 3 — Check connected peers

```sh
seednet list
```

Example output:

```
PeerID           IPv4           IPv6                  Type    RTT    Addr
abc123...        10.0.1.2       fd00::2               direct  12ms   203.0.113.5:51820
def456...        10.0.1.3       fd00::3               direct  45ms   198.51.100.7:51820
```

Once a peer appears, you can ping it by its overlay IP:

```sh
ping 10.0.1.2
```

## Step 4 — Stop the network

```sh
seednet down
```

---

## Prefer a graphical interface?

Run `seednet` with no arguments to open the interactive TUI:

```sh
seednet
```

Enter your seed phrase, press **Enter** to start, and watch peers appear — no commands needed.

→ [Learn more about the TUI](/en/guide/tui)
