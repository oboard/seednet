---
title: Installation
---

# Installation

## Download a pre-built binary

The easiest way to get SeedNet. No build tools required.

1. Visit the [GitHub Releases page](https://github.com/oboard/seednet/releases)
2. Download the binary for your OS and architecture
3. Make it executable and place it in your `PATH`

### macOS / Linux

```sh
# Example for macOS Apple Silicon
curl -LO https://github.com/oboard/seednet/releases/latest/download/seednet-aarch64-apple-darwin
chmod +x seednet-aarch64-apple-darwin
mv seednet-aarch64-apple-darwin /usr/local/bin/seednet
```

> **macOS:** If Gatekeeper blocks the binary, open **System Settings → Privacy & Security** and click **Allow Anyway**.

### Windows

Download `seednet-x86_64-pc-windows-msvc.exe`, rename it to `seednet.exe`, and place it in a folder that is in your `%PATH%` (e.g. `C:\Windows\System32` or a custom tools folder).

## Verify the installation

```sh
seednet --version
```

You should see the version string printed.

## Build from source

You need [Rust](https://rustup.rs/) (stable toolchain).

```sh
git clone https://github.com/oboard/seednet.git
cd seednet
cargo build --release
# Binary is at: target/release/seednet
```

## State directory

SeedNet stores its state (identity, peers, logs, PID) in `~/.seednet/` by default. You can override this with the `--state-dir` flag or the `SEEDNET_STATE_DIR` environment variable.

```sh
seednet --state-dir /var/lib/seednet up "my network"
```
