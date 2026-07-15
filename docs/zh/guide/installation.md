---
title: 安装
---

# 安装

## 下载预构建二进制文件

最简单的方式，无需任何构建工具。

1. 访问 [GitHub Releases 页面](https://github.com/oboard/seednet/releases)
2. 下载适合你操作系统和架构的二进制文件
3. 赋予执行权限并放入 `PATH`

### macOS / Linux

```sh
# 以 macOS Apple Silicon 为例
curl -LO https://github.com/oboard/seednet/releases/latest/download/seednet-aarch64-apple-darwin
chmod +x seednet-aarch64-apple-darwin
mv seednet-aarch64-apple-darwin /usr/local/bin/seednet
```

> **macOS：** 如果 Gatekeeper 阻止了二进制文件，请前往**系统设置 → 隐私与安全性**，点击**仍要打开**。

### Windows

下载 `seednet-x86_64-pc-windows-msvc.exe`，重命名为 `seednet.exe`，放到 `%PATH%` 中的目录（如 `C:\Windows\System32` 或自定义工具目录）。

## 验证安装

```sh
seednet --version
```

应当打印版本号。

## 从源码构建

需要 [Rust](https://rustup.rs/)（stable 工具链）。

```sh
git clone https://github.com/oboard/seednet.git
cd seednet
cargo build --release
# 二进制文件位于：target/release/seednet
```

## 状态目录

SeedNet 默认将状态（身份、节点列表、日志、PID）存储在 `~/.seednet/`。可通过 `--state-dir` 参数或 `SEEDNET_STATE_DIR` 环境变量覆盖。

```sh
seednet --state-dir /var/lib/seednet up "我的网络"
```
