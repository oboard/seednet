---
title: 快速开始
---

# 快速开始

让两台设备加入同一个私有网络，不到一分钟。

## 第一步 — 下载

前往 [Releases 页面](https://github.com/oboard/seednet/releases)，下载适合你平台的二进制文件。

| 平台 | 文件 |
|---|---|
| macOS（Apple Silicon） | `seednet-aarch64-apple-darwin` |
| macOS（Intel） | `seednet-x86_64-apple-darwin` |
| Linux（x86_64） | `seednet-x86_64-unknown-linux-musl` |
| Windows | `seednet-x86_64-pc-windows-msvc.exe` |

将文件重命名为 `seednet`（Windows 上为 `seednet.exe`），并放到 `$PATH` 中的某个目录，或直接在下载目录运行。

> **macOS 用户：** 首次运行时 Gatekeeper 可能阻止程序。请前往**系统设置 → 隐私与安全性**，点击**仍要打开**。

## 第二步 — 启动网络

在**每台**想要互联的设备上运行同一条命令：

```sh
seednet up "我的秘密网络"
```

将 `"我的秘密网络"` 替换为你喜欢的任意短语。使用完全相同短语的设备都会加入你的网络。

## 第三步 — 查看已连接的节点

```sh
seednet list
```

示例输出：

```
PeerID           IPv4           IPv6                  类型    延迟   地址
abc123...        10.0.1.2       fd00::2               direct  12ms   203.0.113.5:51820
def456...        10.0.1.3       fd00::3               direct  45ms   198.51.100.7:51820
```

节点出现后，即可通过覆盖 IP 与之通信：

```sh
ping 10.0.1.2
```

## 第四步 — 停止网络

```sh
seednet down
```

---

## 更喜欢图形界面？

不带参数运行 `seednet` 即可打开交互式 TUI：

```sh
seednet
```

输入种子短语，按 **Enter** 启动，节点会自动出现——无需记命令。

→ [了解更多 TUI 用法](/zh/guide/tui)
