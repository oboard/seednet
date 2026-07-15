---
title: CLI 参考
---

# CLI 参考

## 语法

```
seednet [OPTIONS] [COMMAND]
```

不带子命令运行时，将打开[交互式 TUI](/zh/guide/tui)。

## 全局参数

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `--state-dir <PATH>` | `SEEDNET_STATE_DIR` | `~/.seednet` | 存储身份、日志、PID 的状态目录 |
| `-v` | — | — | info 级别日志 |
| `-vv` | — | — | debug 级别日志 |
| `-vvv` | — | — | trace 级别日志 |

## 子命令

### `seednet up <SEED>`

以后台守护进程启动覆盖网络。

```sh
seednet up "我的网络" [OPTIONS]
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--port <PORT>` | 由种子派生 | UDP 监听端口 |
| `--transport <LIST>` | `udp,tcp,ws` | 启用的传输协议（逗号分隔） |
| `--tracker <ADDR>` | — | 直连节点地址（可重复） |
| `--tracker-url <URL>` | 内置列表 | BitTorrent Tracker URL（可重复） |

### `seednet down`

停止运行中的守护进程。

```sh
seednet down
```

### `seednet list`

列出已连接的节点，含覆盖 IP、连接类型、往返时延和底层地址。

```sh
seednet list
```

### `seednet status`

显示守护进程运行状态和 PID。

```sh
seednet status
```

### `seednet identity <SEED>`

在不加入网络的情况下打印网络身份。

```sh
seednet identity "我的网络"
```

输出：infohash、PeerId、覆盖 IPv4、覆盖 IPv6、X25519 公钥。

### `seednet discover <SEED>`

运行一次性 DHT 发现后退出。

```sh
seednet discover "我的网络" [OPTIONS]
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--port <PORT>` | 由种子派生 | SeedNet 端口 |
| `--dht-port <PORT>` | 随机 | DHT 绑定端口 |
| `--duration <SECS>` | `30` | 发现运行时长（秒） |

## 状态文件

所有文件存储在 `~/.seednet/`（或 `--state-dir` 指定目录）：

| 文件 | 说明 |
|---|---|
| `identity.bin` | 每设备 Ed25519 密钥对（生成一次，永不更改） |
| `seednet.pid` | 运行中守护进程的 PID |
| `peers.json` | 最近已知的节点列表 |
| `seednet.log` | 守护进程日志（TUI 日志面板实时追踪） |
