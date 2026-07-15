---
title: CLI 命令
---

# CLI 命令

所有 SeedNet 功能均可通过 `seednet` 命令使用。

## 启动网络

```sh
seednet up "我的秘密网络"
```

此命令将 SeedNet 以后台守护进程启动并立即返回。你的设备将开始发现使用相同种子的节点。

### 可选参数

```sh
seednet up "我的秘密网络" \
  --port 51820 \
  --transport udp,tcp,ws \
  --tracker 203.0.113.5:51820 \
  --tracker-url udp://tracker.opentrackr.org:1337
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--port` | 由种子派生 | UDP 监听端口 |
| `--transport` | `udp,tcp,ws` | 启用的传输协议（逗号分隔） |
| `--tracker` | — | 直连节点地址，跳过 DHT |
| `--tracker-url` | 内置列表 | 额外的 BitTorrent Tracker URL |

## 停止网络

```sh
seednet down
```

## 查看已连接节点

```sh
seednet list
```

显示每个已连接节点的覆盖 IPv4、IPv6、连接类型（直连 / 中继）、往返时延和底层地址。

## 查看守护进程状态

```sh
seednet status
```

显示守护进程是否正在运行及其 PID。

## 查看网络身份

```sh
seednet identity "我的秘密网络"
```

在不实际加入网络的情况下，打印该网络下本设备的身份（infohash、PeerId、覆盖 IP、X25519 公钥）。

## 全局参数

| 参数 | 说明 |
|---|---|
| `--state-dir <PATH>` | 覆盖默认状态目录 `~/.seednet` |
| `-v / -vv / -vvv` | 增加日志详细程度（info / debug / trace） |
