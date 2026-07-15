---
title: 连接设备
---

# 连接设备

## 基础节点发现（DHT）

默认情况下，SeedNet 通过 **BitTorrent 主线 DHT** 发现节点——与全球 BitTorrent 客户端共用的同一个分布式哈希表。无需任何配置，只要设备能上网即可工作。

```sh
# 设备 A
seednet up "我的秘密网络"

# 设备 B（相同短语，不同机器，互联网任意位置）
seednet up "我的秘密网络"
```

节点通常在 10–60 秒内出现。

## 使用 Tracker 加速发现

BitTorrent Tracker 无需等待 DHT 传播即可即时提供节点列表。SeedNet 内置了一批公共 Tracker，你也可以添加更多：

```sh
seednet up "我的秘密网络" \
  --tracker-url udp://tracker.opentrackr.org:1337 \
  --tracker-url udp://open.demonii.com:1337
```

## 直连节点地址（零延迟发现）

如果你已知某节点的 IP 和端口，可以完全跳过 DHT：

```sh
seednet up "我的秘密网络" --tracker 203.0.113.5:51820
```

启动时立即直连——适合局域网场景或某台机器有固定 IP 的情况。

## 连接类型

`seednet list` 输出会显示每个节点的连接类型：

| 类型 | 含义 |
|---|---|
| `direct` | 直接 UDP/TCP 连接——延迟最低 |
| `relay via <peer>` | 流量通过另一个节点中继——在直连失败时使用（NAT、防火墙） |

SeedNet 总是优先尝试直连。如果 2 秒内失败，则回退到中继，并在后台持续尝试升级为直连。

## 验证连通性

节点出现在 `seednet list` 后，即可通过其覆盖 IP 通信：

```sh
# 查看节点 IP
seednet list

# Ping 节点
ping 10.0.1.2

# SSH 连接节点
ssh user@10.0.1.2

# 任意端口、任意协议——这就是一个虚拟局域网
curl http://10.0.1.3:8080
```

## 防火墙建议

- SeedNet 默认使用一个**由种子短语派生的 UDP 端口**——同一网络的所有设备使用相同端口。
- 如果节点一直停在 `relay`，可以尝试在防火墙或路由器上放行该 UDP 端口。
- TCP 和 WebSocket 也作为备用传输协议支持（`--transport udp,tcp,ws`）。
