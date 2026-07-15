---
layout: home

hero:
  name: SeedNet
  text: 一个词组，一张网
  tagline: 只需一个密码短语即可连接任意设备——无需注册账户，无需服务器，无需配置。
  image:
    src: /logo.svg
    alt: SeedNet
  actions:
    - theme: brand
      text: 快速开始
      link: /zh/guide/quick-start
    - theme: alt
      text: 下载
      link: https://github.com/oboard/seednet/releases
    - theme: alt
      text: GitHub
      link: https://github.com/oboard/seednet

features:
  - icon: 🌱
    title: 基于种子短语组网
    details: 在所有设备上输入同一个密码短语，它们会自动互相发现并形成私有加密网络。无需注册，无需云账户。
  - icon: 🔒
    title: 端对端加密
    details: 所有流量均使用 Noise XX（ChaCha20-Poly1305）加密。不知道种子短语的设备无法加入或解密你的网络。
  - icon: 🌐
    title: 去中心化发现
    details: 通过 BitTorrent DHT 发现对等节点，无需中心服务器。只要互联网可用，网络就可用。
  - icon: ⚡
    title: 多传输协议
    details: 支持 UDP、TCP、WebSocket 和 WSS。自动选择最优路径，在 NAT 后面也能优雅回退。
  - icon: 🖥️
    title: 交互式 TUI
    details: 不带参数运行 seednet 即可打开全屏终端界面——无需记忆命令。
  - icon: 🛜
    title: 虚拟覆盖 IP
    details: 每台设备都会获得一个由其身份派生的稳定覆盖 IPv4 和 IPv6 地址，像局域网一样使用。
---
