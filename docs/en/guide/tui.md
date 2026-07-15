---
title: Interactive TUI
---

# Interactive TUI

Run SeedNet with no arguments to open the interactive terminal UI:

```sh
seednet
```

## Interface overview

```
┌─────────────────────────────────────────────────────────┐
│  SeedNet                                                 │
├──────────────────────────────┬──────────────────────────┤
│  Seed: [my secret network  ] │  Peers (2)               │
│  [ Start ]                   │  10.0.1.2  direct  12ms  │
│                              │  10.0.1.3  relay   89ms  │
├──────────────────────────────┴──────────────────────────┤
│  Logs                                                    │
│  [INFO] DHT bootstrap complete                           │
│  [INFO] New peer connected: abc123                       │
└─────────────────────────────────────────────────────────┘
```

## Controls

| Key | Action |
|---|---|
| `Tab` | Cycle focus between panels |
| `Enter` | Start / Stop the network |
| `↑` / `↓` | Scroll peer list or log panel |
| `Ctrl+C` or `q` | Quit |

## Workflow

1. Type your seed phrase in the **Seed** field
2. Press **Enter** or click **Start**
3. Watch the **Peers** panel — connected devices appear automatically
4. Check the **Logs** panel for connection events
5. Press **Enter** again (or **Stop**) to disconnect

## Tips

- The seed field is editable — change it any time before starting
- The log panel tails `~/.seednet/seednet.log` in real time
- Overlay IPs shown in the peer list are the addresses you use to communicate (e.g. `ping 10.0.1.2`)
