# Clash Verge CLI Skill

A CLI tool to control [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) via the mihomo external controller API.

Pure Python, zero dependencies. Supports Unix socket (macOS/Linux) and HTTP API.

## Features

- **Status** — View core version, mode, TUN status, traffic stats
- **Proxy Groups** — List groups, view nodes, switch selections
- **Delay Testing** — Test individual nodes or entire groups
- **Connections** — Monitor active connections, close by ID or all
- **DNS** — Query resolution, flush cache
- **Rules** — Inspect active routing rules
- **Maintenance** — Restart core, update GeoIP/GeoSite

## Prerequisites

- [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) running
- Python 3.8+
- No additional dependencies

## Installation

### As an OpenClaw Skill

```bash
npx clawhub@latest install Hsiifu3/clash-verge-skill
```

### Manual

```bash
git clone https://github.com/Hsiifu3/clash-verge-skill.git
python3 clash-verge-skill/scripts/clash-verge.py status
```

## Quick Start

```bash
alias cv="python3 /path/to/scripts/clash-verge.py"

cv status                    # Overall status
cv groups                    # List proxy groups
cv nodes "🔥ChatGPT"         # List nodes in a group
cv select "🔥ChatGPT" "🇺🇸US Node"  # Switch node
cv delay "🇺🇸US Node"        # Test delay
cv conns                     # Active connections
cv mode rule                 # Set proxy mode
```

## Connection

The tool auto-detects the connection method:

1. **Unix socket** (preferred): `/tmp/verge/verge-mihomo.sock`
2. **HTTP API** (fallback): `http://127.0.0.1:9090`

Override via environment variables or CLI flags:

```bash
export CLASH_SOCK=/tmp/verge/verge-mihomo.sock
export CLASH_API=http://127.0.0.1:9090
export CLASH_SECRET=your-secret
```

## License

MIT
