# Sentinel Firewall v2.0

A personal software firewall for Windows with six integrated modules: DNS filtering, intrusion detection, threat intelligence, Suricata rule parsing, per-application network control (WFP), and a real-time traffic dashboard.

Sentinel runs alongside your existing Windows Firewall as a supplementary monitoring, filtering, and control layer.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Sentinel Firewall v2.0                        │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  DNS Proxy   │  │   Packet     │  │   Web Dashboard       │  │
│  │  + Blocklist │  │   Engine     │  │   Flask + Socket.IO   │  │
│  │  Manager     │  │   (Scapy)    │  │   Chart.js + WS       │  │
│  └──────┬───────┘  └──────┬───────┘  └───────────┬───────────┘  │
│         │                 │                       │              │
│         │    ┌────────────┼────────────┐          │              │
│         │    │            │            │          │              │
│  ┌──────▼────▼──┐ ┌──────▼──────┐ ┌──▼──────────▼───────────┐  │
│  │  Event Bus   │ │  Built-in   │ │  REST API + WebSocket   │  │
│  │  (pub/sub)   │ │  IDS Rules  │ │  /api/stats             │  │
│  └──────┬───────┘ │  (7 types)  │ │  /api/threat_intel      │  │
│         │         └─────────────┘ │  /api/suricata           │  │
│         │                         │  /api/apps               │  │
│  ┌──────▼───────────────────┐     └──────────────────────────┘  │
│  │  Threat Intelligence     │                                    │
│  │  7 free feeds + 2 API    │                                    │
│  │  AbuseIPDB · ET · OTX    │                                    │
│  │  Feodo · URLhaus · DROP  │                                    │
│  └──────────────────────────┘                                    │
│                                                                  │
│  ┌──────────────────────────┐  ┌─────────────────────────────┐  │
│  │  Suricata Rule Engine    │  │  WFP Application Control    │  │
│  │  Full rule parser        │  │  Per-app block/allow        │  │
│  │  Content/PCRE matching   │  │  Auto-expiry safety         │  │
│  │  30K+ community rules    │  │  Protected process list     │  │
│  │  ET Open rulesets        │  │  Panic remove-all           │  │
│  └──────────────────────────┘  └─────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

---

## Features

### DNS Filtering
- Blocks ads, trackers, and malicious domains (StevenBlack, Energized)
- Local DNS proxy on port 5353 with upstream forwarding
- DNS response caching, runtime block/unblock via API
- Custom whitelist and blocklist

### Intrusion Detection (7 rule types)
- Port scan detection
- SYN flood detection
- DNS tunneling detection
- Signature matching (SSH brute force, etc.)
- Payload regex analysis (Nikto, sqlmap, Nmap)
- ARP spoofing detection
- Data exfiltration alerts

### Threat Intelligence (NEW)
- **7 free feeds** — no API key needed:
  - Emerging Threats Compromised IPs
  - Feodo Tracker (abuse.ch) — Botnet C2 IPs
  - URLhaus (abuse.ch) — Malicious domains
  - ThreatFox (abuse.ch) — Multi-type IOCs
  - Spamhaus DROP + EDROP — Hijacked IP ranges
  - SANS DShield — Top attackers
- **2 optional API feeds** (free accounts):
  - AbuseIPDB blacklist
  - AlienVault OTX indicators
- Indexed O(1) lookups for every packet
- Background hourly refresh
- Supports IPs, CIDRs, domains, URLs, and file hashes

### Suricata-Compatible Rules (NEW)
- Full Suricata rule syntax parser
- Content matching with hex patterns, nocase, depth, offset
- PCRE regex matching
- Sticky buffers (dns.query, http.uri, http.header, etc.)
- Flow directives and thresholds
- Variable substitution ($HOME_NET, $EXTERNAL_NET, etc.)
- Import 30,000+ community rules from Emerging Threats Open
- Load from local files or URLs with caching

### Per-Application Control via WFP (NEW)
- Windows Filtering Platform integration (kernel-level)
- Block/allow individual applications
- Direction control (inbound, outbound, both)
- **Safety features:**
  - Auto-expiry on block rules (default 60 minutes)
  - Protected system process list (cannot block svchost, lsass, etc.)
  - Panic mode: `--panic` flag removes ALL Sentinel filters instantly
  - Unique WFP provider/sublayer for clean identification
- Process discovery: list all apps with active connections
- REST API for runtime control

### Real-Time Dashboard
- Live bandwidth chart (bytes/s and packets/s)
- Protocol distribution doughnut
- Top talkers with visual bars
- IDS alert feed with severity indicators
- DNS query log with blocked/allowed
- Threat intelligence stats and feed status
- Suricata rule statistics
- Application control panel
- Domain block/unblock controls

---

## Quick Start

```bash
cd sentinel-firewall

# Install dependencies
python setup.py

# Run everything (as Administrator for full features)
python -m src.main

# Dashboard at http://127.0.0.1:8080
```

### Selective Modules

```bash
python -m src.main --dns-only          # DNS filtering only
python -m src.main --no-suricata       # Skip Suricata rules
python -m src.main --no-wfp            # Skip WFP app control
python -m src.main --no-threat-intel   # Skip threat feeds
python -m src.main --port 9090         # Custom dashboard port
python -m src.main --panic             # Emergency: remove all WFP filters
```

---

## Configuration

Edit `config/default_config.yaml`:

### Threat Intelligence

```yaml
threat_intel:
  enabled: true
  update_interval: 3600
  api_keys:
    abuseipdb: "your-free-api-key"     # abuseipdb.com/account/api
    otx: "your-free-api-key"           # otx.alienvault.com
```

### Suricata Rules

```yaml
suricata:
  enabled: true
  variables:
    HOME_NET: "192.168.1.0/24"
    EXTERNAL_NET: "any"
  rule_files:
    - /path/to/custom.rules
  rule_urls:
    - name: ET Open Malware
      url: https://rules.emergingthreats.net/open/suricata-7.0/rules/emerging-malware.rules
      enabled: true
```

### Application Control

```yaml
app_control:
  enabled: true
  default_expiry_minutes: 60
  blocked_apps:
    - path: C:\Path\To\suspicious.exe
      direction: outbound
      description: Block outbound telemetry
```

---

## API Endpoints

### Core
| Endpoint | Method | Description |
|---|---|---|
| `/api/stats` | GET | Full system statistics (all modules) |
| `/api/alerts` | GET | Recent IDS alerts |
| `/api/dns` | GET | DNS stats and query log |
| `/api/traffic` | GET | Traffic stats and bandwidth history |
| `/api/dns/block` | POST | Block a domain |
| `/api/dns/unblock` | POST | Unblock a domain |

### Threat Intelligence
| Endpoint | Method | Description |
|---|---|---|
| `/api/threat_intel` | GET | Feed stats and status |
| `/api/threat_intel/check_ip` | POST | Check if IP is malicious |
| `/api/threat_intel/check_domain` | POST | Check if domain is malicious |

### Suricata
| Endpoint | Method | Description |
|---|---|---|
| `/api/suricata` | GET | Rule engine statistics |

### Application Control
| Endpoint | Method | Description |
|---|---|---|
| `/api/apps` | GET | All rules, stats, and active processes |
| `/api/apps/block` | POST | Block an application |
| `/api/apps/unblock` | POST | Remove a block rule |
| `/api/apps/panic` | POST | Emergency: remove all WFP filters |

---

## Project Structure

```
sentinel-firewall/
├── config/
│   └── default_config.yaml
├── src/
│   ├── main.py                      # Orchestrator
│   ├── config_loader.py             # YAML config
│   ├── event_bus.py                 # Pub/sub events
│   ├── dns/
│   │   ├── blocklist.py             # Blocklist management
│   │   └── dns_proxy.py             # DNS proxy server
│   ├── ids/
│   │   ├── packet_engine.py         # Scapy packet capture
│   │   └── detection_rules.py       # 7 IDS rule types
│   ├── threat_intel/
│   │   ├── feed_manager.py          # Feed download/parse/index
│   │   └── ids_integration.py       # Packet ↔ threat intel bridge
│   ├── suricata/
│   │   ├── rule_parser.py           # Suricata syntax parser
│   │   └── rule_engine.py           # Rule evaluation engine
│   ├── wfp/
│   │   └── wfp_controller.py        # WFP per-app control
│   └── dashboard/
│       ├── server.py                # Flask + SocketIO
│       ├── templates/index.html
│       └── static/{css,js}/
├── data/                            # Cached feeds and rules
├── logs/
├── requirements.txt
├── setup.py
└── README.md
```

---

## How It Compares (v2.0)

| Feature | Sentinel v2 | Windows FW | Little Snitch | pfSense |
|---|---|---|---|---|
| DNS Filtering | 147K+ domains | No | No | Via packages |
| IDS Rules | 7 built-in types | Basic | No | Via Snort |
| Threat Intel Feeds | 7+ feeds, auto-refresh | No | No | Via packages |
| Suricata Rules | 30K+ community rules | No | No | Built-in |
| Per-App Control | Yes (WFP) | Yes | Yes | Yes |
| Traffic Dashboard | Real-time web UI | Logs only | Connection list | Via packages |
| Kernel-Level Block | Yes (WFP) | Yes | Yes | Yes |
| Open Source | Yes | No | No | Yes |

---

## Safety

- WFP blocks auto-expire after 60 minutes by default
- System-critical processes (svchost, lsass, csrss, etc.) cannot be blocked
- `--panic` flag instantly removes all Sentinel filters
- Sentinel does not disable or replace Windows Firewall
- All threat intelligence is advisory — false positives happen

---

## License

MIT
