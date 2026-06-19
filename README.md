<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1a2e,50:16213e,100:0f3460&height=220&section=header&text=ReconX%20Framework&fontSize=55&fontColor=e94560&fontAlignY=40&desc=8-Phase%20Automated%20Reconnaissance%20Pipeline&descSize=16&descAlignY=65&animation=fadeIn"/>

<br>

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20WSL-8b5cf6?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Status-Production%20Ready-e94560?style=for-the-badge)]()

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Usage](#-usage)
- [Phase Breakdown](#-phase-breakdown)
- [Tool Reference](#-tool-reference)
- [Configuration](#-configuration)
- [Output Structure](#-output-structure)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

**ReconX Framework** is a production-grade, 8-phase automated reconnaissance pipeline designed for bug bounty hunters, penetration testers, and security engineers. It orchestrates 25+ industry-standard security tools into a single, cohesive workflow — from passive subdomain discovery to critical vulnerability detection.

Built with a **"broad → filter → deep"** philosophy, ReconX minimizes false positives and produces actionable intelligence at every stage.

> ⚡ **One command. Eight phases. Zero manual stitching.**

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **8-Phase Pipeline** | Complete recon workflow from subdomains to vulnerability findings |
| 🧠 **Smart Filtering** | Noise reduction, deduplication, and priority scoring built-in |
| 🎯 **Dual Mode** | `stealth` (low footprint) or `aggressive` (maximum coverage) |
| 📊 **Rich Reporting** | Markdown + text summaries with statistics and next-step guidance |
| 🔧 **Tool Doctor** | Built-in `--check` to verify all dependencies |
| 🔄 **Auto-Update** | One-command tool updates with `--update` |
| 💻 **Resume Support** | Phase-level resume markers — stop and restart anytime |
| 🎨 **Rich CLI** | Beautiful terminal output with `rich` (optional) |
| 🌐 **Cross-Platform** | Linux, macOS, and WSL compatible |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ReconX Framework v2.0                                │
│                    8-Phase Automated Recon Pipeline                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐              │
│  │ Phase 1  │───▶│ Phase 2  │───▶│ Phase 3  │───▶│ Phase 4  │              │
│  │ Subdomain│    │ Live Host│    │ Network  │    │ Tech     │              │
│  │ Enum     │    │ Detection│    │ Scanning │    │ Detection│              │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘              │
│       │               │               │               │                      │
│       ▼               ▼               ▼               ▼                      │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐          │
│  │ Phase 5  │───▶│ Phase 6  │───▶│ Phase 7  │───▶│ Phase 8  │          │
│  │ URL      │    │ Parameter│    │ JS &     │    │ Vuln     │          │
│  │ Collection│   │ Analysis │    │ Secrets  │    │ Scanning │          │
│  └──────────┘    └──────────┘    └──────────┘    └──────────┘          │
│                                                                             │
│                              ┌──────────────┐                              │
│                              │   REPORT     │                              │
│                              │  (MD + TXT)  │                              │
│                              └──────────────┘                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prerequisites

- Python 3.8+
- Go 1.21+
- `bash`, `curl`, `git`

### Quick Install

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/reconx.git
cd reconx

# 2. Run the installer (installs all external tools)
bash install.sh

# 3. Install Python dependencies
pip3 install -r requirements.txt

# 4. Verify everything is ready
python3 recon.py --check
```

> 💡 **Tip:** The installer supports both `apt` (Linux) and `brew` (macOS) automatically.

---

## 🎮 Usage

### Basic Usage

```bash
# Stealth mode (default)
python3 recon.py example.com

# Aggressive mode
python3 recon.py example.com aggressive

# Custom output directory
python3 recon.py example.com -o ./my_scan

# Quiet mode (minimal output)
python3 recon.py example.com --quiet

# Verbose mode
python3 recon.py example.com -vv
```

### Interactive Mode

Run without arguments for interactive prompts:

```bash
python3 recon.py
# [?] Enter target: example.com
# [?] Stealth or aggressive? (s/a): s
```

### Utility Commands

```bash
# Check all tool dependencies
python3 recon.py --check

# Update all tools + nuclei templates
python3 recon.py --update
```

---

## 🔬 Phase Breakdown

### Phase 1: Subdomain Enumeration
- **Passive:** `subfinder`, `chaos`
- **Bruteforce:** `shuffledns` + wordlist
- **Validation:** `dnsx` (A + CNAME records)
- **Takeover:** `subzy`, `nuclei` (takeover tags)

### Phase 2: Live Host Detection
- **Probing:** `httpx` (status codes, redirects)
- **Screenshots:** `gowitness` (optional)

### Phase 3: Network Scanning
- **Port Scanning:** `naabu` (all ports) + `nmap` (service detection)
- **Vuln Scanning:** `nuclei` (network + web)
- **Prioritization:** P1/P2 manual target list generation

### Phase 4: Technology Detection
- **Fingerprinting:** `httpx` (tech-detect, CDN, server)
- **Categorization:** CMS, frameworks, JS frameworks, cloud/CDN/WAF

### Phase 5: URL Collection
- **Crawlers:** `katana`, `hakrawler`
- **Archives:** `gauplus`, `waybackurls`
- **JS Extraction:** `subjs`
- **Deduplication:** `uro`
- **Validation:** `httpx` (chunked for large sets)

### Phase 6: Parameter Analysis
- **Extraction:** From URLs + JS files
- **Discovery:** `arjun` (hidden params)
- **Pattern Matching:** `gf` (XSS, SQLi, SSRF, SSTI, LFI, etc.)
- **Fuzzing Prep:** `qsreplace` (FUZZ injection points)

### Phase 7: JavaScript & Secrets Analysis
- **Collection:** `subjs` + URL filtering
- **Download & Beautify:** `curl` + `js-beautify`
- **Extraction:** Endpoints, parameters, headers, requests, secrets
- **Secret Detection:** AWS keys, GitHub tokens, JWTs, API keys, private keys

### Phase 8: Vulnerability Scanning
- **Nuclei:** High + critical severity
- **CVE Focus:** Critical CVE templates only
- **Tech-Aware:** Auto-template selection (`-as`)

---

## 🔧 Tool Reference

### Core Tools (Required)

| Tool | Phase | Purpose |
|------|-------|---------|
| `subfinder` | 1 | Passive subdomain discovery |
| `dnsx` | 1 | DNS validation & resolution |
| `httpx` | 2, 4, 5 | HTTP probing & tech detection |
| `jq` | 3 | JSON parsing |

### Optional Tools (Recommended)

| Tool | Phase | Purpose |
|------|-------|---------|
| `nuclei` | 1, 3, 8 | Vulnerability scanning |
| `naabu` | 3 | Fast port scanning |
| `nmap` | 3 | Service detection & deep scanning |
| `katana` | 5 | Web crawler |
| `chaos` | 1 | Passive subdomain discovery |
| `shuffledns` | 1 | DNS bruteforce |
| `subzy` | 1 | Subdomain takeover detection |
| `gowitness` | 2 | Web screenshots |
| `hakrawler` | 5 | URL crawler |
| `gauplus` | 5 | Archive URL discovery |
| `waybackurls` | 5 | Wayback Machine URLs |
| `subjs` | 5, 7 | JavaScript URL extraction |
| `uro` | 5 | URL deduplication |
| `arjun` | 6 | Hidden parameter discovery |
| `qsreplace` | 6 | Fuzzing point injection |
| `gf` | 6 | Pattern matching (XSS, SQLi, etc.) |
| `xnLinkFinder` | 6, 7 | Link extraction from JS |
| `js-beautify` | 7 | JavaScript formatting |
| `feroxbuster` | 5 | Content discovery |

> ℹ️ All tools above are installed automatically by `install.sh`. Missing optional tools are gracefully skipped during execution.

---

## ⚙️ Configuration

### Mode Config

| Mode | Threads | Katana Depth | Rate Limit |
|------|---------|--------------|------------|
| `stealth` | 7 | 7 | 20 req/s |
| `aggressive` | 20 | 15 | 30 req/s |

### Environment Variables

```bash
# Set custom wordlist path
export RECON_WORDLIST=/path/to/wordlist.txt

# Set custom resolvers
export RECON_RESOLVERS=/path/to/resolvers.txt
```

---

## 📁 Output Structure

```
recon_example.com_20250619_143022/
├── subdomains/
│   ├── final.txt              # Validated subdomains
│   ├── passive.txt            # Passive discovery results
│   ├── bruteforce.txt         # Bruteforce results
│   ├── takeover_subzy.txt     # Subzy takeover findings
│   └── takeover_nuclei.txt    # Nuclei takeover findings
├── live_hosts/
│   ├── httpx.txt              # All probed URLs
│   ├── httpx_live.txt         # Live URLs only
│   └── crawl_urls.txt         # URLs for crawling
├── network/
│   ├── open_tcp.txt           # Open TCP ports
│   ├── open_tcp.json          # Naabu JSON output
│   ├── nmap_fast.*            # Fast nmap scan
│   ├── nmap_vuln.txt          # Deep vulnerability scan
│   └── manual_targets.txt     # P1/P2 priority targets
├── technology/
│   ├── full_stack.json        # Raw httpx JSON
│   ├── full_stack.txt         # Human-readable tech
│   ├── cms.txt                # CMS detections
│   ├── frameworks.txt         # Backend frameworks
│   ├── js_frameworks.txt      # Frontend frameworks
│   ├── cloud_cdn_waf.txt      # Cloud/CDN/WAF
│   ├── servers.txt            # Web servers
│   └── unique_technologies.txt # Deduplicated tech list
├── content/
│   ├── all_urls.txt           # Deduplicated URLs
│   ├── final_urls.txt         # Final URL list
│   ├── live_urls.txt          # Live URLs (all status)
│   ├── live_urls_200_only.txt # 200 OK only
│   ├── protected_urls.txt     # 401/403 URLs
│   ├── priority_urls.txt      # High-value URLs
│   ├── katana.txt             # Katana crawl results
│   ├── wayback.txt            # Wayback Machine URLs
│   └── ...
├── parameters/
│   ├── all.txt                # All discovered params
│   ├── all_live.txt           # Live param URLs
│   ├── fuzz_ready.txt         # qsreplace FUZZ URLs
│   ├── gf_patterns/           # GF pattern matches
│   │   ├── xss.txt
│   │   ├── sqli.txt
│   │   ├── ssrf.txt
│   │   └── ...
│   └── ...
├── javascript/
│   ├── js_urls.txt            # All JS URLs
│   ├── js_endpoints.txt       # Extracted endpoints
│   ├── js_params.txt          # Extracted parameters
│   ├── js_secrets.txt         # ⚠️ Potential secrets
│   ├── js_requests.txt        # fetch/axios calls
│   ├── auth_related.txt       # Auth-flagged files
│   ├── raw/                   # Downloaded JS files
│   └── beautified/            # Beautified JS files
├── vulnerabilities/
│   ├── high_critical.txt      # Nuclei high/critical
│   ├── cves_critical.txt      # Critical CVEs only
│   ├── nuclei_web.txt         # Web vulnerability scan
│   ├── nuclei_network.txt     # Network vulnerability scan
│   └── all.txt                # Merged findings
├── screenshots/               # gowitness screenshots
│   └── report.html
├── logs/
│   ├── recon.log              # Full execution log
│   ├── tools/                 # Per-tool stderr logs
│   └── phases/                # Per-phase logs
├── REPORT.md                  # Markdown report
├── SUMMARY.txt                # Text summary
└── .phase_*_done              # Resume markers
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code follows the existing style and includes appropriate tests.

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for the incredible open-source security tool suite
- [SecLists](https://github.com/danielmiessler/SecLists) for wordlists
- The bug bounty and security community for continuous inspiration

---

<div align="center">

**Made with ❤️ by [Mohamed Abd almalek](https://github.com/YOUR_USERNAME)**

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:1a1a2e,50:16213e,100:0f3460&height=100&section=footer&animation=fadeIn"/>

</div>
