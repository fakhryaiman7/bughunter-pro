<h1 align="center">
  <br>
  🔍 BugHunter Pro v2.0
  <br>
</h1>

<h4 align="center">Advanced Bug Bounty Automation Framework — Safe | Smart | Open Source</h4>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-blue?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/python-3.9+-green?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/license-MIT-purple?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20WSL-orange?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/checks-24%20types-red?style=for-the-badge"/>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-burp-suite-integration">Burp Integration</a> •
  <a href="#-output">Output</a> •
  <a href="#-legal">Legal</a>
</p>

---

> ⚠️ **LEGAL NOTICE:** Use ONLY on targets you have **explicit written permission** to test.
> Unauthorized scanning is **illegal**. This tool is for **authorized bug bounty programs** only.

---

## 🔥 Features

### 📡 Recon Engine (7 Sources)
- **Subfinder** — passive subdomain discovery
- **Amass** — deep subdomain enumeration
- **crt.sh** — certificate transparency logs
- **Assetfinder** — quick passive recon
- **dnsx** — DNS bruteforce (NEW)
- **Wayback Machine** — historical URLs & subdomains (NEW)
- **Shodan** — internet-wide scan data (optional API key) (NEW)

### 🔍 24 Safe Exploit Checks
| # | Check | Severity |
|---|-------|---------|
| 1 | IDOR Detection | HIGH |
| 2 | Auth Bypass (7 techniques) | HIGH |
| 3 | Sensitive Data Exposure (13 patterns) | CRITICAL |
| 4 | Open Admin Panel | HIGH |
| 5 | Debug Endpoint Exposure | HIGH |
| 6 | Sensitive Files (.env, .git, .aws...) | CRITICAL |
| 7 | SQL Injection (Error-Based) | CRITICAL |
| 8 | Reflected XSS | HIGH |
| **9** | **Subdomain Takeover (20 providers)** | **CRITICAL** |
| **10** | **CORS Misconfiguration** | **CRITICAL** |
| **11** | **SSRF (AWS + GCP + internal)** | **CRITICAL** |
| **12** | **Open Redirect** | **MEDIUM** |
| **13** | **Host Header Injection** | **HIGH** |
| **14** | **JWT Testing (alg:none, RS256→HS256)** | **CRITICAL** |
| **15** | **Security Headers Audit** | **LOW** |
| **16** | **WAF Detection** | **INFO** |
| **17** | **HTTP Method Enumeration** | **MEDIUM** |
| **18** | **Git / SVN Exposure** | **CRITICAL** |
| **19** | **Backup File Discovery** | **HIGH** |
| **20** | **Rate Limit Absence** | **MEDIUM** |
| **21** | **GraphQL Introspection** | **MEDIUM** |
| **22** | **Spring Boot Actuator** | **CRITICAL** |
| **23** | **Public S3 Bucket** | **HIGH** |
| **24** | **HTTP Parameter Pollution** | **LOW** |

### 🧠 Intelligence Engine
- Risk scoring system (0–100)
- 40+ keyword patterns & port scores
- Context-aware target tagging (API, ADMIN, DEV, DEVOPS, CLOUD...)
- Pattern matching from previous scans

### 🤖 Learning Engine
- JSON knowledge base that improves with each scan
- Learns from confirmed vulnerabilities
- Boosts score for previously vulnerable patterns

### 📊 Beautiful HTML Report
- Dark-themed professional report
- Interactive severity filter
- Executive summary dashboard
- Full finding details with remediation

### 🔗 Integrations
- **Burp Suite** — automatic export + proxy routing
- **Slack** — real-time notifications
- **Discord** — real-time notifications
- **Shodan** — enhanced reconnaissance

---

## ⚙️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/bughunter-pro.git
cd bughunter-pro
```

### 2. Set Up Python Environment
```bash
python3 -m venv venv
source venv/bin/activate          # Linux/macOS
# venv\Scripts\activate           # Windows

pip install -r requirements.txt
```

### 3. Install External Tools (Go-based)
```bash
# Install Go first
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Install all Go tools at once
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/sensepost/gowitness@latest

# Update nuclei templates
nuclei -update-templates
```

### 4. Install APT Tools
```bash
sudo apt update
sudo apt install -y amass nmap whatweb seclists
```

### 5. Create Output Directories
```bash
mkdir -p outputs/knowledge outputs/screenshots wordlists
```

### 6. Verify Installation
```bash
python3 -c "
from utils import tool_available
tools = ['subfinder', 'httpx', 'nuclei', 'ffuf', 'dnsx', 'amass', 'nmap', 'gowitness', 'whatweb']
for t in tools:
    status = '✅' if tool_available(t) else '❌'
    print(f'{status} {t}')
"
```

---

## 🚀 Usage

### Basic Scan
```bash
python3 main.py -t example.com
```

### Full Scan with Output Directory
```bash
python3 main.py -t example.com -o ./results/$(date +%Y%m%d)
```

### Scan with Scope File
```bash
# Create scope.txt
cat > scope.txt << EOF
example.com
api.example.com
admin.example.com
EOF

python3 main.py -t example.com -s scope.txt
```

### With All Options
```bash
python3 main.py \
  -t example.com \
  -s scope.txt \
  -o ./results/example \
  --threads 20 \
  --min-score 60 \
  --shodan-key YOUR_SHODAN_API_KEY \
  --notify-slack https://hooks.slack.com/services/... \
  --notify-discord https://discord.com/api/webhooks/...
```

### Recon-Only Mode (Monitoring)
```bash
python3 main.py -t example.com --no-fuzzing --no-exploit --no-screenshots
```

### Skip Specific Steps
```bash
python3 main.py -t example.com \
  --no-screenshots \    # skip gowitness
  --no-nuclei \         # skip nuclei scan  
  --no-fuzzing          # skip ffuf fuzzing
```

### CLI Reference
```
  -t, --target          Primary target domain (required)
  -s, --scope           Scope file (one domain per line)
  -o, --output          Output directory (default: outputs/)
  --threads             Thread count (default: 10)
  --min-score           Min score for fuzzing (default: 60)
  --no-screenshots      Skip screenshots
  --no-nuclei           Skip Nuclei scan
  --no-fuzzing          Skip ffuf fuzzing
  --no-exploit          Skip exploit checks
  --burp-host           Burp proxy host (default: 127.0.0.1)
  --burp-port           Burp proxy port (default: 8080)
  --shodan-key          Shodan API key (optional)
  --notify-slack        Slack webhook URL
  --notify-discord      Discord webhook URL
```

---

## 🔗 Burp Suite Integration

### Step 1 — Configure Burp Proxy
1. Open **Burp Suite** (Community or Pro)
2. Go to **Proxy → Proxy Settings**
3. Add listener: `127.0.0.1:8080`
4. Make sure the proxy is **ON** (green toggle)

### Step 2 — Install Burp CA Certificate
```bash
# Download Burp CA cert
curl http://127.0.0.1:8080/cert -o burp-ca.der

# Trust it (Linux)
sudo cp burp-ca.der /usr/local/share/ca-certificates/burp-ca.crt
sudo update-ca-certificates
```

### Step 3 — Run with Burp
```bash
python3 main.py -t example.com --burp-host 127.0.0.1 --burp-port 8080
```

### What Happens Automatically
✅ BugHunter detects if Burp is running on `127.0.0.1:8080`  
✅ All **high-value targets** (score ≥ 80) are sent through Burp proxy  
✅ They appear automatically in **Burp → Target → Site Map**  
✅ A `burp_targets.txt` file is created for manual import  

### Manual Import into Burp
1. In Burp: **Target → Site Map**
2. Right-click → **Load from file**
3. Select `outputs/burp_targets.txt`

### Import to Burp via Scope
```
outputs/burp_targets.txt  →  Burp > Target > Scope > Load
```

---

## 📁 Output

```
outputs/
├── 🌐 report.html              ← Open this first! Full HTML report
├── subdomains.txt              ← All discovered subdomains
├── new_assets.txt              ← New assets vs last scan
├── alive.txt                   ← Live hosts
├── port_scan.json              ← Port data (40+ ports)
├── nuclei_output.json          ← Raw nuclei findings
├── tech_map.json               ← Technology stack per URL
├── js_endpoints.txt            ← API routes found in JS files
├── wayback_urls.txt            ← Historical URLs
├── scored_targets.json         ← Full risk scoring data
├── prioritized_targets.txt     ← Targets ranked by risk
├── recommendations.txt         ← Manual testing guide
├── fuzzing_results.txt         ← ffuf discoveries
├── burp_targets.txt            ← Import into Burp Suite
├── exploit_results.txt         ← 24-check PoC findings
├── exploit_results.json        ← Machine-readable findings
├── payloads.txt                ← Context-aware payloads
├── scenarios.txt               ← Bug bounty scenarios
├── attack_suggestions.txt      ← Ranked attack actions
├── screenshots/                ← Target screenshots
└── knowledge/
    ├── knowledge_base.json     ← Learning engine state
    └── prev_assets.json        ← Asset history
```

---

## 🔄 Automated Scanning (Cron)

```bash
# Daily full scan at 8 AM with notifications
0 8 * * * cd /path/to/bughunter-pro && \
  /path/to/venv/bin/python3 main.py \
  -t example.com -s scope.txt \
  -o ./results/$(date +\%Y\%m\%d) \
  --notify-discord https://discord.com/api/webhooks/... \
  >> logs/daily.log 2>&1

# Every 6 hours — lightweight monitoring
0 */6 * * * cd /path/to/bughunter-pro && \
  /path/to/venv/bin/python3 main.py \
  -t example.com --no-fuzzing --no-screenshots --no-exploit \
  >> logs/monitor.log 2>&1
```

---

## 🏗️ Architecture

```
main.py (Pipeline Orchestrator — 17 stages)
├── recon.py          — Subdomain discovery, alive check, port scan
├── intelligence.py   — Risk scoring & target prioritization
├── learning_engine.py — Pattern learning from previous scans
├── exploit_engine.py — 24 safe PoC vulnerability checks
├── fuzzing_engine.py — Smart ffuf integration
├── payloads_engine.py — Context-aware payloads & scenarios
├── report_engine.py  — HTML report generation
├── burp_integration.py — Burp Suite proxy & export
├── notifier.py       — Slack / Discord notifications
└── utils.py          — Shared utilities & safety wrappers
```

---

## 🛠️ Troubleshooting

| Issue | Fix |
|-------|-----|
| `ModuleNotFoundError` | `pip install -r requirements.txt` |
| `subfinder not found` | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `dnsx not found` | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| `nuclei not found` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `ffuf not found` | `go install github.com/ffuf/ffuf/v2@latest` |
| No SecLists wordlists | `sudo apt install seclists` (tool auto-creates minimal fallback) |
| Burp not detected | Start Burp first, ensure proxy on `127.0.0.1:8080` |
| Rate limited | Reduce `--threads` to 5 |
| `nmap` requires sudo | `sudo python3 main.py -t example.com` |
| Tool works with missing tools | ✅ Normal — tool has graceful fallbacks |

---

## 🤝 Contributing

Pull requests welcome! Please:
1. Fork the repo
2. Create your feature branch: `git checkout -b feature/AmazingFeature`
3. Commit your changes: `git commit -m 'Add AmazingFeature'`
4. Push to the branch: `git push origin feature/AmazingFeature`
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## ⚖️ Legal

This tool is intended for:
- ✅ Authorized bug bounty programs (HackerOne, Bugcrowd, Intigriti...)
- ✅ Penetration testing with written permission
- ✅ Security research on your own infrastructure

**Never use on targets without explicit written authorization.**

---

<p align="center">Made with ❤️ for the Bug Bounty community</p>
