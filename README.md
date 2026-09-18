<div align="center">
  <img src="https://img.icons8.com/color/96/000000/radar.png" alt="logo"/>
  <h1>Sn1p3rNetX Enterprise</h1>
  <p><strong>AI-Powered Network Security Intelligence Platform (NSIP)</strong></p>
</div>

---

Sn1p3rNetX Enterprise is a comprehensive, AI-driven Network Security Intelligence Platform. It goes beyond simple port scanning to provide board-ready business risk translation, automatic remediation scripting, compliance mapping, network drift detection, and interactive live dashboards.

##  Features

- **Business Risk Translation**: Translates technical vulnerabilities (CVSS 9.8) into realistic financial breach cost estimates using FAIR-inspired models.
- **Threat Actor Profiler**: Correlates exposed ports and CVEs with known Advanced Persistent Threat (APT) groups (e.g., APT41, LockBit).
- **Compliance Mapping Engine**: Automatically maps findings to major frameworks including PCI-DSS, HIPAA, and NIST 800-53, providing audit-ready grades.
- **AI Remediation Commander**: Generates exact, priority-ordered executable shell scripts (`ufw`, `systemctl`, `mysql`) to instantly fix identified vulnerabilities.
- **Network Drift Detector**: Uses a local SQLite time-series database to instantly detect new open ports, closed services, or rising risk scores across scans.
- **Live Interactive Dashboard**: A Rich-powered Terminal User Interface (TUI) acting as an `htop` for network security, providing real-time telemetry.
- **Attack Story Engine**: Uses AI to generate a step-by-step narrative of the most likely attack path based on the specific services exposed.

##  Architecture

The platform is designed around an extensible **8-Pillar NSIP Architecture**, orchestrated centrally by `cli.py`:

```
Sn1p3rNetX/
├── cli.py                    # The central CLI orchestrator and entry point
├── config.py                 # System configurations and API limits
├── sn1p3rnetx_history.db     # SQLite database storing time-series scan results
├── core/
│   ├── scanner.py            # Nmap orchestration (TCP/SYN, OS Detection)
│   ├── parser.py             # Parses Nmap XML & handles MAC/vendor lookups
│   ├── cve_lookup.py         # Offline CVE knowledge base + SearchSploit
│   ├── risk_engine.py        # CVSS math, Port weighting, Device classification
│   ├── drift_detector.py     # SQLite comparison for network drift
│   ├── compliance.py         # PCI-DSS, HIPAA, NIST mapping
│   ├── remediation.py        # Generates bash scripts for fixes
│   ├── business_risk.py      # Breach cost & probability translation
│   ├── threat_actors.py      # APT & Ransomware group profiling
│   ├── attack_story.py       # AI Kill-chain narrative generation
│   ├── dashboard.py          # Rich-based interactive TUI
│   └── watchdog.py           # Background monitoring daemon
└── tests/                    # Pytest coverage (100% Pass Rate)
```

##  Installation & Setup

1. **Clone & Environment Setup**
   ```bash
   git clone https://github.com/yourrepo/Sn1p3rNetX.git
   cd Sn1p3rNetX
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **API Keys (Optional but Recommended)**
   To enable AI Attack Story generation, add your API key to an `.env` file:
   ```env
   GROQ_API_KEY='your_api_key_here'
   ```

4. **System Privileges**
   While Sn1p3rNetX gracefully falls back to a non-root TCP Connect scan (`-sT`), **running as root (`sudo`) is highly recommended**. Root enables:
   - SYN Stealth Scanning (`-sS`)
   - OS Fingerprinting (`-O`)
   - ARP-based local network discovery (`-PR`)

##  Usage Guide

All interactions happen through `cli.py`. The typical workflow involves running a scan to populate the database, followed by running intelligence commands.

### 1. Scanning the Network
**Basic Fast Scan**
```bash
sudo -E python3 cli.py scan 192.168.1.8
```
**Deep Intelligence Scan (Vulnerability Enrichment + Risk Scoring)**
```bash
sudo -E python3 cli.py fullscan 192.168.1.8
```
*(Note: You can scan a single IP, a CIDR like `192.168.1.0/24`, or `auto` for the local subnet).*

### 2. Live Security Operations (SecOps)
Launch the interactive terminal dashboard to monitor the host's security posture:
```bash
python3 cli.py dashboard 192.168.1.8
```
*(Press `Ctrl+C` to exit).*

### 3. Change Detection (Drift)
Compare the latest scan against the previous scan to find what changed:
```bash
python3 cli.py drift 192.168.1.8
```

### 4. Automatic Remediation
Generate an exact bash script to fix the vulnerabilities found:
```bash
python3 cli.py remediate 192.168.1.8 > fix.sh
chmod +x fix.sh
./fix.sh
```

### 5. Compliance & Auditing
Map the current security posture against PCI-DSS, HIPAA, and NIST 800-53:
```bash
python3 cli.py comply 192.168.1.8
```

### 6. Board & Executive Reporting
**Business Risk & Cost Estimation:**
```bash
python3 cli.py business 192.168.1.8
```
**AI Attack Narrative (Kill Chain):**
```bash
python3 cli.py story 192.168.1.8
```

### 7. View Scan History
See all historical scans stored in the SQLite database:
```bash
python3 cli.py history
```

##  Testing

Sn1p3rNetX comes with a comprehensive `pytest` suite ensuring 100% reliability across all core modules.
```bash
source .venv/bin/activate
PYTHONPATH=. pytest tests/ -v
```

##  Security & Disclaimer
**For Authorised Use Only.** 
Sn1p3rNetX Enterprise is a powerful security intelligence tool. The authors are not responsible for any misuse or damage caused by this software. Always ensure you have explicit permission before scanning a network.
