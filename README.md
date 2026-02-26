```bash
 ____        _      _____      _   _      _  __  __
/ ___| _ __ / |_ __|___ / _ __| \ | | ___| |_\ \/ /
\___ \| '_ \| | '_ \ |_ \| '__|  \| |/ _ \ __|\  / 
 ___) | | | | | |_) |__) | |  | |\  |  __/ |_ /  \ 
|____/|_| |_|_| .__/____/|_|  |_| \_|\___|\__/_/\_\
              |_|                                  
 
  <<< AI-Powered Network Risk Intelligence  >>>
```

**Sn1p3rNetX** is a professional-grade, modular network reconnaissance tool that combines the raw power of **Network Scanning** with contextual **AI Analysis**. It doesn't just find open ports; it understands what they mean for your security posture.

---

## Core Features

- **Contextual AI Analysis**: Leverages Groq (Llama-3.3-70b) to analyze scan results and provide executive summaries, attack vector predictions, and hardening advice.
- **Multi-Layer Recon**: Automatically enriches scan data with real CVEs (via NIST/Vulners integration) and calculates a structured Risk Score (0-100).
- **Vibrant Interactive UI**: Features a professional ASCII banner, real-time loading animations (Rich spinners), and clean tabulated results.
- **Resident Resilience**: Automatically detects root privileges and falls back to stealth-friendly scans if running without`sudo`.
- **Unified Reporting**: Generates beautiful terminal outputs, structured JSON logs, and professional PDF summaries.
- **Scan History**: Persistent SQLite-backed history to track targets and risk scores over time.

---

## Installation

### 1. Prerequisites
Ensure you have Nmap installed on your system:
```bash
sudo apt update && sudo apt install nmap -y
```

### **2. Clone and Setup**

```bash
git clone https://github.com/HarisaranS/Sn1p3rNetX.git
cd Sn1p3rNetX
pip install -r requirements.txt
```

### **3. Configure AI**

Export your Groq API Key to your environment:

```bash
export GROQ_API_KEY='your_api_key_here'
```

> **Tip**: Use `sudo -E` when running privileged scans to ensure your environment variables (like API keys) are preserved.

---

##  Usage

###  Full AI Pipeline (Recommended)

Run a complete scan, CVE enrichment, risk scoring, and AI analysis in one go.

```bash
sudo -E python3 cli.py fullscan 192.168.1.0/24 --pdf
```

###  Standard Network Scan

Perform a fast vulnerability scan without AI overhead.

```bash
python3 cli.py scan 192.168.1.8 --json
```

###  AI Analysis from JSON

Analyze a previously saved JSON scan report using the AI engine.

```bash
python3 cli.py analyze report.json --pdf
```

### History

View your past scan activity and risk levels.

```bash
python3 cli.py history
```

---

## Important Note on Permissions

**Sn1p3rNetX** features a smart permission-aware engine:

- **Root (`sudo`)**: Enables OS Fingerprinting, SYN Stealth Scans, and advanced MAC detection.
- **User**: Automatically falls back to TCP Connect scans. You will still see open ports, but OS details and some MAC information may be limited.

---

##  Disclaimer

**For Authorized Use Only.** Sn1p3rNetX is designed for security professionals and authorized penetration testing. Scanning systems without explicit permission is illegal and unethical. The authors assume no liability for misuse of this tool.

---

