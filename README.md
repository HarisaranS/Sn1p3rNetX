Sn1p3rNetX+ — AI-Powered Network Recon Scanner

'Sn1p3rNetX+' is an advanced AI-integrated network reconnaissance scanner that combines traditional scanning techniques with machine learning–based anomaly detection. 
It’s built for offensive security experts, students, red teamers, and bug bounty hunters.

> Performs recon, CVE mapping, OS fingerprinting, anomaly detection — all in one terminal-powered interface.

## Features

- > Deep TCP/UDP scanning using Nmap
- > AI-based anomaly detection with IsolationForest
- > CVE mapping based on identified services
- > OS fingerprinting with intelligent fallback
- > Live progress and beautiful output via Rich
- > Exports: JSON + CSV
- > MAC address and vendor mapping
- > Interactive + CLI modes

## Installation

#bash
git clone https://github.com/yourusername/Sn1p3rNetXPlus.git
cd Sn1p3rNetXPlus
pip install -r requirements.txt

>> Requires: nmap, python3, pip, searchsploit (optional for CVE lookup)

## Usage

## Train the model : 

#bash
python ai_anomaly.py 
# Next runs: auto loads trained models
python ai_anomaly.py --evaluate
 
# Optional: force retraining from fresh samples
python ai_anomaly.py --retrain

## Interactive Mode :
#bash
python3 sn1pernetx.py

## CLI Mode :
#bash
python3 sn1pernetx.py --target 192.168.1.0/24 --mode tcp --aggressive --threads 30 --fresh

## AI Anomaly Detection

- > Uses vectorized port/service data
- > IsolationForest trained on real recon logs
- > Flags anomalies based on behavior

## Output

- > results.json – Full scan result in structured JSON
- > results.csv – Ready to use in Excel/Google Sheets
- > logs/scan_*.log – Timestamped logs

## Credits

- > Developed by $3r3N — Cyber security
- > Contributions welcome via Pull Requests
