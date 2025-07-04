## Sn1p3rNetX+  AI-Powered Network Recon Scanner

Sn1p3rNetX+ is an advanced AI-integrated network reconnaissance scanner that combines traditional scanning techniques with machine learning–based anomaly detection. 
It’s built for offensive security experts, students, red teamers, and bug bounty hunters.

Performs recon, CVE mapping, OS fingerprinting, anomaly detection — all in one terminal-powered interface.

## Features

-  Deep TCP/UDP scanning using Nmap
-  AI-based anomaly detection with IsolationForest
-  CVE mapping based on identified services
-  OS fingerprinting with intelligent fallback
-  Live progress and beautiful output via Rich
-  Exports: JSON + CSV
-  MAC address and vendor mapping
-  Interactive + CLI modes

## Installation

```yaml
git clone https://github.com/HarisaranS/Sn1p3rNetX.git
cd Sn1p3rNetX
pip install -r requirements.txt
```
**note: if pip installation fails, create a virtual environment or just use,**
```yaml
pip install -r requirements.txt --break-system-packages
```
use the above command at you own risk

**All in one command (easier installation):**
```yaml
git clone https://github.com/HarisaranS/Sn1p3rNetX.git && cd Sn1p3rNetX && pip install -r requirements.txt --break-system-packages
```


## Usage

## First Step (Important)
**Train the model :**
## Step 1
```yaml
python ai_anomaly.py
```
## Step 2
```yaml 
python ai_anomaly.py --evaluate 
```
## Step 3 (Optional)
```yaml
python ai_anomaly.py --retrain 
```

## Interactive Mode(Recommended) :
```yaml
sudo python3 Sn1p3rNetX.py
```
## CLI Mode(Pro) :
```yaml
sudo python3 Sn1p3rNetX.py --target <target> --mode tcp --aggressive --threads 50 --fresh
```
## AI Anomaly Detection

- Uses vectorized port/service data
- IsolationForest trained on real recon logs
- Flags anomalies based on behavior

## Output

- Results.json – Full scan result in structured JSON
- Results.csv – Ready to use in Excel/Google Sheets
- Logs/scan_*.log – Timestamped logs

## Credits

- Developed by $3r3N — Cyber security
- Contributions welcome via Pull Requests
