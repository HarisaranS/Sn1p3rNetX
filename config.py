import os
import logging
from pathlib import Path

# ── Try to load .env file if present ──────────────────────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, rely on environment vars

# ── Tool Identity ──────────────────────────────────────────────────────────────
VERSION       = "3.0"
TOOL_NAME     = "Sn1p3rNetX"
SCHEMA_VER    = "3.0"

# ── Database ───────────────────────────────────────────────────────────────────
DB_FILE = os.environ.get("SNX_DB_FILE", "sn1p3rnetx_history.db")

# ── AI / LLM Config ───────────────────────────────────────────────────────────
GROQ_API_KEY   = os.environ.get("GROQ_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")   # fallback provider

GROQ_MODEL     = os.environ.get("SNX_GROQ_MODEL",   "openai/gpt-oss-120b")
OPENAI_MODEL   = os.environ.get("SNX_OPENAI_MODEL", "gpt-4o-mini")
AI_MAX_TOKENS  = int(os.environ.get("SNX_AI_MAX_TOKENS", "2500"))
AI_TEMPERATURE = float(os.environ.get("SNX_AI_TEMPERATURE", "0.3"))
AI_RETRIES     = int(os.environ.get("SNX_AI_RETRIES", "3"))

# ── NVD / CVE ─────────────────────────────────────────────────────────────────
NVD_API_KEY    = os.environ.get("NVD_API_KEY", "")   # optional — enables live CVE lookups

# ── Scan Defaults ─────────────────────────────────────────────────────────────
DEFAULT_SCAN_MODE    = os.environ.get("SNX_SCAN_MODE",    "tcp")
DEFAULT_THREADS      = int(os.environ.get("SNX_THREADS",  "20"))
DEFAULT_SCAN_TIMEOUT = int(os.environ.get("SNX_TIMEOUT",  "120"))  # seconds per host

# ── Reporting ──────────────────────────────────────────────────────────────────
REPORT_DIR            = os.environ.get("SNX_REPORT_DIR", "reports/output")
DEFAULT_REPORT_FORMAT = os.environ.get("SNX_REPORT_FORMAT", "text")

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_FILE  = os.environ.get("SNX_LOG_FILE",  "sn1p3rnetx.log")
LOG_LEVEL = os.environ.get("SNX_LOG_LEVEL", "INFO").upper()

# ── Ensure report directory exists (lazy — done inside report functions) ──────
# Directory is created on first write, not at import time.
