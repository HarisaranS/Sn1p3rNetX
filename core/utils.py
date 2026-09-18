import os
import sqlite3
import json
import logging
import logging.handlers
from datetime import datetime
from config import DB_FILE, LOG_FILE, LOG_LEVEL

# ── Rotating File Logger ───────────────────────────────────────────────────────
def _build_logger():
    logger = logging.getLogger("sn1p3rnetx")
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    try:
        # Rotating file handler (10 MB × 5 backups)
        fh = logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        fh.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S"
        ))
        logger.addHandler(fh)
    except (PermissionError, OSError):
        # Can't write log file (e.g. read-only fs, sandbox) — use NullHandler
        logger.addHandler(logging.NullHandler())
    return logger

_logger = _build_logger()


def log_message(msg: str, level: str = "info"):
    """Write a message to the rotating log file at the given level."""
    fn = getattr(_logger, level.lower(), _logger.info)
    fn(msg)


# ── DB Helpers ────────────────────────────────────────────────────────────────

def init_db():
    """Ensure all required tables exist (idempotent)."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # ── scans: one row per scan session ──────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            target    TEXT    NOT NULL,
            scan_mode TEXT,
            raw_json  TEXT
        )
    """)

    # ── scan_hosts: one row per discovered host ───────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS scan_hosts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL,
            ip          TEXT,
            mac         TEXT,
            os          TEXT,
            vendor      TEXT,
            device_type TEXT,
            port_count  INTEGER,
            risk_score  INTEGER,
            risk_level  TEXT,
            host_json   TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)

    # ── Schema migration: add new columns to existing DBs ────────────────────
    migrations = [
        ("ALTER TABLE scans ADD COLUMN scan_mode TEXT",    "scans",      "scan_mode"),
        ("ALTER TABLE scans ADD COLUMN raw_json  TEXT",    "scans",      "raw_json"),
        ("ALTER TABLE scan_hosts ADD COLUMN vendor      TEXT", "scan_hosts", "vendor"),
        ("ALTER TABLE scan_hosts ADD COLUMN device_type TEXT", "scan_hosts", "device_type"),
        ("ALTER TABLE scan_hosts ADD COLUMN host_json   TEXT", "scan_hosts", "host_json"),
    ]
    for sql, table, column in migrations:
        try:
            c.execute(sql)
        except sqlite3.OperationalError:
            pass  # column already exists

    conn.commit()
    conn.close()


def save_scan_history(target: str, hosts_list: list, scan_mode: str = "tcp"):
    """Persist a complete scan session — metadata + per-host rows + raw JSON."""
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    raw_json = json.dumps(hosts_list, ensure_ascii=False)

    c.execute(
        "INSERT INTO scans (timestamp, target, scan_mode, raw_json) VALUES (?, ?, ?, ?)",
        (datetime.now().isoformat(), target, scan_mode, raw_json),
    )
    scan_id = c.lastrowid

    for h in hosts_list:
        c.execute(
            """INSERT INTO scan_hosts
               (scan_id, ip, mac, os, vendor, device_type, port_count, risk_score, risk_level, host_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                h.get("ip"),
                h.get("mac"),
                h.get("os"),
                h.get("vendor"),
                h.get("device_type", "Unknown"),
                len(h.get("open_ports", [])),
                h.get("risk_score", 0),
                h.get("risk_level", "UNKNOWN"),
                json.dumps(h, ensure_ascii=False),
            ),
        )

    conn.commit()
    conn.close()
    log_message(f"Saved scan for target={target} with {len(hosts_list)} host(s)")


def get_scan_history():
    """Return summary rows of past scans (most recent first, limit 100)."""
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT s.timestamp, s.target, COUNT(h.id) AS host_count,
               AVG(h.risk_score) AS avg_risk, s.scan_mode
        FROM   scans s
        LEFT JOIN scan_hosts h ON s.id = h.scan_id
        GROUP BY s.id
        ORDER BY s.id DESC
        LIMIT 100
    """)
    rows = c.fetchall()
    conn.close()
    return rows


def get_scan_detail(scan_id: int) -> dict:
    """Return the full raw_json blob for a past scan."""
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT raw_json FROM scans WHERE id = ?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if row and row[0]:
        try:
            return json.loads(row[0])
        except Exception:
            return {}
    return {}


def check_disclaimer():
    """Show disclaimer once; persist acceptance to disk."""
    disclaimer_file = ".disclaimer_accepted"
    if os.path.exists(disclaimer_file):
        return  # already accepted

    print("\n" + "=" * 50)
    print("WARNING: Sn1p3rNetX is a Network Intelligence Tool.")
    print("Only scan systems you have explicit authorisation to test.")
    print("The authors accept NO liability for misuse.")
    print("=" * 50 + "\n")
    ans = input("Do you accept these terms? (yes/no): ").strip().lower()
    if ans not in ("y", "yes"):
        print("You must accept the terms to use this tool. Exiting.")
        raise SystemExit(1)
    with open(disclaimer_file, "w") as f:
        f.write("accepted")
