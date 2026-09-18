"""
ai_analyzer.py — AI-powered cybersecurity analysis engine.

Features:
  • Groq (Llama-3.3-70b) primary — falls back to OpenAI if configured
  • Exponential-backoff retry (up to 3 attempts)
  • Response cache keyed on MD5(scan_data_json)  — avoids re-analyzing same host
  • Structured prompt covering: Executive Summary, Risk Explanation,
    Attack Vectors, MITRE ATT&CK techniques, Remediation, Hardening
  • Emits a well-formed Markdown report section
"""

import json
import time
import hashlib
import os
try:
    from openai import OpenAI, APIError, RateLimitError
except ImportError:
    OpenAI = None
    APIError = Exception
    RateLimitError = Exception
from config import (
    GROQ_API_KEY, OPENAI_API_KEY,
    GROQ_MODEL, OPENAI_MODEL,
    AI_MAX_TOKENS, AI_TEMPERATURE, AI_RETRIES,
)
from core.utils import log_message

# ── In-process cache (hash → analysis text) ───────────────────────────────────
_ANALYSIS_CACHE: dict[str, str] = {}


def _cache_key(data: dict) -> str:
    """Return MD5 hex digest of JSON-serialised scan data."""
    raw = json.dumps(data, sort_keys=True, ensure_ascii=False)
    return hashlib.md5(raw.encode()).hexdigest()


def _build_client(provider: str):
    """Return an OpenAI-compatible client for the requested provider."""
    if provider == "groq" and GROQ_API_KEY:
        return OpenAI(
            api_key=GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1",
        )
    if provider == "openai" and OPENAI_API_KEY:
        return OpenAI(api_key=OPENAI_API_KEY)
    return None


def _call_llm(client, model: str, messages: list,
              max_tokens: int, temperature: float) -> str:
    """Send a chat completion request and return the response text."""
    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return response.choices[0].message.content.strip()


def _build_prompt(scan_data: dict) -> tuple[str, str]:
    """Build system + user prompt from scan_data."""
    ip           = scan_data.get("ip", "unknown")
    os_det       = scan_data.get("os", "Unknown OS")
    device_type  = scan_data.get("device_type", "Unknown")
    risk_score   = scan_data.get("risk_score", 0)
    risk_level   = scan_data.get("risk_level", "UNKNOWN")
    services     = scan_data.get("services", [])
    mitre        = scan_data.get("mitre_techniques", [])
    metrics      = scan_data.get("risk_metrics", {})

    # Build a compact CVE summary
    cve_lines = []
    for svc in services:
        for v in svc.get("vulnerabilities", []):
            cve_lines.append(
                f"  • [{v['severity']}] {v['cve_id']} — {v['description']} "
                f"(CVSS {v.get('cvss_score', 'N/A')}) on port {svc['port']}"
            )
    cve_summary = "\n".join(cve_lines[:25]) if cve_lines else "  None detected"

    mitre_summary = "\n".join(
        f"  • {t['technique_id']}: {t['technique_name']}" for t in mitre[:10]
    ) or "  None mapped"

    system = (
        "You are a senior cybersecurity analyst with Red Team and Blue Team expertise. "
        "Analyse ONLY the provided scan data. "
        "Do NOT invent CVEs, do NOT hallucinate services, do NOT overclaim exploitability. "
        "Be precise, concise, and actionable."
    )

    user = f"""Produce a professional cybersecurity assessment for the host below.
Format your response EXACTLY with these Markdown sections:

##  Executive Summary
(2–3 sentence overview of the host's security posture)

##  Risk Breakdown
(Explain the risk score and what drives it)

##  Potential Attack Vectors
(List the 3–5 most dangerous attack paths an adversary would exploit first)

##  MITRE ATT&CK Techniques Observed
(Reference the provided techniques with brief explanation)

##  Recommended Remediation
(Numbered, prioritised list — most critical first)

##  Defensive Hardening Advice
(Practical hardening steps specific to the detected services)

---
HOST INTELLIGENCE:
- IP: {ip}
- Device Type: {device_type}
- OS: {os_det}
- Risk Score: {risk_score}/100  ({risk_level})
- Open Ports: {metrics.get('total_open_ports', 0)}
- Critical CVEs: {metrics.get('critical_cves', 0)}
- High CVEs: {metrics.get('high_cves', 0)}
- Max CVSS: {metrics.get('max_cvss', 0)}
- Attack Surface Index: {metrics.get('attack_surface_idx', 0)}%

DETECTED CVEs / VULNERABILITIES:
{cve_summary}

MITRE ATT&CK TECHNIQUES:
{mitre_summary}

SERVICES:
{json.dumps([{"port": s["port"], "desc": s["description"]} for s in services], indent=2)}
"""
    return system, user


def generate_ai_analysis(scan_data: dict) -> str:
    """
    Main entry point — returns a Markdown analysis string.
    Results are cached by scan content hash.
    Tries Groq first, then OpenAI as fallback.
    """
    if not GROQ_API_KEY and not OPENAI_API_KEY:
        return (
            " **AI Analysis Unavailable** — set `GROQ_API_KEY` or `OPENAI_API_KEY` "
            "in your environment or `.env` file."
        )

    if OpenAI is None:
        return (
            " **AI Analysis Unavailable** — `openai` Python package is missing. "
            "Ensure you are running in your virtual environment (e.g., `sudo -E python3`)."
        )

    # ── Cache lookup ──────────────────────────────────────────────────────────
    cache_key = _cache_key(scan_data)
    if cache_key in _ANALYSIS_CACHE:
        log_message(f"AI cache hit for {scan_data.get('ip', '?')}")
        return _ANALYSIS_CACHE[cache_key]

    system_prompt, user_prompt = _build_prompt(scan_data)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_prompt},
    ]

    providers = []
    if GROQ_API_KEY:
        providers.append(("groq", GROQ_MODEL))
    if OPENAI_API_KEY:
        providers.append(("openai", OPENAI_MODEL))

    last_error = "Unknown error"
    for provider_name, model_name in providers:
        client = _build_client(provider_name)
        if not client:
            continue

        for attempt in range(1, AI_RETRIES + 1):
            try:
                log_message(
                    f"AI request [{provider_name}/{model_name}] "
                    f"for {scan_data.get('ip', '?')} — attempt {attempt}"
                )
                result = _call_llm(
                    client, model_name, messages,
                    max_tokens=AI_MAX_TOKENS,
                    temperature=AI_TEMPERATURE,
                )
                _ANALYSIS_CACHE[cache_key] = result
                return result

            except RateLimitError as e:
                wait = 2 ** attempt
                log_message(f"Rate limit on attempt {attempt}: {e} — waiting {wait}s", "warning")
                time.sleep(wait)
                last_error = str(e)

            except APIError as e:
                log_message(f"API error on attempt {attempt}: {e}", "error")
                last_error = str(e)
                if attempt < AI_RETRIES:
                    time.sleep(1.5 * attempt)

            except Exception as e:
                log_message(f"Unexpected AI error: {e}", "error")
                last_error = str(e)
                break

    return f" **AI Analysis Failed** — {last_error}"
