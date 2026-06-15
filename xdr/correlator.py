"""
AEGIS XDR Correlator
====================
Polls AEGIS (network), IRIS (AI agent), and AWS Scanner (cloud) for recent
high-severity events. When 2+ sources fire within the same time window,
a correlated SOAR case is triggered — indicating a coordinated multi-vector attack.

Run standalone:   python3 xdr/correlator.py
Run as daemon:    python3 xdr/correlator.py --daemon
"""
import json
import os
import sys
import time
import argparse
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from soar.config import BASE_DIR, SLACK_WEBHOOK_URL

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ── Config ────────────────────────────────────────────────────────────────────

IRIS_API_URL      = os.environ.get("IRIS_API_URL", "http://localhost:8000")
AWS_FINDINGS_FILE = os.environ.get("AWS_FINDINGS_FILE",
    os.path.join(BASE_DIR, "..", "aws-security-scanner", "findings.json"))
CORRELATION_WINDOW_MINUTES = int(os.environ.get("XDR_WINDOW_MINUTES", "5"))
POLL_INTERVAL_SECONDS      = int(os.environ.get("XDR_POLL_SECONDS", "30"))

LEDGER_FILE = os.path.join(BASE_DIR, "policy-engine", "audit_ledger.json")
ALERTS_LOG  = os.path.join(BASE_DIR, "ids-ips", "alerts.log")

# Track already-fired correlations to avoid duplicate cases
_fired_hashes = set()


# ── Source pollers ────────────────────────────────────────────────────────────

def _poll_aegis(window_start):
    """Read AEGIS audit ledger + alert log for recent HIGH/CRITICAL events."""
    signals = []

    # Ledger entries
    try:
        with open(LEDGER_FILE) as f:
            ledger = json.load(f)
        for entry in ledger:
            ts = entry.get("timestamp", "")
            try:
                t = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            if t < window_start:
                continue
            action = entry.get("action", "")
            if action in ("BLOCK", "ENSEMBLE-BLOCK", "SOAR-ESCALATE", "SOAR-IR"):
                signals.append({
                    "source":    "AEGIS",
                    "type":      "NETWORK_THREAT",
                    "action":    action,
                    "src_ip":    entry.get("src_ip", "unknown"),
                    "detail":    entry.get("reason", ""),
                    "timestamp": ts,
                    "severity":  "CRITICAL" if "ENSEMBLE" in action else "HIGH",
                })
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"\033[93m[AEGIS-XDR] Ledger read error: {e}\033[0m")

    # Alert log (rule-based IDS)
    try:
        with open(ALERTS_LOG) as f:
            for line in f.readlines()[-200:]:
                if "ALERT" not in line:
                    continue
                ts_str = line[1:20] if line.startswith("[") else None
                if not ts_str:
                    continue
                try:
                    t = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
                if t < window_start:
                    continue
                signals.append({
                    "source":    "AEGIS",
                    "type":      "IDS_ALERT",
                    "action":    "ALERT",
                    "src_ip":    _extract_ip(line),
                    "detail":    line.strip(),
                    "timestamp": ts_str,
                    "severity":  "HIGH",
                })
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"\033[93m[AEGIS-XDR] Alert log read error: {e}\033[0m")

    return signals


def _poll_iris(window_start):
    """Query IRIS FastAPI for recent detections and collusion."""
    signals = []

    if not REQUESTS_AVAILABLE:
        print(f"\033[90m[AEGIS-XDR] requests not available — IRIS polling skipped\033[0m")
        return signals

    # Intent-action divergence (prompt injection)
    try:
        resp = requests.get(f"{IRIS_API_URL}/api/detections",
                            params={"verdict": "SUSPICIOUS", "limit": 50}, timeout=5)
        if resp.status_code == 200:
            detections = resp.json().get("detections", [])
            for d in detections:
                ts_str = d.get("timestamp", "")
                try:
                    t = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    try:
                        t = datetime.fromisoformat(ts_str[:19])
                    except Exception:
                        continue
                if t < window_start:
                    continue
                signals.append({
                    "source":    "IRIS",
                    "type":      "PROMPT_INJECTION",
                    "action":    "DIVERGENCE_DETECTED",
                    "src_ip":    None,
                    "agent":     d.get("agent_role", "unknown"),
                    "detail":    f"divergence_score={d.get('divergence_score', '?')} task={d.get('task', '?')}",
                    "timestamp": ts_str,
                    "severity":  "HIGH",
                })
    except requests.exceptions.ConnectionError:
        print(f"\033[90m[AEGIS-XDR] IRIS API not reachable at {IRIS_API_URL} — skipping\033[0m")
        return signals
    except Exception as e:
        print(f"\033[93m[AEGIS-XDR] IRIS detections error: {e}\033[0m")

    # Cross-agent collusion
    try:
        resp = requests.get(f"{IRIS_API_URL}/api/collusion",
                            params={"severity": "CRITICAL", "limit": 50}, timeout=5)
        if resp.status_code == 200:
            detections = resp.json().get("detections", [])
            for d in detections:
                ts_str = d.get("detected_at", "")
                try:
                    t = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
                if t < window_start:
                    continue
                signals.append({
                    "source":    "IRIS",
                    "type":      "AGENT_COLLUSION",
                    "action":    "COLLUSION_DETECTED",
                    "src_ip":    None,
                    "agent":     f"{d.get('agent1_role')} + {d.get('agent2_role')}",
                    "detail":    f"pattern={d.get('pattern_type')} severity={d.get('severity')}",
                    "timestamp": ts_str,
                    "severity":  d.get("severity", "HIGH"),
                })
    except Exception as e:
        print(f"\033[93m[AEGIS-XDR] IRIS collusion error: {e}\033[0m")

    # Blocked tool calls (high-risk agent actions)
    try:
        resp = requests.get(f"{IRIS_API_URL}/api/events",
                            params={"blocked_only": True, "limit": 50}, timeout=5)
        if resp.status_code == 200:
            events = resp.json().get("events", [])
            high_risk = [e for e in events
                         if (e.get("risk_score") or 0) >= 70]
            for e in high_risk:
                ts_str = e.get("timestamp", "")
                try:
                    t = datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
                if t < window_start:
                    continue
                signals.append({
                    "source":    "IRIS",
                    "type":      "HIGH_RISK_TOOL_CALL",
                    "action":    "BLOCKED",
                    "src_ip":    None,
                    "agent":     e.get("agent_role", "unknown"),
                    "detail":    f"tool={e.get('tool_name')} risk={e.get('risk_score')} ttp={e.get('ttp_name')}",
                    "timestamp": ts_str,
                    "severity":  "CRITICAL" if (e.get("risk_score") or 0) >= 85 else "HIGH",
                })
    except Exception as e:
        print(f"\033[93m[AEGIS-XDR] IRIS events error: {e}\033[0m")

    return signals


def _poll_aws(window_start):
    """Read AWS Scanner findings JSON if available."""
    signals = []
    path = os.path.expanduser(AWS_FINDINGS_FILE)

    if not os.path.exists(path):
        return signals

    try:
        mtime = datetime.fromtimestamp(os.path.getmtime(path))
        if mtime < window_start:
            return signals  # File not updated in window

        with open(path) as f:
            findings = json.load(f)

        if isinstance(findings, dict):
            findings = findings.get("findings", [])

        for finding in findings:
            sev = finding.get("severity", "").upper()
            if sev not in ("HIGH", "CRITICAL"):
                continue
            signals.append({
                "source":    "AWS",
                "type":      "CLOUD_MISCONFIGURATION",
                "action":    "FINDING",
                "src_ip":    None,
                "detail":    f"{finding.get('check', '?')} — {finding.get('resource', '?')}",
                "timestamp": mtime.strftime("%Y-%m-%d %H:%M:%S"),
                "severity":  sev,
            })
    except Exception as e:
        print(f"\033[93m[AEGIS-XDR] AWS findings read error: {e}\033[0m")

    return signals


# ── Correlation engine ────────────────────────────────────────────────────────

def correlate(window_minutes=None):
    window_minutes = window_minutes or CORRELATION_WINDOW_MINUTES
    window_start = datetime.now() - timedelta(minutes=window_minutes)

    print(f"\033[96m[AEGIS-XDR] Polling sources (window={window_minutes}min)...\033[0m")

    aegis_signals = _poll_aegis(window_start)
    iris_signals  = _poll_iris(window_start)
    aws_signals   = _poll_aws(window_start)

    all_signals = aegis_signals + iris_signals + aws_signals

    # Group by source
    by_source = {}
    for s in all_signals:
        src = s["source"]
        by_source.setdefault(src, []).append(s)

    active_sources = list(by_source.keys())

    _print_poll_summary(by_source)

    # Correlation fires when 2+ sources have recent high-severity events
    if len(active_sources) >= 2:
        return _fire_correlation(active_sources, by_source)

    print(f"\033[92m[AEGIS-XDR] No correlation — only {len(active_sources)} source(s) active\033[0m\n")
    return None


def _fire_correlation(active_sources, by_source):
    # Deduplicate: same source combo in same window shouldn't fire twice
    combo_key = "+".join(sorted(active_sources)) + "_" + datetime.now().strftime("%Y%m%d%H%M")
    if combo_key in _fired_hashes:
        print(f"\033[93m[AEGIS-XDR] Correlation already fired for this window — skipping\033[0m")
        return None
    _fired_hashes.add(combo_key)

    # Pick a representative src_ip from AEGIS signals (or UNKNOWN)
    src_ip = "MULTI-SOURCE"
    for s in by_source.get("AEGIS", []):
        if s.get("src_ip") and s["src_ip"] != "unknown":
            src_ip = s["src_ip"]
            break

    details = _build_details(active_sources, by_source)

    print(f"\n\033[91m{'='*62}\033[0m")
    print(f"\033[91m[AEGIS-XDR] !! MULTI-VECTOR CORRELATED ATTACK DETECTED !!\033[0m")
    print(f"\033[91m[AEGIS-XDR] Sources    : {' + '.join(active_sources)}\033[0m")
    print(f"\033[91m[AEGIS-XDR] AEGIS      : {len(by_source.get('AEGIS', []))} network event(s)\033[0m")
    print(f"\033[91m[AEGIS-XDR] IRIS       : {len(by_source.get('IRIS', []))} AI agent event(s)\033[0m")
    print(f"\033[91m[AEGIS-XDR] AWS        : {len(by_source.get('AWS', []))} cloud finding(s)\033[0m")
    print(f"\033[91m{'='*62}\033[0m\n")

    # Fire SOAR playbook
    from incident_response import generate_incident_report
    incident_id = f"XDR-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    report = generate_incident_report("CORRELATED-ATTACK", src_ip, details)

    # Attach XDR metadata to the saved report
    _enrich_report(report, active_sources, by_source)

    return report


def _build_details(active_sources, by_source):
    parts = []
    for src in active_sources:
        events = by_source[src]
        types  = list({e["type"] for e in events})
        parts.append(f"{src}:[{','.join(types)}]")
    return " | ".join(parts)


def _enrich_report(report, active_sources, by_source):
    if not report:
        return
    report["xdr"] = {
        "correlated_sources": active_sources,
        "signal_breakdown": {
            src: [{"type": e["type"], "detail": e["detail"], "severity": e["severity"]}
                  for e in events]
            for src, events in by_source.items()
        },
    }


def _print_poll_summary(by_source):
    total = sum(len(v) for v in by_source.values())
    if total == 0:
        print(f"\033[92m[AEGIS-XDR] All quiet — 0 signals across all sources\033[0m")
        return
    for src, events in by_source.items():
        types = ", ".join({e["type"] for e in events})
        print(f"\033[93m[AEGIS-XDR] {src:<6} : {len(events)} signal(s) — {types}\033[0m")


def _extract_ip(line):
    import re
    m = re.search(r'SRC:\s*([\d.]+)', line)
    return m.group(1) if m else "unknown"


# ── Entry point ───────────────────────────────────────────────────────────────

def run_once():
    """Single correlation check — useful for testing."""
    return correlate()


def run_daemon(interval=None):
    """Continuous polling loop."""
    interval = interval or POLL_INTERVAL_SECONDS
    print(f"\033[96m[AEGIS-XDR] XDR Correlator starting — polling every {interval}s\033[0m")
    print(f"\033[96m[AEGIS-XDR] Sources: AEGIS (network) | IRIS ({IRIS_API_URL}) | AWS Scanner\033[0m")
    print(f"\033[96m[AEGIS-XDR] Correlation window: {CORRELATION_WINDOW_MINUTES} minutes\033[0m\n")

    while True:
        try:
            correlate()
        except KeyboardInterrupt:
            print(f"\n\033[93m[AEGIS-XDR] Stopped.\033[0m")
            break
        except Exception as e:
            print(f"\033[91m[AEGIS-XDR] Error: {e}\033[0m")
        print(f"[AEGIS-XDR] Next check in {interval}s...\n")
        time.sleep(interval)


if __name__ == "__main__":
    sys.path.insert(0, os.path.join(BASE_DIR, "incident-response"))

    parser = argparse.ArgumentParser(description="AEGIS XDR Correlator")
    parser.add_argument("--daemon", action="store_true",
                        help="Run continuously (default: single check)")
    parser.add_argument("--interval", type=int, default=POLL_INTERVAL_SECONDS,
                        help=f"Poll interval in seconds (default: {POLL_INTERVAL_SECONDS})")
    parser.add_argument("--window",   type=int, default=CORRELATION_WINDOW_MINUTES,
                        help=f"Correlation window in minutes (default: {CORRELATION_WINDOW_MINUTES})")
    args = parser.parse_args()

    CORRELATION_WINDOW_MINUTES = args.window

    if args.daemon:
        run_daemon(args.interval)
    else:
        print("[AEGIS-XDR] Running single correlation check...\n")
        result = run_once()
        if result:
            print(f"\n[AEGIS-XDR] Correlated incident fired: {result.get('incident_id', 'XDR')}")
        else:
            print("[AEGIS-XDR] No multi-vector correlation detected.")
