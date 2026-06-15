import json
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from soar.config import SLACK_WEBHOOK_URL

SEVERITY_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH":     ":large_orange_circle:",
    "MEDIUM":   ":large_yellow_circle:",
    "LOW":      ":large_green_circle:",
}

SEVERITY_COLOR = {
    "CRITICAL": "#FF0000",
    "HIGH":     "#FF6600",
    "MEDIUM":   "#FFCC00",
    "LOW":      "#00CC44",
}

CONSOLE_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[91m",
    "MEDIUM":   "\033[93m",
    "LOW":      "\033[92m",
}


def send_alert(incident_id, alert_type, src_ip, severity, steps_summary, enrichment=None):
    _console_alert(incident_id, alert_type, src_ip, severity, steps_summary, enrichment)
    if SLACK_WEBHOOK_URL and REQUESTS_AVAILABLE:
        _slack_alert(incident_id, alert_type, src_ip, severity, steps_summary, enrichment)
    else:
        print(f"\033[90m[AEGIS-NOTIFY] Slack not configured — set SLACK_WEBHOOK_URL env var to enable\033[0m")


def _console_alert(incident_id, alert_type, src_ip, severity, steps_summary, enrichment):
    c = CONSOLE_COLOR.get(severity, "\033[93m")
    enrich_line = ""
    if enrichment and enrichment.get("source") != "unavailable":
        enrich_line = (f"\n{c}[AEGIS-NOTIFY]   Enrichment  : score={enrichment['reputation_score']} | "
                       f"country={enrichment['country']} | reports={enrichment['total_reports']}\033[0m")

    print(f"\n{c}{'='*62}\033[0m")
    print(f"{c}[AEGIS-NOTIFY] !! {severity} ALERT !!\033[0m")
    print(f"{c}[AEGIS-NOTIFY]   Incident ID : {incident_id}\033[0m")
    print(f"{c}[AEGIS-NOTIFY]   Threat Type : {alert_type}\033[0m")
    print(f"{c}[AEGIS-NOTIFY]   Source IP   : {src_ip}\033[0m")
    print(f"{c}[AEGIS-NOTIFY]   Severity    : {severity}\033[0m")
    if enrich_line:
        print(enrich_line, end="")
    print(f"{c}[AEGIS-NOTIFY]   Steps done  : {', '.join(steps_summary)}\033[0m")
    print(f"{c}{'='*62}\033[0m\n")


def _slack_alert(incident_id, alert_type, src_ip, severity, steps_summary, enrichment):
    emoji   = SEVERITY_EMOJI.get(severity, ":warning:")
    color   = SEVERITY_COLOR.get(severity, "#FFCC00")
    enrich_text = ""
    if enrichment and enrichment.get("source") not in ("unavailable", "local_heuristic"):
        enrich_text = (f"\n*Enrichment:* score={enrichment['reputation_score']} | "
                       f"country={enrichment['country']} | ISP={enrichment['isp']} | "
                       f"reports={enrichment['total_reports']}")

    payload = {
        "text": f"{emoji} *AEGIS SOAR Alert — {severity}*",
        "attachments": [{
            "color":  color,
            "fields": [
                {"title": "Incident ID",  "value": incident_id,          "short": True},
                {"title": "Threat Type",  "value": alert_type,           "short": True},
                {"title": "Source IP",    "value": src_ip,               "short": True},
                {"title": "Severity",     "value": severity,             "short": True},
                {"title": "Steps Taken",  "value": " → ".join(steps_summary), "short": False},
            ],
            "footer": f"AEGIS SOAR{enrich_text}",
        }]
    }

    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        if resp.status_code == 200:
            print(f"\033[92m[AEGIS-NOTIFY] Slack alert sent ✓\033[0m")
        else:
            print(f"\033[91m[AEGIS-NOTIFY] Slack returned {resp.status_code}\033[0m")
    except Exception as e:
        print(f"\033[91m[AEGIS-NOTIFY] Slack send failed: {e}\033[0m")
