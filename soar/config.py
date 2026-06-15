import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Auto-load .env if present
_env_path = os.path.join(BASE_DIR, ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())
SOAR_DIR      = os.path.join(BASE_DIR, "soar")
CASES_DIR     = os.path.join(SOAR_DIR, "cases")
PLAYBOOKS_DIR = os.path.join(SOAR_DIR, "playbooks")
INCIDENT_DIR  = os.path.join(BASE_DIR, "incident-response")
LEDGER_FILE   = os.path.join(BASE_DIR, "policy-engine", "audit_ledger.json")

SLACK_WEBHOOK_URL  = os.environ.get("SLACK_WEBHOOK_URL", "")
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY", "")

os.makedirs(CASES_DIR, exist_ok=True)
os.makedirs(INCIDENT_DIR, exist_ok=True)
