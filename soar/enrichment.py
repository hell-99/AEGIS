import ipaddress
import json
import os
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from soar.config import ABUSEIPDB_API_KEY

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

_cache = {}


def _is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def _local_heuristic(ip):
    if _is_private(ip):
        return {
            "ip":              ip,
            "reputation_score": 0,
            "country":         "LOCAL",
            "isp":             "Private Network",
            "total_reports":   0,
            "is_known_attacker": False,
            "confidence":      "N/A",
            "source":          "local_heuristic",
            "note":            "Private/loopback address — internal traffic",
        }
    return {
        "ip":               ip,
        "reputation_score": -1,
        "country":          "UNKNOWN",
        "isp":              "UNKNOWN",
        "total_reports":    -1,
        "is_known_attacker": False,
        "confidence":       "UNKNOWN",
        "source":           "unavailable",
        "note":             "Set ABUSEIPDB_API_KEY env var for live enrichment",
    }


def enrich_ip(ip):
    if ip in _cache:
        return _cache[ip]

    if not ABUSEIPDB_API_KEY or not REQUESTS_AVAILABLE:
        result = _local_heuristic(ip)
        _cache[ip] = result
        _print_enrichment(result)
        return result

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=5,
        )
        data = resp.json().get("data", {})
        result = {
            "ip":               ip,
            "reputation_score": data.get("abuseConfidenceScore", 0),
            "country":          data.get("countryCode", "UNKNOWN"),
            "isp":              data.get("isp", "UNKNOWN"),
            "total_reports":    data.get("totalReports", 0),
            "is_known_attacker": data.get("abuseConfidenceScore", 0) >= 50,
            "confidence":       "HIGH" if data.get("abuseConfidenceScore", 0) >= 75 else
                                "MEDIUM" if data.get("abuseConfidenceScore", 0) >= 25 else "LOW",
            "source":           "abuseipdb",
            "note":             None,
        }
    except Exception as e:
        result = _local_heuristic(ip)
        result["note"] = f"AbuseIPDB lookup failed: {e}"

    _cache[ip] = result
    _print_enrichment(result)
    return result


def _print_enrichment(e):
    score = e["reputation_score"]
    color = "\033[91m" if score >= 50 else "\033[93m" if score >= 25 else "\033[92m"
    known = " ⚠ KNOWN ATTACKER" if e.get("is_known_attacker") else ""
    print(f"{color}[AEGIS-ENRICH] {e['ip']} | score={score} | "
          f"country={e['country']} | isp={e['isp']} | "
          f"reports={e['total_reports']} | src={e['source']}{known}\033[0m")
