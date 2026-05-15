#!/usr/bin/env python3
"""Fetches CTI data from multiple threat intelligence sources and writes to data/cti_data.json."""

import json
import os
import sys
import traceback
from datetime import datetime, timezone

import requests

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "CTI-Dashboard/1.0 (github.com/cti-dashboard)"})
TIMEOUT = 30


def ts():
    return datetime.now(timezone.utc).isoformat()


def _err(source, e):
    print(f"  [ERROR] {source}: {e}", file=sys.stderr)
    return {"source": source, "status": "error", "error": str(e), "items": [], "last_updated": ts()}


# ── Free sources ──────────────────────────────────────────────────────────────

def fetch_cisa_kev():
    try:
        r = SESSION.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        return {
            "source": "CISA KEV",
            "description": "Known Exploited Vulnerabilities Catalog",
            "count": len(vulns),
            "items": [
                {
                    "id": v.get("cveID", ""),
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "date_added": v.get("dateAdded", ""),
                    "due_date": v.get("dueDate", ""),
                    "description": (v.get("shortDescription", "") or "")[:250],
                    "action": (v.get("requiredAction", "") or "")[:200],
                }
                for v in vulns[:25]
            ],
            "last_updated": ts(),
            "status": "ok",
        }
    except Exception as e:
        return _err("CISA KEV", e)


def fetch_urlhaus():
    try:
        r = SESSION.post(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            data={"limit": 25},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        urls = r.json().get("urls", [])
        return {
            "source": "URLhaus",
            "description": "Malware Distribution URLs (Abuse.ch)",
            "items": [
                {
                    "url": u.get("url", ""),
                    "status": u.get("url_status", ""),
                    "host": u.get("host", ""),
                    "threat": u.get("threat", ""),
                    "tags": u.get("tags") or [],
                    "date_added": u.get("date_added", ""),
                }
                for u in urls
            ],
            "last_updated": ts(),
            "status": "ok",
        }
    except Exception as e:
        return _err("URLhaus", e)


def fetch_malwarebazaar():
    try:
        r = SESSION.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "time"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        samples = r.json().get("data", [])
        return {
            "source": "MalwareBazaar",
            "description": "Recent Malware Samples (Abuse.ch)",
            "items": [
                {
                    "sha256": s.get("sha256_hash", ""),
                    "md5": s.get("md5_hash", ""),
                    "file_name": s.get("file_name", ""),
                    "file_type": s.get("file_type_mime", ""),
                    "signature": s.get("signature") or "Unknown",
                    "tags": s.get("tags") or [],
                    "first_seen": s.get("first_seen", ""),
                    "imphash": s.get("imphash", ""),
                }
                for s in samples[:25]
            ],
            "last_updated": ts(),
            "status": "ok",
        }
    except Exception as e:
        return _err("MalwareBazaar", e)


def fetch_threatfox():
    try:
        r = SESSION.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        iocs = r.json().get("data") or []
        return {
            "source": "ThreatFox",
            "description": "Indicators of Compromise (Abuse.ch)",
            "items": [
                {
                    "ioc": i.get("ioc_value", ""),
                    "type": i.get("ioc_type", ""),
                    "threat": i.get("threat_type", ""),
                    "malware": i.get("malware", ""),
                    "confidence": i.get("confidence_level", 0),
                    "first_seen": i.get("first_seen", ""),
                    "tags": i.get("tags") or [],
                    "reporter": i.get("reporter", ""),
                }
                for i in iocs[:25]
            ],
            "last_updated": ts(),
            "status": "ok",
        }
    except Exception as e:
        return _err("ThreatFox", e)


def fetch_feodo():
    try:
        r = SESSION.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.json",
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        ips = data if isinstance(data, list) else []
        return {
            "source": "Feodo Tracker",
            "description": "Botnet C2 Infrastructure (Abuse.ch)",
            "count": len(ips),
            "items": [
                {
                    "ip": i.get("ip_address", ""),
                    "port": i.get("port", ""),
                    "status": i.get("status", ""),
                    "malware": i.get("malware", ""),
                    "first_seen": i.get("first_seen", ""),
                    "last_online": i.get("last_online", ""),
                    "country": i.get("country", ""),
                    "as_number": i.get("as_number", ""),
                }
                for i in ips[:25]
            ],
            "last_updated": ts(),
            "status": "ok",
        }
    except Exception as e:
        return _err("Feodo Tracker", e)


def fetch_nvd():
    try:
        r = SESSION.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"resultsPerPage": 20, "startIndex": 0},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        items = []
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            v31 = metrics.get("cvssMetricV31", [])
            v30 = metrics.get("cvssMetricV30", [])
            v2 = metrics.get("cvssMetricV2", [])
            best = v31 or v30 or v2
            cvss_data = best[0].get("cvssData", {}) if best else {}
            items.append({
                "id": cve.get("id", ""),
                "description": desc[:300],
                "published": cve.get("published", ""),
                "modified": cve.get("lastModified", ""),
                "score": cvss_data.get("baseScore", "N/A"),
                "severity": cvss_data.get("baseSeverity", "N/A"),
                "vector": cvss_data.get("attackVector", ""),
            })
        return {
            "source": "NVD CVE",
            "description": "National Vulnerability Database (NIST)",
            "total": data.get("totalResults", 0),
            "items": items,
            "last_updated": ts(),
            "status": "ok",
        }
    except Exception as e:
        return _err("NVD CVE", e)


# ── API-key sources ───────────────────────────────────────────────────────────

def fetch_otx(api_key: str):
    if not api_key:
        return {
            "source": "AlienVault OTX",
            "status": "skipped",
            "reason": "Add OTX_API_KEY to GitHub Secrets to enable",
            "items": [],
            "last_updated": ts(),
        }
    try:
        r = SESSION.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": api_key},
            params={"limit": 15, "page": 1},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        pulses = r.json().get("results", [])
        return {
            "source": "AlienVault OTX",
            "description": "Open Threat Exchange — Threat Pulses",
            "items": [
                {
                    "name": p.get("name", ""),
                    "description": (p.get("description") or "")[:250],
                    "author": p.get("author", {}).get("username", ""),
                    "created": p.get("created", ""),
                    "modified": p.get("modified", ""),
                    "tags": (p.get("tags") or [])[:6],
                    "indicators": p.get("indicators_count", 0),
                    "countries": (p.get("targeted_countries") or [])[:5],
                    "malware": (p.get("malware_families") or [])[:5],
                    "adversary": p.get("adversary", ""),
                    "tlp": p.get("tlp", "white"),
                    "id": p.get("id", ""),
                }
                for p in pulses
            ],
            "last_updated": ts(),
            "status": "ok",
        }
    except Exception as e:
        return _err("AlienVault OTX", e)


def fetch_virustotal(api_key: str):
    if not api_key:
        return {
            "source": "VirusTotal",
            "status": "skipped",
            "reason": "Add VT_API_KEY to GitHub Secrets to enable",
            "items": [],
            "last_updated": ts(),
        }
    try:
        # Fetch recently submitted popular URLs
        r = SESSION.get(
            "https://www.virustotal.com/api/v3/search",
            headers={"x-apikey": api_key},
            params={"query": "type:url engines:5+ date:1d-", "limit": 20},
            timeout=TIMEOUT,
        )
        if r.status_code == 400:
            # Fallback: get recent URL analyses
            r = SESSION.get(
                "https://www.virustotal.com/api/v3/analyses",
                headers={"x-apikey": api_key},
                params={"filter": "type:url"},
                timeout=TIMEOUT,
            )
        r.raise_for_status()
        data = r.json().get("data", [])
        items = []
        for entry in data[:20]:
            attrs = entry.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            items.append({
                "id": entry.get("id", ""),
                "type": entry.get("type", ""),
                "name": attrs.get("meaningful_name") or attrs.get("name") or attrs.get("url") or entry.get("id", ""),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "tags": (attrs.get("tags") or [])[:5],
                "last_analysis": attrs.get("last_analysis_date", ""),
            })
        return {
            "source": "VirusTotal",
            "description": "VirusTotal Threat Intelligence",
            "items": items,
            "last_updated": ts(),
            "status": "ok",
        }
    except Exception as e:
        return _err("VirusTotal", e)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    otx_key = os.environ.get("OTX_API_KEY", "").strip()
    vt_key = os.environ.get("VT_API_KEY", "").strip()

    tasks = [
        ("cisa_kev", fetch_cisa_kev),
        ("urlhaus", fetch_urlhaus),
        ("malwarebazaar", fetch_malwarebazaar),
        ("threatfox", fetch_threatfox),
        ("feodo", fetch_feodo),
        ("nvd", fetch_nvd),
    ]

    output = {"generated_at": ts(), "sources": {}}

    for key, fn in tasks:
        print(f"  Fetching {key}...")
        try:
            output["sources"][key] = fn()
        except Exception:
            traceback.print_exc()
            output["sources"][key] = {"status": "error", "items": [], "last_updated": ts()}

    print("  Fetching otx...")
    output["sources"]["otx"] = fetch_otx(otx_key)

    print("  Fetching virustotal...")
    output["sources"]["virustotal"] = fetch_virustotal(vt_key)

    os.makedirs("data", exist_ok=True)
    with open("data/cti_data.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    print("Done. Written to data/cti_data.json")


if __name__ == "__main__":
    main()
