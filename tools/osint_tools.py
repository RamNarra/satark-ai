import requests
import os
from datetime import datetime

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

def whois_lookup(domain: str) -> dict:
    try:
        clean = domain.replace("https://","").replace("http://","").split("/")[0]
        r = requests.get(f"https://api.whois.vu/?q={clean}", timeout=8)
        data = r.json() if r.status_code == 200 else {}
        created = data.get("creation_date", "unknown")
        age_days = None
        if created and created != "unknown":
            try:
                age_days = (datetime.now() - datetime.strptime(created[:10], "%Y-%m-%d")).days
            except Exception:
                pass
        return {
            "domain": clean,
            "registrar": data.get("registrar", "unknown"),
            "created": created,
            "age_days": age_days,
            "country": data.get("registrant_country", "unknown"),
            "is_new_domain": age_days is not None and age_days < 30,
        }
    except Exception as e:
        return {"domain": domain, "error": str(e), "is_new_domain": None}

def reverse_ip_lookup(ip_or_domain: str) -> dict:
    try:
        r = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip_or_domain}",
            timeout=10
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            domains = [d.strip() for d in r.text.strip().split("\n") if d.strip()]
            return {"ip": ip_or_domain, "hosted_domains": domains,
                    "domain_count": len(domains), "suspicious": len(domains) > 10}
        return {"ip": ip_or_domain, "hosted_domains": [], "domain_count": 0}
    except Exception as e:
        return {"ip": ip_or_domain, "error": str(e)}

def asn_lookup(ip: str) -> dict:
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=8)
        data = r.json() if r.status_code == 200 else {}
        org = data.get("org", "")
        bp = ["frantech","moldtelecom","combahton","serverius",
              "psychz","hostkey","ddos-guard","blazingfast","selectel","M247"]
        return {
            "ip": ip,
            "org": org,
            "country": data.get("country", "unknown"),
            "city": data.get("city", "unknown"),
            "asn": data.get("asn", "unknown"),
            "is_bulletproof_hosting": any(k.lower() in org.lower() for k in bp),
            "hostname": data.get("hostname", ""),
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def abuseipdb_check(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"ip": ip, "abuse_score": 0, "total_reports": 0, "note": "no_api_key"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8,
        )
        data = r.json().get("data", {}) if r.status_code == 200 else {}
        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", "never"),
            "is_malicious": data.get("abuseConfidenceScore", 0) > 50,
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def crtsh_lookup(domain: str) -> dict:
    try:
        clean = domain.replace("https://","").replace("http://","").split("/")[0]
        r = requests.get(f"https://crt.sh/?q=%.{clean}&output=json", timeout=10)
        if r.status_code == 200:
            certs = r.json()
            subdomains = list(set([
                c.get("name_value","").replace("*.","")
                for c in certs if c.get("name_value")
            ]))
            admin_panels = [s for s in subdomains if any(
                k in s for k in ["admin","cpanel","login","portal","manage","panel"]
            )]
            return {
                "domain": clean,
                "subdomain_count": len(subdomains),
                "subdomains": subdomains[:20],
                "admin_panels_found": admin_panels,
                "has_admin_panel": len(admin_panels) > 0,
            }
        return {"domain": domain, "subdomains": []}
    except Exception as e:
        return {"domain": domain, "error": str(e)}

def web_risk_check(url: str, project_id: str) -> dict:
    try:
        from google.cloud import webrisk_v1
        wrc = webrisk_v1.WebRiskServiceClient()
        threat_types = [
            webrisk_v1.ThreatType.MALWARE,
            webrisk_v1.ThreatType.SOCIAL_ENGINEERING,
            webrisk_v1.ThreatType.UNWANTED_SOFTWARE,
        ]
        response = wrc.search_uris(uri=url, threat_types=threat_types)
        threats = [str(t) for t in response.threat.threat_types] if response.threat else []
        return {"url": url, "threats_found": threats,
                "is_malicious": len(threats) > 0, "source": "Google Web Risk API"}
    except Exception as e:
        return {"url": url, "threats_found": [], "is_malicious": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Compatibility wrappers (used by ADK-based OSINT agent)

def check_whois(domain: str) -> dict:
    return whois_lookup(domain)


def check_reverse_ip(ip_or_domain: str) -> dict:
    return reverse_ip_lookup(ip_or_domain)


def check_asn(ip: str) -> dict:
    return asn_lookup(ip)


def check_abuseipdb(ip: str) -> dict:
    return abuseipdb_check(ip)


def check_crtsh(domain: str) -> dict:
    return crtsh_lookup(domain)


def check_google_web_risk(url: str, project_id: str = "") -> dict:
    # project_id is unused by the underlying client (ADC determines project),
    # but we keep the signature to match earlier prototypes.
    return web_risk_check(url, project_id)