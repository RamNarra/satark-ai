from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from config import GEMINI_PRO_MODEL
from tools.osint_tools import (
    check_whois,
    check_reverse_ip,
    check_asn,
    check_abuseipdb,
    check_crtsh,
    check_google_web_risk,
)
from db.operations import get_osint_cache, save_osint_cache, save_threat_intel


def cached_whois(domain: str) -> dict:
    cached = get_osint_cache(f"whois:{domain}")
    if cached:
        return cached["result"]
    result = check_whois(domain)
    save_osint_cache(f"whois:{domain}", result)
    return result


def cached_reverse_ip(ip: str) -> dict:
    cached = get_osint_cache(f"revip:{ip}")
    if cached:
        return cached["result"]
    result = check_reverse_ip(ip)
    save_osint_cache(f"revip:{ip}", result)
    return result


def cached_abuseipdb(ip: str) -> dict:
    cached = get_osint_cache(f"abuse:{ip}")
    if cached:
        return cached["result"]
    result = check_abuseipdb(ip)
    save_osint_cache(f"abuse:{ip}", result)
    return result


def store_ioc(indicator: str, indicator_type: str, summary: str) -> dict:
    save_threat_intel(indicator, indicator_type, {"summary": summary})
    return {"stored": True}


osint_agent = Agent(
    name="osint_agent",
    model=GEMINI_PRO_MODEL,
    description="Performs OSINT investigation on suspicious URLs, IPs, domains, and phone numbers",
    instruction="""
You are a cyber threat intelligence investigator. Given suspicious URLs,
domains, IPs, or phone numbers, perform OSINT investigation.

Steps:
1. Run WHOIS on domains (age < 30 days = red flag)
2. Reverse IP lookup to find co-hosted fraud domains
3. Check ASN (bulletproof hosting = red flag)
4. AbuseIPDB reputation check
5. Certificate transparency (crt.sh) for hidden subdomains
6. Google Web Risk verdict
7. Store confirmed IOCs using store_ioc

Return strict JSON:
{
  "indicators_investigated": [],
  "domain_age_days": null,
  "registrar": "",
  "hosting_country": "",
  "asn_org": "",
  "co_hosted_domains": [],
  "abuse_reports": 0,
  "web_risk_verdict": "SAFE|PHISHING|MALWARE|UNWANTED_SOFTWARE",
  "hidden_subdomains": [],
  "threat_score": 0-100,
  "osint_summary": "2-3 sentence intelligence summary",
  "red_flags": []
}
""",
    tools=[
        FunctionTool(func=cached_whois),
        FunctionTool(func=cached_reverse_ip),
        FunctionTool(func=check_asn),
        FunctionTool(func=cached_abuseipdb),
        FunctionTool(func=check_crtsh),
        FunctionTool(func=check_google_web_risk),
        FunctionTool(func=store_ioc),
    ],
)
