from google.adk.agents import Agent
from google.adk.tools import FunctionTool
from google.genai import types
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
    generate_content_config=types.GenerateContentConfig(
        thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
    ),
    instruction="""
You are a cyber threat intelligence investigator. Given suspicious indicators
(URLs/domains/IPs/phone numbers), perform OSINT investigation with the tools.

    Gemini capabilities available for this agent (use them when relevant):
    - If any indicator contains a URL, use the URL Context tool to fetch/read the page contents and summarize what the page is doing (brand impersonation, login/OTP capture, payment collection, outbound endpoints).
    - Use Google Search grounding to validate claims about phone numbers/domains (e.g., prior reports, scam warnings). Prefer grounded findings over speculation.
        - To make grounding auditable, add 1-3 short entries in `red_flags` like:
            - "URL_CONTEXT: <url> — <what the page does>"
            - "SEARCH: <indicator> — <top result domain / warning>"

Do:
- WHOIS on domains (age < 30 days = red flag)
- Certificate transparency (crt.sh) to find related subdomains
- Reverse IP lookup to find co-hosted domains (if you have an IP)
- ASN/org check for hosting risk signals
- AbuseIPDB for IP reputation
- Google Web Risk verdicts for URLs

When you have high-confidence malicious indicators, store them using store_ioc.

Return STRICT JSON only (no prose, no markdown). This is a multi-indicator report:
{
    "indicators_investigated": ["..."],
    "domains": {
        "example.com": {
            "domain_age_days": 0,
            "registrar": "",
            "hosting_country": "",
            "ssl": {"present": false, "issuer": "", "valid_to": ""},
            "hidden_subdomains": [""],
            "notes": ""
        }
    },
    "ips": {
        "1.2.3.4": {
            "reputation": "GOOD|UNKNOWN|SUSPICIOUS|MALICIOUS",
            "asn_org": "",
            "abuse_reports": 0,
            "co_hosted_domains": [""],
            "notes": ""
        }
    },
    "urls": {
        "https://example.com/path": {
            "verdict": "SAFE|SUSPICIOUS|MALICIOUS",
            "web_risk_verdict": "SAFE|PHISHING|MALWARE|UNWANTED_SOFTWARE|UNKNOWN",
            "red_flags": [""],
            "notes": ""
        }
    },
    "threat_summary": "One paragraph summary grounded in findings",
    "overall_threat_score": 0,
    "red_flags": ["..."],
    "recommendations": ["..."],
    "sources": ["whois", "crtsh", "web_risk", "reverse_ip", "asn", "abuse_reports"]
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
