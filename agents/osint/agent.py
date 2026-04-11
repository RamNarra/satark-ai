import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from google import genai
from google.genai import types
from config import MODEL_PRO_TOOLS, PROJECT_ID, LOCATION
from tools.osint_tools import (
    whois_lookup, reverse_ip_lookup, asn_lookup,
    abuseipdb_check, crtsh_lookup, web_risk_check
)

client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)


def _response_text(resp) -> str:
    try:
        candidates = getattr(resp, "candidates", None)
        if candidates and getattr(candidates[0], "content", None):
            parts = candidates[0].content.parts
            return "".join(
                t
                for t in (getattr(p, "text", None) for p in (parts or []))
                if isinstance(t, str) and t
            )
    except Exception:
        pass
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        t = resp.get("text")
        return t if isinstance(t, str) else ""
    return ""


def _append_candidate_content(history: list, resp) -> None:
    """Append the model's full Content (including thought signature parts)."""

    try:
        candidates = getattr(resp, "candidates", None)
        if candidates and getattr(candidates[0], "content", None):
            history.append(candidates[0].content)
    except Exception:
        pass

def run_full_osint(indicators: dict) -> dict:
    results = {"domains": {}, "ips": {}, "urls": {}, "threat_summary": "", "overall_threat_score": 0}

    for domain in indicators.get("domains", [])[:3]:
        dr = {}
        dr["whois"]    = whois_lookup(domain)
        dr["crt_sh"]   = crtsh_lookup(domain)
        dr["web_risk"] = web_risk_check(domain, PROJECT_ID)
        ip = dr["whois"].get("raw", {}).get("ip", "")
        if ip:
            dr["reverse_ip"] = reverse_ip_lookup(ip)
            dr["asn"]        = asn_lookup(ip)
            dr["abuseipdb"]  = abuseipdb_check(ip)
        results["domains"][domain] = dr

    for ip in indicators.get("ips", [])[:3]:
        results["ips"][ip] = {
            "asn":        asn_lookup(ip),
            "abuseipdb":  abuseipdb_check(ip),
            "reverse_ip": reverse_ip_lookup(ip),
        }

    for url in indicators.get("urls", [])[:5]:
        results["urls"][url] = web_risk_check(url, PROJECT_ID)

    results["threat_summary"]       = synthesize(indicators, results)
    results["overall_threat_score"] = score(results)
    return results

def synthesize(indicators: dict, raw: dict) -> str:
    try:
        use_grounding = str(os.getenv("SATARK_ENABLE_OSINT_GROUNDING", "1") or "1").strip().lower() not in {"0", "false", "no"}
        has_url = False
        try:
            urls = indicators.get("urls") or []
            has_url = any(re.search(r"https?://", str(u or "")) for u in urls)
        except Exception:
            has_url = False

        tools = None
        if use_grounding:
            tool_list = []
            try:
                if hasattr(types, "GoogleSearch"):
                    tool_list.append(types.Tool(google_search=types.GoogleSearch()))
            except Exception:
                pass
            try:
                if has_url and hasattr(types, "UrlContext"):
                    tool_list.append(types.Tool(url_context=types.UrlContext()))
            except Exception:
                pass
            tools = tool_list or None

        prompt = f"""You are a Threat Intelligence analyst at TGCSB.
Write a 3-4 sentence threat intelligence summary for law enforcement.
Focus on: domain age, hosting location, bulletproof hosting, fraud infrastructure.

If URLs are present, use URL Context to fetch and briefly describe what the page does.
Use Google Search grounding to validate any claims about phone numbers/domains (prior reports, scam warnings).

Indicators: {json.dumps(indicators)}
Findings: {json.dumps(raw, default=str)[:3000]}"""

        history = [
            types.Content(
                role="user",
                parts=[types.Part(text=prompt)],
            )
        ]
        resp = client.models.generate_content(
            model=MODEL_PRO_TOOLS,
            contents=history,
            config=types.GenerateContentConfig(
                temperature=0.2,
                thinking_config=types.ThinkingConfig(thinking_level="MINIMAL"),
                tools=tools,
                tool_config=types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="AUTO")) if tools else types.ToolConfig(function_calling_config=types.FunctionCallingConfig(mode="NONE")),
            )
        )
        _append_candidate_content(history, resp)
        return _response_text(resp).strip()
    except Exception as e:
        return f"OSINT analysis complete. Synthesis error: {e}"

def score(results: dict) -> int:
    s = 0
    for d, data in results.get("domains", {}).items():
        if data.get("whois", {}).get("is_new_domain"):        s += 30
        if data.get("asn", {}).get("is_bulletproof_hosting"): s += 25
        if data.get("abuseipdb", {}).get("is_malicious"):     s += 20
        if data.get("web_risk", {}).get("is_malicious"):      s += 25
    for _, data in results.get("ips", {}).items():
        if data.get("abuseipdb", {}).get("is_malicious"):      s += 20
        if data.get("asn", {}).get("is_bulletproof_hosting"):  s += 15
    for _, data in results.get("urls", {}).items():
        if data.get("is_malicious"):                           s += 25
    return min(s, 100)

def run(input_data: dict) -> dict:
    entities = input_data.get("extracted_entities", {})
    indicators = {
        "domains": [u.replace("https://","").replace("http://","").split("/")[0]
                    for u in entities.get("urls", []) if u],
        "ips": [],
        "phone_numbers": entities.get("phone_numbers", []),
        "urls": entities.get("urls", []),
    }
    if not any(indicators.values()):
        return {"threat_summary": "No indicators found.", "overall_threat_score": 0}
    return run_full_osint(indicators)