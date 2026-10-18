import json
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings()


THEHIVE_URL = ""
API_KEY = ""


LEGIT_DOMAINS = {
    "microsoft.com", "live.com", "office.com", "google.com", "apple.com",
    "facebook.com", "paypal.com", "amazon.com",
}
SEVERITY = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
TYPE_MAP = {"domain": "domain", "url": "url", "ip": "ip", "email": "mail",
            "hash": "hash", "filename": "filename"}


def load_event():
    """Wazuh gửi {"text": full_log, "all_fields": alert, ...}. Lấy lại JSON gốc của bot."""
    wazuh = json.loads(r'''$exec''')
    text = wazuh.get("text")
    if isinstance(text, dict):
        return wazuh, text
    for candidate in (text, wazuh.get("all_fields", {}).get("full_log")):
        if isinstance(candidate, str):
            try:
                return wazuh, json.loads(candidate)
            except ValueError:
                pass
    raise ValueError("Không tìm thấy JSON của phishing bot trong dữ liệu Wazuh")


def host_of(obs_type, value):
    if obs_type == "url":
        return (urlparse(value).hostname or "").lower()
    if obs_type == "email":
        return value.split("@")[-1].lower()
    return value.lower()


def is_legit(host):
    return any(host == d or host.endswith("." + d) for d in LEGIT_DOMAINS)


def build_observables(bot, verdict):
    items = list((bot.get("observable_metadata") or {}).values())
    if not items:
        for key, obs_type in (("domains", "domain"), ("urls", "url"), ("ips", "ip"),
                              ("emails", "email"), ("hashes", "hash")):
            for v in bot.get("observables", {}).get(key, []):
                items.append({"type": obs_type, "value": v, "source": key, "environment": "PRODUCTION"})

    result, seen = [], set()
    for obs in items:
        data_type = TYPE_MAP.get(obs.get("type"))
        value = (obs.get("value") or "").strip()
        if not data_type or not value or (data_type, value) in seen:
            continue
        if obs.get("environment") == "TEST":
            continue
        seen.add((data_type, value))
        legit = data_type != "hash" and is_legit(host_of(obs.get("type"), value))
        result.append({
            "dataType": data_type,
            "data": value,
            "message": f"Nguồn: {obs.get('source', 'phishing-bot')}",
            "ioc": (not legit) and verdict == "PHISHING",
            "tags": ["benign-reference"] if legit else ["phishing-bot", verdict.lower()],
            "tlp": 2,
            "pap": 2,
        })
    return result


def build_description(bot, wazuh):
    email = bot.get("email", {})
    risk = bot.get("risk", {})
    auth = bot.get("authentication", {})
    header = bot.get("header_analysis", {})
    content = bot.get("content_analysis", {})
    ai = bot.get("ai", {})
    coverage = bot.get("evidence_coverage", {})
    flags = [k for k, v in content.items() if v is True]
    return "\n".join([
        "## Kết quả đánh giá sơ bộ của phishing bot",
        f"- **Verdict:** {risk.get('initial_verdict')} (score {risk.get('base_score')}, severity {risk.get('initial_severity')})",
        f"- **Evidence coverage:** {coverage.get('percentage', 'N/A')}%",
        f"- **AI:** {ai.get('prediction')} (confidence {round(float(ai.get('confidence') or 0), 3)})",
        f"- **Playbook đề xuất:** {bot.get('suggested_playbook')}",
        "",
        "## Email",
        f"- **From:** `{email.get('from')}`",
        f"- **Reply-To:** `{email.get('reply_to')}`",
        f"- **Return-Path:** `{email.get('return_path')}`",
        f"- **To:** `{email.get('to')}`",
        f"- **Subject:** {email.get('subject')}",
        f"- **Date:** {email.get('date')}",
        "",
        "## Dấu hiệu",
        f"- **SPF / DKIM / DMARC:** {auth.get('spf')} / {auth.get('dkim')} / {auth.get('dmarc')}",
        f"- **Header mismatches:** {', '.join(header.get('mismatches', [])) or 'không có'}",
        f"- **Nội dung:** {', '.join(flags) or 'không có'}",
        "",
        f"_Wazuh rule {wazuh.get('rule_id')} | agent {wazuh.get('all_fields', {}).get('agent', {}).get('name')} | event_id {bot.get('event_id')}_",
    ])


def main():
    if THEHIVE_URL.startswith("$") or API_KEY.startswith("$"):
        return {"success": False, "error": "Chưa khai báo workflow variable thehive_url / thehive_api_key"}

    wazuh, bot = load_event()
    risk = bot.get("risk", {})
    verdict = (risk.get("initial_verdict") or "UNKNOWN").upper()
    subject = bot.get("email", {}).get("subject") or "(no subject)"

    payload = {
        "type": "phishing-report",
        "source": "phishing-bot",
        "sourceRef": bot.get("event_id") or wazuh.get("id"),
        "title": f"[{verdict}] {subject}"[:250],
        "description": build_description(bot, wazuh),
        "severity": SEVERITY.get((risk.get("initial_severity") or "").upper(), 2),
        "tlp": 2,
        "pap": 2,
        "tags": ["phishing", "wazuh", "T1566", f"verdict:{verdict.lower()}",
                 f"playbook:{bot.get('suggested_playbook')}"],
        "observables": build_observables(bot, verdict),
    }

    resp = requests.post(
        f"{THEHIVE_URL}/api/v1/alert",
        headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
        json=payload, timeout=30, verify=False,
    )
    body = resp.text[:500]
    if resp.status_code in (200, 201):
        alert = resp.json()
        return {"success": True, "alert_id": alert.get("_id"), "sourceRef": payload["sourceRef"],
                "verdict": verdict, "observables": len(payload["observables"])}
    if resp.status_code == 400 and "exist" in body.lower():
        return {"success": True, "duplicate": True, "sourceRef": payload["sourceRef"]}
    return {"success": False, "status": resp.status_code, "error": body}


print(json.dumps(main(), ensure_ascii=False))
