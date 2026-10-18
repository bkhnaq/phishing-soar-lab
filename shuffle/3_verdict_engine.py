import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings()

THEHIVE_URL = ""
API_KEY = ""
RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK = {"com": "https://rdap.verisign.com/com/v1/", "net": "https://rdap.verisign.com/net/v1/",
                 "org": "https://rdap.publicinterestregistry.org/rdap/"}
UA = {"User-Agent": "phishing-soc-lab/1.0", "Accept": "application/rdap+json"}
MAX_RDAP_LOOKUPS = 6
HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}


MALICIOUS_AT = 70
SUSPICIOUS_AT = 40


BRANDS = {
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com", "meta.com"],
}
MULTI_PART_SUFFIXES = {"co.uk", "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn",
                       "com.au", "co.jp", "com.sg", "com.br", "co.in"}




def api(method, path, **kwargs):
    resp = requests.request(method, f"{THEHIVE_URL}{path}", headers=HEADERS,
                            timeout=10, verify=False, **kwargs)
    if resp.status_code >= 400:
        raise RuntimeError(f"{method} {path} -> {resp.status_code}: {resp.text[:300]}")
    return resp.json() if resp.text else {}


def load_bot_event():
    wazuh = json.loads(r'''$exec''')
    text = wazuh.get("text")
    return text if isinstance(text, dict) else json.loads(text)


def registered_domain(host):
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def host_of(data_type, value):
    if data_type == "url":
        return (urlparse(value).hostname or "").lower()
    if data_type == "mail":
        return value.split("@")[-1].lower()
    if data_type == "domain":
        return value.lower()
    return ""


def is_ip(value):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value or ""))


def is_official(domain, brand):
    return any(domain == d or domain.endswith("." + d) for d in BRANDS[brand])




def load_rdap_servers():
    """Danh sách RDAP server chính thức theo TLD từ IANA."""
    servers = dict(RDAP_FALLBACK)
    try:
        data = requests.get(RDAP_BOOTSTRAP, timeout=6, headers=UA).json()
        for tlds, urls in data.get("services", []):
            https = [u for u in urls if u.startswith("https")] or urls
            for tld in tlds:
                servers[tld.lower()] = https[0] if https[0].endswith("/") else https[0] + "/"
    except Exception:
        pass
    return servers


def rdap_lookup(args):
    domain, servers = args
    base = servers.get(domain.rsplit(".", 1)[-1])
    if not base:
        return domain, {"status": "unknown", "reason": "TLD không có RDAP"}
    try:
        r = requests.get(f"{base}domain/{domain}", timeout=6, headers=UA)
    except requests.RequestException as e:
        return domain, {"status": "error", "error": type(e).__name__}
    if r.status_code == 404:
        return domain, {"status": "not_registered"}
    if r.status_code != 200:
        return domain, {"status": "unknown", "http": r.status_code}
    try:
        data = r.json()
    except ValueError:
        return domain, {"status": "unknown"}
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - created).days
            return domain, {"status": "registered", "created": created.date().isoformat(), "age_days": age}
    return domain, {"status": "registered", "age_days": None}




def parse_reports(obs):
    """Rút các chỉ số từ taxonomies mà TheHive lưu trên observable."""
    result = {"vt_hits": None, "vt_total": None, "abuseipdb_score": None,
              "abuseipdb_whitelisted": False, "urlscan_malicious": False,
              "other_malicious": [], "analyzers": []}
    for analyzer, report in (obs.get("reports") or {}).items():
        result["analyzers"].append(analyzer)
        for t in report.get("taxonomies", []):
            ns, pred = str(t.get("namespace", "")), str(t.get("predicate", ""))
            value, level = str(t.get("value", "")), str(t.get("level", "")).lower()
            m = re.fullmatch(r"\s*(\d+)\s*/\s*(\d+)\s*", value)
            if ns.upper() == "VT" and m:
                result["vt_hits"], result["vt_total"] = int(m.group(1)), int(m.group(2))
            elif ns.lower() == "abuseipdb" and pred.lower() == "score":
                try:
                    result["abuseipdb_score"] = int(float(value))
                except ValueError:
                    pass
            elif ns.lower() == "abuseipdb" and pred.lower() == "whitelisted":
                result["abuseipdb_whitelisted"] = value.lower() == "true"
            elif "urlscan" in ns.lower() and level == "malicious":
                result["urlscan_malicious"] = True
            elif level == "malicious" and "resolution" not in value.lower() \
                    and ns.lower() not in ("abuseipdb", "vt"):
                result["other_malicious"].append(f"{ns}:{pred}={value}")
    return result




class Score:
    def __init__(self):
        self.points, self.reasons = 0, []

    def add(self, pts, reason):
        self.points += pts
        self.reasons.append(f"{'+' if pts >= 0 else ''}{pts} {reason}")


def score_bot_signals(bot, s):
    header = bot.get("header_analysis", {})
    mismatches = set(header.get("mismatches", []))
    for key, pts, text in (("reply_to_mismatch", 10, "Reply-To khác domain người gửi"),
                           ("return_path_mismatch", 5, "Return-Path khác domain người gửi"),
                           ("message_id_mismatch", 5, "Message-ID khác domain người gửi")):
        if key in mismatches:
            s.add(pts, text)

    auth = {k: str(v).upper() for k, v in bot.get("authentication", {}).items()}
    for key, pts in (("spf", 10), ("dkim", 10), ("dmarc", 15)):
        if auth.get(key) in ("FAIL", "SOFTFAIL", "PERMERROR"):
            s.add(pts, f"{key.upper()} {auth[key]}")

    content = bot.get("content_analysis", {})
    if content.get("credential_request"):
        s.add(15, "Nội dung yêu cầu đăng nhập / cung cấp thông tin")
    if content.get("urgency"):
        s.add(5, "Ngôn ngữ thúc ép khẩn cấp")
    if content.get("authority_impersonation"):
        s.add(10, "Mạo danh cơ quan / người có thẩm quyền")
    if bot.get("url_analysis", {}).get("deceptive_link"):
        s.add(15, "Link hiển thị khác link thật")

    ai = bot.get("ai", {})
    if str(ai.get("prediction", "")).lower() == "phishing" and float(ai.get("confidence") or 0) >= 0.9:
        s.add(10, f"Mô hình AI dự đoán phishing ({float(ai['confidence']):.2f})")


    sender = str(bot.get("email", {}).get("from", ""))
    display = sender.split("<")[0].lower()
    from_domain = str(header.get("from_domain", "")).lower()
    for brand in BRANDS:
        if brand in display and from_domain and not is_official(from_domain, brand):
            s.add(20, f"Tên người gửi mạo danh {brand.title()} nhưng domain là {from_domain}")
            return {registered_domain(from_domain)}
    return set()


def score_observables(observables, s, already_counted=()):
    lookalike_seen, details = set(already_counted), []
    for obs in observables:
        if "benign-reference" in (obs.get("tags") or []):
            continue
        data_type, value = obs.get("dataType"), obs.get("data", "")
        r = parse_reports(obs)
        details.append({"data": value, "type": data_type, **{k: v for k, v in r.items() if v is not None and v != [] and v is not False}})

        if r["vt_hits"] is not None:
            if r["vt_hits"] >= 3:
                s.add(30, f"VirusTotal: {r['vt_hits']}/{r['vt_total']} engine gắn cờ {value}")
            elif r["vt_hits"] >= 1:
                s.add(15, f"VirusTotal: {r['vt_hits']}/{r['vt_total']} engine gắn cờ {value}")
        if r["abuseipdb_score"] is not None:
            if r["abuseipdb_score"] >= 75:
                s.add(20, f"AbuseIPDB score {r['abuseipdb_score']} cho {value}")
            elif r["abuseipdb_score"] >= 25:
                s.add(10, f"AbuseIPDB score {r['abuseipdb_score']} cho {value}")
        if r["abuseipdb_whitelisted"]:
            s.add(-10, f"AbuseIPDB whitelist {value}")
        if r["urlscan_malicious"]:
            s.add(20, f"urlscan.io đánh giá độc hại {value}")
        for item in r["other_malicious"][:2]:
            s.add(10, f"Analyzer gắn malicious: {item}")

        if data_type == "url" and is_ip(urlparse(value).hostname or ""):
            s.add(10, f"URL dùng IP trực tiếp: {value}")

        host = host_of(data_type, value)
        reg = registered_domain(host) if host and not is_ip(host) else ""
        for brand in BRANDS:
            if reg and brand in reg and not is_official(reg, brand) and reg not in lookalike_seen:
                lookalike_seen.add(reg)
                s.add(15, f"Domain giả dạng {brand.title()}: {reg}")
    return details


def score_rdap(rdap, s):
    missing = 0
    for domain, info in rdap.items():
        if info["status"] == "not_registered":
            missing += 1

            s.add(20 if missing == 1 else 5, f"Domain {domain} không tồn tại (RDAP)")
        elif info.get("age_days") is not None:
            age = info["age_days"]
            if age < 30:
                s.add(25, f"Domain {domain} mới đăng ký {age} ngày")
            elif age < 180:
                s.add(10, f"Domain {domain} đăng ký {age} ngày")
            elif age > 5 * 365:
                s.add(-5, f"Domain {domain} đã hoạt động {age // 365} năm")




ANALYZABLE_TYPES = {"url", "ip", "domain", "hash"}
RISKY_EXT = (".exe", ".scr", ".js", ".jse", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".lnk",
             ".iso", ".img", ".docm", ".xlsm", ".pptm", ".html", ".htm", ".svg")
FINANCE_WORDS = ("invoice", "payment", "wire", "transfer", "bank", "remittance", "payroll",
                 "hóa đơn", "thanh toán", "chuyển khoản", "ngân hàng", "tài khoản nhận", "lương")


def classify_category(bot, observables, details, s):
    obs_all = bot.get("observables", {})
    subject = str(bot.get("email", {}).get("subject", "")).lower()
    has_urls = bool(obs_all.get("urls"))
    files = [f.lower() for f in obs_all.get("filenames", [])]
    has_files = bool(files or obs_all.get("hashes"))
    mismatches = set(bot.get("header_analysis", {}).get("mismatches", []))
    content = bot.get("content_analysis", {})

    bad_hash = any(d.get("type") == "hash" and (d.get("vt_hits") or 0) >= 1 for d in details)
    risky_file = [f for f in files if f.endswith(RISKY_EXT)]
    if bad_hash or risky_file:
        if risky_file:
            s.add(20, f"File đính kèm có định dạng nguy hiểm: {', '.join(risky_file[:3])}")
        return "malware"

    playbook = bot.get("suggested_playbook")
    lang_categories = [str(c).lower() for c in (bot.get("language_categories") or [])]


    if playbook == "payment_fraud":
        return "bec"

    if playbook == "credential_phishing" or (content.get("credential_request") and has_urls):
        return "credential_phishing"

    finance = [w for w in FINANCE_WORDS if w in subject]
    if "financial" in lang_categories and "nội dung (bot)" not in finance:
        finance.append("nội dung (bot)")
    if not has_urls and not has_files and (finance or "reply_to_mismatch" in mismatches):
        if finance:
            s.add(15, f"Tiêu đề có nội dung tài chính: {', '.join(finance[:3])}")
        return "bec"

    return "spam_or_legit"




def find_alert(event_id):
    query = {"query": [{"_name": "listAlert"},
                       {"_name": "filter", "_eq": {"_field": "sourceRef", "_value": event_id}}]}
    found = api("POST", "/api/v1/query", json=query)
    return found[0] if found else None


def main():
    if THEHIVE_URL.startswith("$") or API_KEY.startswith("$"):
        return {"success": False, "error": "Chưa khai báo workflow variable thehive_url / thehive_api_key"}

    bot = load_bot_event()
    alert = find_alert(bot.get("event_id"))
    if not alert:
        return {"success": False, "error": f"Không tìm thấy alert sourceRef={bot.get('event_id')}"}
    alert_id = alert["_id"]

    observables = api("POST", "/api/v1/query", json={"query": [
        {"_name": "getAlert", "idOrName": alert_id}, {"_name": "observables"}]})

    s = Score()
    counted = score_bot_signals(bot, s)
    details = score_observables(observables, s, counted)


    header = bot.get("header_analysis", {})
    candidates = [header.get("from_domain"), header.get("reply_to_domain"), header.get("return_path_domain")]
    for obs in observables:
        if "benign-reference" not in (obs.get("tags") or []) and obs.get("dataType") in ("url", "domain"):
            candidates.append(host_of(obs["dataType"], obs.get("data", "")))
    domains = []
    for h in candidates:
        reg = registered_domain(h) if h and not is_ip(h) else ""
        if reg and reg not in domains and not any(is_official(reg, b) for b in BRANDS):
            domains.append(reg)
    domains = domains[:MAX_RDAP_LOOKUPS]
    servers = load_rdap_servers() if domains else {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        rdap = dict(pool.map(rdap_lookup, [(d, servers) for d in domains]))
    score_rdap(rdap, s)

    category = classify_category(bot, observables, details, s)

    score = max(0, min(100, s.points))
    verdict = "MALICIOUS" if score >= MALICIOUS_AT else "SUSPICIOUS" if score >= SUSPICIOUS_AT else "CLEAN"


    strong = [d["data"] for d in details if (d.get("vt_hits") or 0) >= 5 or d.get("urlscan_malicious")]
    if strong and verdict != "MALICIOUS":
        verdict = "MALICIOUS"
        s.reasons.append(f"Bằng chứng mạnh từ threat intel: {', '.join(strong[:3])}")


    analyzable = [o for o in observables if o.get("dataType") in ANALYZABLE_TYPES
                  and "benign-reference" not in (o.get("tags") or [])]
    analyzed = sum(1 for o in analyzable if o.get("reports"))
    coverage_note = f"{analyzed}/{len(analyzable)} observable cần phân tích đã có kết quả analyzer"
    bot_coverage = int((bot.get("evidence_coverage") or {}).get("percentage") or 0)


    if verdict == "CLEAN" and (bot_coverage < 50 or (analyzable and analyzed / len(analyzable) < 0.5)):
        verdict = "INCONCLUSIVE"
        s.reasons.append("Không đủ bằng chứng để kết luận an toàn")

    if category == "bec" and verdict in ("CLEAN", "INCONCLUSIVE"):
        verdict = "SUSPICIOUS"
        s.reasons.append("Nghi BEC: không tự động đóng, cần analyst xác nhận")


    severity = {"MALICIOUS": 3, "SUSPICIOUS": 2, "INCONCLUSIVE": 2, "CLEAN": 1}[verdict]
    tags = [t for t in (alert.get("tags") or []) if not t.startswith(("final-verdict:", "score:", "category:"))]
    tags += [f"final-verdict:{verdict.lower()}", f"score:{score}", f"category:{category}"]
    rdap_lines = [f"- `{d}`: {i['status']}" + (f", tạo {i.get('created')} ({i['age_days']} ngày)"
                  if i.get("age_days") is not None else "") for d, i in rdap.items()]
    section = "\n".join([
        "", "---", f"## Kết luận tự động: **{verdict}** ({score}/100)", f"**Loại email:** `{category}`",
        f"_{coverage_note}. Ngưỡng: ≥{MALICIOUS_AT} MALICIOUS, ≥{SUSPICIOUS_AT} SUSPICIOUS._", "",
        "### Lý do", *[f"- {r}" for r in s.reasons], "",
        "### Tuổi domain (RDAP)", *(rdap_lines or ["- Không có domain cần tra"]),
    ])
    description = (alert.get("description") or "").split("\n---\n## Kết luận tự động")[0] + section
    api("PATCH", f"/api/v1/alert/{alert_id}",
        json={"severity": severity, "tags": tags, "description": description})

    return {
        "success": True,
        "alert_id": alert_id,
        "verdict": verdict,
        "category": category,
        "score": score,
        "raw_points": s.points,
        "reasons": s.reasons,
        "coverage": coverage_note,
        "rdap": rdap,
        "observables": details,
    }


try:
    print(json.dumps(main(), ensure_ascii=False))
except Exception as e:
    print(json.dumps({"success": False, "error": f"{type(e).__name__}: {e}"}, ensure_ascii=False))
