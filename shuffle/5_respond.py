import json
import requests
import urllib3

urllib3.disable_warnings()

THEHIVE_URL = ""
API_KEY = ""

NOTIFY_REPORTER = False
TELEGRAM_TOKEN = "" if NOTIFY_REPORTER else ""
TELEGRAM_API = "https://api.telegram.org"

CLEAN_STATUS = "FalsePositive"

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

ADVICE = {
    "credential_phishing":
        "Không bấm vào link và không nhập mật khẩu. "
        "Nếu bạn đã nhập thông tin đăng nhập, hãy đổi mật khẩu ngay "
        "và báo cho đội SOC.",

    "malware":
        "Không mở tệp đính kèm. Nếu bạn đã mở, "
        "hãy ngắt mạng máy tính và báo ngay cho đội SOC.",

    "bec":
        "Không chuyển tiền, không cung cấp thông tin tài khoản "
        "và không trả lời email. Hãy xác minh với người gửi "
        "qua điện thoại hoặc kênh liên lạc chính thức.",

    "spam_or_legit":
        "Không bấm vào link trong email.",
}

CATEGORY_NAME = {
    "credential_phishing": "lừa đảo đánh cắp mật khẩu",
    "malware": "phát tán mã độc",
    "bec": "lừa đảo tài chính / giả mạo",
    "spam_or_legit": "email thông thường",
}






def api(method, path, **kwargs):
    resp = requests.request(
        method,
        f"{THEHIVE_URL}{path}",
        headers=HEADERS,
        timeout=10,
        verify=False,
        **kwargs
    )

    if resp.status_code >= 400:
        raise RuntimeError(
            f"{method} {path} -> "
            f"{resp.status_code}: {resp.text[:300]}"
        )

    return resp.json() if resp.text else {}






def load_bot_event():
    wazuh = json.loads(r'''$exec''')

    text = wazuh.get("text")

    return text if isinstance(text, dict) else json.loads(text)






def load_scoping():


    raw_scope = r'''$ioc_scoping'''

    try:
        data = json.loads(raw_scope)
    except Exception:
        return {
            "performed": False,
            "error": "Không parse được output IOC Scoping"
        }

    current = data









    for _ in range(10):

        if not isinstance(current, dict):
            break

        if isinstance(current.get("scoping"), dict):
            return current["scoping"]

        message = current.get("message")

        if isinstance(message, dict):
            current = message
            continue

        break

    return {
        "performed": False,
        "error": "Không tìm thấy trường scoping trong output"
    }






def tag_value(tags, prefix):
    for t in tags:
        if t.startswith(prefix):
            return t[len(prefix):]

    return None


def add_tag(tags, tag):
    if tag and tag not in tags:
        tags.append(tag)






def build_scope_description(scoping):

    performed = scoping.get("performed", False)

    if not performed:
        return (
            "## IOC Scoping\n\n"
            "**Status:** FAILED\n\n"
            f"Error: {scoping.get('error', 'unknown error')}"
        )

    observed = scoping.get("observed", False)
    dns_hits = scoping.get("dns_hits", 0)
    unique_hosts = scoping.get("unique_hosts", 0)
    window = scoping.get("window", "unknown")

    hosts = scoping.get("affected_hosts") or []
    domain_results = scoping.get("domain_results") or {}

    lines = [
        "## IOC Scoping",
        "",
        f"**IOC observed:** {'YES' if observed else 'NO'}",
        f"**Search window:** {window}",
        f"**DNS hits:** {dns_hits}",
        f"**Affected endpoints:** {unique_hosts}",
    ]

    if hosts:
        lines += [
            "",
            "### Affected hosts"
        ]

        for host in hosts:

            name = host.get("agent_name") or "unknown"
            ip = host.get("agent_ip") or "unknown"
            agent_id = host.get("agent_id") or "unknown"

            lines += [
                "",
                f"- **Host:** {name}",
                f"  - IP: {ip}",
                f"  - Agent ID: {agent_id}",
                f"  - DNS hits: {host.get('dns_hits', 0)}",
                f"  - First seen: {host.get('first_seen')}",
                f"  - Last seen: {host.get('last_seen')}",
            ]

            domains = host.get("domains") or []

            if domains:
                lines.append(
                    "  - IOC domains: " + ", ".join(domains)
                )

    observed_domains = []

    for domain, result in domain_results.items():

        if result.get("dns_hits", 0) > 0:
            observed_domains.append({
                "domain": domain,
                "dns_hits": result.get("dns_hits", 0),
                "unique_hosts": result.get("unique_hosts", 0),
                "first_seen": result.get("first_seen"),
                "last_seen": result.get("last_seen"),
            })

    if observed_domains:

        lines += [
            "",
            "### Observed IOC domains"
        ]

        for item in observed_domains:
            lines += [
                "",
                f"- **{item['domain']}**",
                f"  - DNS hits: {item['dns_hits']}",
                f"  - Unique hosts: {item['unique_hosts']}",
                f"  - First seen: {item['first_seen']}",
                f"  - Last seen: {item['last_seen']}",
            ]

    return "\n".join(lines)







SCOPE_MARKER = "\n\n## IOC Scoping"


def merge_scope_description(old_description, scope_text):
    old_description = old_description or ""


    legacy_marker = "Scoping (Wazuh):"


    current_marker = "## IOC Scoping"

    positions = []

    p1 = old_description.find(legacy_marker)
    if p1 != -1:
        positions.append(p1)

    p2 = old_description.find(current_marker)
    if p2 != -1:
        positions.append(p2)


    if positions:
        old_description = old_description[:min(positions)]

    return (
        old_description.rstrip()
        + "\n\n"
        + scope_text.strip()
    ).strip()






def build_message(
    verdict,
    category,
    subject,
    event_id,
    case_number=None
):

    ref = f"Mã báo cáo: {event_id[:8]}"

    if verdict == "MALICIOUS":
        return (
            f"🚨 Email bạn báo cáo là PHISHING "
            f"({CATEGORY_NAME.get(category, category)}).\n"
            f"Tiêu đề: {subject}\n\n"
            f"{ADVICE.get(category, ADVICE['spam_or_legit'])}\n\n"
            f"Đội SOC đã mở vụ việc"
            f"{f' #{case_number}' if case_number else ''} "
            f"để xử lý. Cảm ơn bạn đã báo cáo!\n"
            f"{ref}"
        )

    if verdict in ("SUSPICIOUS", "INCONCLUSIVE"):
        return (
            f"⚠️ Email bạn báo cáo có dấu hiệu đáng ngờ "
            f"và đang được đội SOC kiểm tra.\n"
            f"Tiêu đề: {subject}\n\n"
            f"Trong lúc chờ kết quả: "
            f"{ADVICE.get(category, ADVICE['spam_or_legit'])}\n"
            f"Chúng tôi sẽ liên hệ lại nếu cần thêm thông tin.\n"
            f"{ref}"
        )

    return (
        f"✅ Email bạn báo cáo được đánh giá là an toàn.\n"
        f"Tiêu đề: {subject}\n\n"
        f"Cảm ơn bạn đã cảnh giác! "
        f"Nếu vẫn thấy nghi ngờ, hãy liên hệ đội SOC.\n"
        f"{ref}"
    )


def send_telegram(chat_id, text):

    r = requests.post(
        f"{TELEGRAM_API}/bot{TELEGRAM_TOKEN}/sendMessage",
        json={
            "chat_id": chat_id,
            "text": text
        },
        timeout=10
    )

    return r.status_code == 200, r.text[:200]






def main():

    if not API_KEY:
        return {
            "success": False,
            "error": "Thiếu TheHive API key"
        }

    if NOTIFY_REPORTER and not TELEGRAM_TOKEN:
        return {
            "success": False,
            "error": "Thiếu Telegram bot token"
        }





    bot = load_bot_event()

    event_id = bot.get("event_id") or ""

    if not event_id:
        return {
            "success": False,
            "error": "Không tìm thấy event_id"
        }





    scoping = load_scoping()

    scope_text = build_scope_description(scoping)





    found = api(
        "POST",
        "/api/v1/query",
        json={
            "query": [
                {
                    "_name": "listAlert"
                },
                {
                    "_name": "filter",
                    "_eq": {
                        "_field": "sourceRef",
                        "_value": event_id
                    }
                }
            ]
        }
    )

    if not found:
        return {
            "success": False,
            "error": f"Không tìm thấy alert sourceRef={event_id}"
        }

    alert = found[0]

    alert_id = alert["_id"]

    original_tags = list(alert.get("tags") or [])

    tags = list(original_tags)





    verdict = (
        tag_value(tags, "final-verdict:")
        or "INCONCLUSIVE"
    ).upper()

    category = (
        tag_value(tags, "category:")
        or "spam_or_legit"
    )

    subject = (
        bot.get("email", {}).get("subject")
        or "(không có tiêu đề)"
    )

    actions = []

    case_number = None





    if scoping.get("performed"):

        if scoping.get("observed"):

            add_tag(tags, "ioc-observed")

            for host in scoping.get("affected_hosts") or []:

                host_name = host.get("agent_name")

                if host_name:
                    add_tag(
                        tags,
                        f"affected-host:{host_name}"
                    )

            actions.append("ioc_scope_observed")

        else:
            add_tag(tags, "ioc-not-observed")
            actions.append("ioc_scope_not_observed")

    else:
        add_tag(tags, "ioc-scoping-failed")
        actions.append("ioc_scoping_failed")





    old_alert_description = alert.get("description") or ""

    new_alert_description = merge_scope_description(
        old_alert_description,
        scope_text
    )

    try:
        api(
            "PATCH",
            f"/api/v1/alert/{alert_id}",
            json={
                "description": new_alert_description,
                "tags": tags
            }
        )

        actions.append("alert_scope_updated")

    except RuntimeError as e:
        actions.append(
            f"alert_scope_update_failed: {e}"
        )





    try:





        if verdict == "MALICIOUS":

            existing_case_id = alert.get("caseId")

            if existing_case_id:

                actions.append("case_already_exists")


                try:

                    existing_case = api(
                        "GET",
                        f"/api/v1/case/{existing_case_id}"
                    )

                    case_number = existing_case.get("number")

                    case_description = merge_scope_description(
                        existing_case.get("description") or "",
                        scope_text
                    )

                    case_tags = list(
                        existing_case.get("tags") or []
                    )

                    for tag in tags:
                        add_tag(case_tags, tag)

                    api(
                        "PATCH",
                        f"/api/v1/case/{existing_case_id}",
                        json={
                            "title":
                                f"[MALICIOUS][{category}] "
                                f"{subject}"[:250],

                            "description":
                                case_description,

                            "tags":
                                case_tags
                        }
                    )

                    actions.append(
                        "existing_case_scope_updated"
                    )

                except (RuntimeError, KeyError) as e:

                    actions.append(
                        f"existing_case_update_failed: {e}"
                    )

            else:



                case = api(
                    "POST",
                    f"/api/v1/alert/{alert_id}/case",
                    json={}
                )

                case_number = case.get("number")

                actions.append(
                    f"case_created:#{case_number}"
                )





                try:

                    case_id = case["_id"]

                    case_description = merge_scope_description(
                        case.get("description")
                        or new_alert_description,
                        scope_text
                    )

                    case_tags = list(
                        case.get("tags") or []
                    )

                    for tag in tags:
                        add_tag(case_tags, tag)

                    api(
                        "PATCH",
                        f"/api/v1/case/{case_id}",
                        json={
                            "title":
                                f"[MALICIOUS][{category}] "
                                f"{subject}"[:250],

                            "description":
                                case_description,

                            "tags":
                                case_tags
                        }
                    )

                    actions.append(
                        "case_scope_updated"
                    )

                except (RuntimeError, KeyError) as e:

                    actions.append(
                        f"case_scope_update_failed: {e}"
                    )





        elif verdict == "CLEAN":

            api(
                "PATCH",
                f"/api/v1/alert/{alert_id}",
                json={
                    "status": CLEAN_STATUS,
                    "description": new_alert_description,
                    "tags": tags
                }
            )

            actions.append(
                f"alert_status:{CLEAN_STATUS}"
            )





        else:

            add_tag(
                tags,
                "needs-analyst"
            )

            api(
                "PATCH",
                f"/api/v1/alert/{alert_id}",
                json={
                    "description":
                        new_alert_description,

                    "tags":
                        tags
                }
            )

            actions.append(
                "left_for_analyst"
            )

    except RuntimeError as e:

        actions.append(
            f"thehive_action_failed: {e}"
        )





    reporter = bot.get("reporter") or {}

    chat_id = reporter.get("chat_id")

    if not NOTIFY_REPORTER:

        actions.append(
            "reporter_notification_disabled"
        )

    elif "reporter-notified" in tags:

        actions.append(
            "reporter_already_notified"
        )

    elif not chat_id:

        actions.append(
            "no_reporter_chat_id"
        )

    else:

        ok, detail = send_telegram(
            chat_id,
            build_message(
                verdict,
                category,
                subject,
                event_id,
                case_number
            )
        )

        if ok:

            add_tag(
                tags,
                "reporter-notified"
            )

            actions.append(
                "telegram_sent"
            )

        else:

            actions.append(
                f"telegram_failed: {detail}"
            )





    try:

        api(
            "PATCH",
            f"/api/v1/alert/{alert_id}",
            json={
                "tags": tags
            }
        )

    except RuntimeError as e:

        actions.append(
            f"tag_update_failed: {e}"
        )





    return {
        "success": True,
        "alert_id": alert_id,
        "verdict": verdict,
        "category": category,

        "scoping": {
            "performed":
                scoping.get("performed", False),

            "observed":
                scoping.get("observed", False),

            "dns_hits":
                scoping.get("dns_hits", 0),

            "unique_hosts":
                scoping.get("unique_hosts", 0),

            "affected_hosts":
                scoping.get("affected_hosts", [])
        },

        "actions": actions
    }






try:

    print(
        json.dumps(
            main(),
            ensure_ascii=False
        )
    )

except Exception as e:

    print(
        json.dumps(
            {
                "success": False,
                "error":
                    f"{type(e).__name__}: {e}"
            },
            ensure_ascii=False
        )
    )
