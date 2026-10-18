import json
import time
from concurrent.futures import ThreadPoolExecutor

START = time.time()

import requests
import urllib3

urllib3.disable_warnings()

THEHIVE_URL = ""
API_KEY = ""

ALERT_ID = "$create_thehive_alert.message.alert_id"

CORTEX_ID = "cortex"
TIME_BUDGET = 150
POLL_INTERVAL = 5
MAX_VT_JOBS = 4


ANALYZERS_BY_TYPE = {
    "url":    ["VirusTotal_GetReport", "Urlscan_io_Search"],
    "ip":     ["AbuseIPDB", "VirusTotal_GetReport", "Abuse_Finder"],
    "domain": ["VirusTotal_GetReport", "Urlscan_io_Search", "Abuse_Finder"],
    "hash":   ["VirusTotal_GetReport"],
    "mail":   ["Abuse_Finder"],
}

TYPE_PRIORITY = ["url", "ip", "hash", "domain", "mail"]

HEADERS = {"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}


def api(method, path, **kwargs):
    resp = requests.request(method, f"{THEHIVE_URL}{path}", headers=HEADERS,
                            timeout=10, verify=False, **kwargs)
    if resp.status_code >= 400:
        raise RuntimeError(f"{method} {path} -> {resp.status_code}: {resp.text[:300]}")
    return resp.json() if resp.text else {}


def resolve_alert_id():
    """Ưu tiên alert_id từ node trước; nếu không có (alert trùng, sai tên biến)
    thì tìm alert theo sourceRef = event_id của bot."""
    if ALERT_ID and not ALERT_ID.startswith("$"):
        return ALERT_ID, "from_previous_node"
    try:
        wazuh = json.loads(r'''$exec''')
        text = wazuh.get("text")
        bot = text if isinstance(text, dict) else json.loads(text)
        ref = bot.get("event_id")
    except Exception:
        return None, "cannot_read_event_id"
    if not ref:
        return None, "no_event_id"
    query = {"query": [{"_name": "listAlert"},
                       {"_name": "filter", "_eq": {"_field": "sourceRef", "_value": ref}}]}
    found = api("POST", "/api/v1/query", json=query)
    return (found[0]["_id"], f"by_sourceRef:{ref}") if found else (None, f"not_found:{ref}")


def get_observables(alert_id):
    query = {"query": [{"_name": "getAlert", "idOrName": alert_id}, {"_name": "observables"}]}
    return api("POST", "/api/v1/query", json=query)


def get_analyzers():
    """Danh sách analyzer TheHive thấy được từ Cortex: {name: {id, dataTypeList}}."""
    result = {}
    for a in api("GET", "/api/connector/cortex/analyzer"):
        result[a.get("name", "")] = {"id": a.get("id") or a.get("_id"),
                                     "types": a.get("dataTypeList", [])}
    return result


def find_analyzer(analyzers, prefix, data_type):
    matches = [name for name, a in analyzers.items()
               if (name == prefix or name.startswith(prefix + "_")) and data_type in a["types"]]
    return sorted(matches)[-1] if matches else None


def plan_jobs(observables, analyzers):
    plan, vt_count, skipped = [], 0, []
    observables = sorted(observables, key=lambda o: TYPE_PRIORITY.index(o["dataType"])
                         if o.get("dataType") in TYPE_PRIORITY else 99)
    for obs in observables:
        data_type = obs.get("dataType")
        if "benign-reference" in (obs.get("tags") or []):
            skipped.append(f"{obs.get('data')} (benign-reference)")
            continue
        for prefix in ANALYZERS_BY_TYPE.get(data_type, []):
            name = find_analyzer(analyzers, prefix, data_type)
            if not name:
                continue
            if prefix == "VirusTotal_GetReport":
                if vt_count >= MAX_VT_JOBS:
                    skipped.append(f"{obs.get('data')} ({name}: hết quota mỗi alert)")
                    continue
                vt_count += 1
            plan.append({"observable_id": obs["_id"], "data": obs.get("data"),
                         "dataType": data_type, "analyzer": name,
                         "analyzer_id": analyzers[name]["id"]})
    return plan, skipped


def start_job(item):
    body = {"analyzerId": item["analyzer_id"], "cortexId": CORTEX_ID,
            "artifactId": item["observable_id"]}
    job = api("POST", "/api/connector/cortex/job", json=body)
    return job.get("_id") or job.get("id")


def wait_jobs(jobs):
    deadline = START + TIME_BUDGET
    pending = [j for j in jobs if j.get("job_id")]
    while pending and time.time() + POLL_INTERVAL < deadline:
        time.sleep(POLL_INTERVAL)
        def fetch(j):
            try:
                return j, api("GET", f"/api/connector/cortex/job/{j['job_id']}"), None
            except Exception as e:
                return j, None, str(e)

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(fetch, list(pending)))
        for j, job, err in results:
            if err:
                j["status"], j["error"] = "Error", err
                pending.remove(j)
                continue
            j["status"] = job.get("status", "Unknown")
            if j["status"] in ("Success", "Failure", "Deleted"):
                taxonomies = (job.get("report") or {}).get("summary", {}).get("taxonomies", [])
                j["taxonomies"] = [f"{t.get('namespace')}:{t.get('predicate')}={t.get('value')} [{t.get('level')}]"
                                   for t in taxonomies]
                if j["status"] == "Failure":
                    j["error"] = (job.get("report") or {}).get("errorMessage", "")
                pending.remove(j)
    for j in pending:
        j["status"] = "Pending"


def main():
    alert_id, resolved_by = resolve_alert_id()
    if not alert_id:
        return {"success": False, "error": f"Không tìm được alert ({resolved_by})",
                "alert_id_raw": ALERT_ID}

    observables = get_observables(alert_id)
    analyzers = get_analyzers()
    if not analyzers:
        return {"success": False, "error": "TheHive không thấy analyzer nào từ Cortex"}

    plan, skipped = plan_jobs(observables, analyzers)
    def submit(item):
        try:
            item["job_id"] = start_job(item)
            item["status"] = "Submitted"
        except Exception as e:
            item["status"], item["error"] = "SubmitError", str(e)


    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(submit, plan))

    wait_jobs(plan)

    summary = {}
    for item in plan:
        summary[item["status"]] = summary.get(item["status"], 0) + 1
    return {
        "success": True,
        "alert_id": alert_id,
        "alert_resolved_by": resolved_by,
        "observables": len(observables),
        "jobs_total": len(plan),
        "jobs_by_status": summary,
        "elapsed_seconds": round(time.time() - START, 1),
        "skipped": skipped,
        "jobs": [{k: v for k, v in item.items() if k not in ("analyzer_id", "observable_id")}
                 for item in plan],
    }


try:
    print(json.dumps(main(), ensure_ascii=False))
except Exception as e:
    print(json.dumps({"success": False, "error": str(e)}, ensure_ascii=False))
