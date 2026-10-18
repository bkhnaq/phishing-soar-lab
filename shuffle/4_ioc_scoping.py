import json
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)






WAZUH_URL = ""
WAZUH_USER = ""
WAZUH_PASS = ""

TIME_RANGE = "now-24h"





raw_verdict = r'''$verdict_engine'''

try:
    verdict = json.loads(raw_verdict)
except Exception as e:
    print(json.dumps({
        "success": False,
        "stage": "ioc_scoping",
        "error": "Cannot parse Verdict engine output",
        "details": str(e),
        "raw_input": raw_verdict[:500]
    }))
    raise SystemExit()

message = verdict.get("message", {})
observables = message.get("observables", [])





domains = []

for obs in observables:
    if not isinstance(obs, dict):
        continue

    if obs.get("type") != "domain":
        continue

    domain = str(obs.get("data", "")).strip().lower().rstrip(".")

    if domain and domain not in domains:
        domains.append(domain)





if not domains:
    message["scoping"] = {
        "performed": True,
        "window": TIME_RANGE,
        "domains_checked": [],
        "dns_hits": 0,
        "unique_hosts": 0,
        "affected_hosts": [],
        "domain_results": {},
        "observed": False
    }

    verdict["message"] = message
    print(json.dumps(verdict))
    raise SystemExit()





should_queries = []

for domain in domains:
    should_queries.append({
        "match_phrase": {
            "data.win.eventdata.queryName": domain
        }
    })

query = {
    "size": 500,
    "_source": [
        "@timestamp",
        "agent.id",
        "agent.name",
        "agent.ip",
        "rule.id",
        "data.win.system.eventID",
        "data.win.eventdata.queryName",
        "data.win.eventdata.queryType",
        "data.win.eventdata.queryStatus"
    ],
    "query": {
        "bool": {
            "filter": [
                {
                    "term": {
                        "rule.id": "100600"
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "gte": TIME_RANGE
                        }
                    }
                }
            ],
            "should": should_queries,
            "minimum_should_match": 1
        }
    },
    "sort": [
        {
            "@timestamp": {
                "order": "desc"
            }
        }
    ]
}





try:
    response = requests.post(
        WAZUH_URL + "/wazuh-alerts-4.x-*/_search",
        auth=(WAZUH_USER, WAZUH_PASS),
        headers={"Content-Type": "application/json"},
        json=query,
        verify=False,
        timeout=20
    )

    response.raise_for_status()
    wazuh_data = response.json()

except Exception as e:
    message["scoping"] = {
        "performed": False,
        "error": "Wazuh Indexer query failed",
        "details": str(e),
        "domains_checked": domains
    }

    verdict["message"] = message
    print(json.dumps(verdict))
    raise SystemExit()





hits = wazuh_data.get("hits", {}).get("hits", [])

hosts = {}
domain_results = {}

for domain in domains:
    domain_results[domain] = {
        "dns_hits": 0,
        "unique_hosts": [],
        "first_seen": None,
        "last_seen": None
    }

for hit in hits:
    src = hit.get("_source", {})

    timestamp = src.get("@timestamp")
    agent = src.get("agent", {})

    win = src.get("data", {}).get("win", {})
    eventdata = win.get("eventdata", {})

    query_name = str(
        eventdata.get("queryName", "")
    ).strip().lower().rstrip(".")


    if query_name not in domain_results:
        continue

    agent_id = agent.get("id")
    agent_name = agent.get("name")
    agent_ip = agent.get("ip")

    host_key = agent_id or agent_name or agent_ip





    dr = domain_results[query_name]

    dr["dns_hits"] += 1

    if timestamp:
        if dr["first_seen"] is None or timestamp < dr["first_seen"]:
            dr["first_seen"] = timestamp

        if dr["last_seen"] is None or timestamp > dr["last_seen"]:
            dr["last_seen"] = timestamp

    if host_key and host_key not in dr["unique_hosts"]:
        dr["unique_hosts"].append(host_key)





    if not host_key:
        continue

    if host_key not in hosts:
        hosts[host_key] = {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "agent_ip": agent_ip,
            "dns_hits": 0,
            "domains": [],
            "first_seen": None,
            "last_seen": None
        }

    host = hosts[host_key]

    host["dns_hits"] += 1

    if query_name not in host["domains"]:
        host["domains"].append(query_name)

    if timestamp:
        if host["first_seen"] is None or timestamp < host["first_seen"]:
            host["first_seen"] = timestamp

        if host["last_seen"] is None or timestamp > host["last_seen"]:
            host["last_seen"] = timestamp


for domain in domain_results:
    domain_results[domain]["unique_hosts"] = len(
        domain_results[domain]["unique_hosts"]
    )

affected_hosts = list(hosts.values())





scoping = {
    "performed": True,
    "window": TIME_RANGE,
    "domains_checked": domains,
    "dns_hits": sum(
        x["dns_hits"] for x in domain_results.values()
    ),
    "unique_hosts": len(affected_hosts),
    "affected_hosts": affected_hosts,
    "domain_results": domain_results,
    "observed": len(affected_hosts) > 0
}


message["scoping"] = scoping
verdict["message"] = message

print(json.dumps(verdict))
