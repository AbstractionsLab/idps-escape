#!/usr/bin/env python3
import sys
import json
import logging
from collections import defaultdict
import requests

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
OPENSEARCH_URL   = "https://wazuh.indexer:9200"
OPENSEARCH_INDEX = "wazuh-ad-insider-threat-2025.*"
OPENSEARCH_USER  = "admin"
OPENSEARCH_PASS  = "SecretPassword"

WAZUH_API_URL    = "https://192.168.0.28:55000"
WAZUH_AUTH_USER  = "wazuh-wui"
WAZUH_AUTH_PASS  = "MyS3cr37P450r.*-"

HEADERS_JSON     = {"Content-Type": "application/json"}
MAX_HITS         = 1000
LOG_FILE         = "/var/ossec/logs/active-responses.log"

# ──────────────────────────────────────────────────────────────────────────────
# Logging (to both console and a file)
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(logging.INFO)
for h in (
    logging.StreamHandler(sys.stderr),
    logging.FileHandler(LOG_FILE, mode="a")
):
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(h)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers: Auth, OpenSearch query, Wazuh API calls
# ──────────────────────────────────────────────────────────────────────────────
def get_wazuh_token():
    url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
    r = requests.post(url,
        auth=(WAZUH_AUTH_USER, WAZUH_AUTH_PASS),
        verify=False)
    r.raise_for_status()
    token = r.text.strip()
    logger.info("Obtained Wazuh JWT token")
    return token

def query_opensearch(user, start, end):
    body = {
        "size": MAX_HITS,
        "query": {
            "bool": {
                "must": [
                    {"term":  {"user.keyword": user}},
                    {"range": {"@timestamp": {"gte": start,"lte": end}}}
                ]
            }
        },
        "_source": ["pc","id","@timestamp","filename","content_bytes"]
    }
    url = f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_search"
    r = requests.post(url, auth=(OPENSEARCH_USER,OPENSEARCH_PASS),
                     headers=HEADERS_JSON,
                     data=json.dumps(body), verify=False)
    r.raise_for_status()
    return r.json().get("hits",{}).get("hits",[])

def get_agent_id_by_pc(pc, token):
    url = f"{WAZUH_API_URL}/agents"
    h = {"Authorization":f"Bearer {token}", **HEADERS_JSON}
    r = requests.get(url, headers=h, params={"search":pc}, verify=False)
    r.raise_for_status()
    payload = r.json().get("data", [])

    # payload may be:
    # 1) a list of agent dicts, as in GET /agents
    # 2) a dict with 'affected_items' list (if reused from AR), so guard both
    if isinstance(payload, dict) and "affected_items" in payload:
        agents = payload["affected_items"]
    elif isinstance(payload, list):
        agents = payload
    else:
        agents = []

    if not agents:
        return None

    first = agents[0]
    return first.get("id")


def send_agent_ar(agent_id, cmd, args, token, alert_data):
    url = f"{WAZUH_API_URL}/active-response"
    h   = {"Authorization":f"Bearer {token}", **HEADERS_JSON}
    params = {"agents_list":agent_id, "wait_for_complete":True}
    payload = {"command":cmd, "arguments":args, "alert":{"data":alert_data}}
    logger.info(f"Sending AR '{cmd}' to agent {agent_id}")
    r = requests.put(url, headers=h, params=params,
                     data=json.dumps(payload), verify=False)
    r.raise_for_status()
    result = r.json()
    if result.get("error",0)!=0:
        logger.error(f"AR {cmd} failed: {result}")
    else:
        logger.info(f"AR {cmd} succeeded: {result.get('affected_items',result.get('data'))}")
    return result

# ──────────────────────────────────────────────────────────────────────────────
# Main entrypoint
# ──────────────────────────────────────────────────────────────────────────────
def main():
    input_str = ""
    for line in sys.stdin.readline().strip():
        input_str += line

    try:
        wrapper = json.loads(input_str)
    except ValueError as e:
        logger.error(str(e))

    action = wrapper.get("command")
    params = wrapper.get("parameters", {})
    alert   = params.get("alert", {})
    data   = alert.get("data", {})
    user   = data.get("user_keyword")
    start  = data.get("period_start")
    end    = data.get("period_end")

    if action == "add" and user and start and end:
        logger.info(f"Active response ADD for user={user} window={start}→{end}")

        token = get_wazuh_token()
        hits  = query_opensearch(user, start, end)

        by_pc = defaultdict(list)
        for h in hits:
            src = h.get("_source",{})
            by_pc[src.get("pc","UNKNOWN")].append(src)

        # 1) Enrichment log on each agent
        for pc, events in by_pc.items():
            aid = get_agent_id_by_pc(pc, token)
            if not aid:
                logger.warning(f"No agent for PC={pc}")
                continue
            events_json = json.dumps(events)
            send_agent_ar(aid, "!write_contextual_logs_insider_active_response.sh", [user, events_json], token, data)

        # Optional lockout (comment out to disable)
        for pc in by_pc:
            aid = get_agent_id_by_pc(pc, token)
            if aid:
                send_agent_ar(aid, "!lock_user_linux_active_reponse.sh", [user], token, data)

        resp = {"version":1, "origin":wrapper.get("origin",{}),
                "command":"continue", "parameters":{}}
    else:
        logger.info(f"Ignoring action='{action}'")
        resp = {"version":1, "origin":wrapper.get("origin",{}),
                "command":"continue", "parameters":{}}

    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()