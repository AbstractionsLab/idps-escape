#!/usr/bin/python3
import os
import sys
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
import requests

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
OPENSEARCH_URL   = os.environ.get("OS_URL", "https://localhost:9200") 
# New index for suspicious logins
OPENSEARCH_INDEX = "wazuh-ad-suspicious-login-2025.*"
OPENSEARCH_USER  = os.environ.get("OS_USER", "")
OPENSEARCH_PASS  = os.environ.get("OS_PASS", "")

WAZUH_API_URL    = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
WAZUH_AUTH_USER  = os.environ.get("WAZUH_AUTH_USER", "")
WAZUH_AUTH_PASS  = os.environ.get("WAZUH_AUTH_PASS", "")

HEADERS_JSON     = {"Content-Type": "application/json"}
MAX_HITS         = 1000
LOG_FILE         = os.environ.get("AR_LOG_FILE", "/var/ossec/logs/active-responses.log")

# ──────────────────────────────────────────────────────────────────────────────
# Logging (to both console and a file)
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(logging.INFO)
for handler in (
    logging.StreamHandler(sys.stderr),
    logging.FileHandler(LOG_FILE, mode="a")
):
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)

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
                    {"term": {"User ID.keyword": user}},
                    {"range": {"@timestamp": {"gte": start, "lte": end}}}
                ]
            }
        },
        # fetch IP Address and timestamp fields
        "_source": ["IP Address", "User ID", "@timestamp", "agent.name"]
    }
    url = f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_search"
    r = requests.post(url,
                      auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
                      headers=HEADERS_JSON,
                      data=json.dumps(body), verify=False)
    r.raise_for_status()
    return r.json().get("hits", {}).get("hits", [])


def get_agent_id_by_identifier(identifier, token):
    # identifier may be PC name or agent IP
    url = f"{WAZUH_API_URL}/agents"
    headers = {"Authorization": f"Bearer {token}", **HEADERS_JSON}
    # search by IP or name
    params = {"search": identifier}
    r = requests.get(url, headers=headers, params=params, verify=False)
    r.raise_for_status()
    data = r.json().get("data", [])
    if isinstance(data, dict) and "affected_items" in data:
        agents = data["affected_items"]
    elif isinstance(data, list):
        agents = data
    else:
        agents = []
    return agents[0].get("id") if agents else None


def send_agent_ar(agent_id, cmd, args, token, alert_data):
    url = f"{WAZUH_API_URL}/active-response"
    headers = {"Authorization": f"Bearer {token}", **HEADERS_JSON}
    params = {"agents_list": agent_id, "wait_for_complete": True}
    payload = {"command": cmd, "arguments": args, "alert": {"data": alert_data}}
    logger.info(f"Sending AR '{cmd}' to agent {agent_id}")
    r = requests.put(url, headers=headers, params=params,
                     data=json.dumps(payload), verify=False)
    r.raise_for_status()
    result = r.json()
    logger.info(str(result))
    if result.get("error", 0) != 0:
        logger.error(f"AR {cmd} failed: {result}")
    else:
        logger.info(f"AR {cmd} succeeded: {result.get('affected_items', result.get('data'))}")
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
        logger.error("Failed to parse wrapper JSON: %s", e)
        return

    action = wrapper.get("command")
    params = wrapper.get("parameters", {})
    alert  = params.get("alert", {})
    data   = alert.get("data", {})
    user   = data.get("entity_keyword")
    start  = data.get("period_start")
    end    = data.get("period_end")
    agent_id = None


    if action == "add" and user and start and end:
        logger.info(f"ADD for user={user} window={start}->{end}")
        token = get_wazuh_token()


        # Enrich with OpenSearch
        hits = query_opensearch(user, start, end)
        events_json = json.dumps(hits)

        # Block IPs
        events_by_ip = defaultdict(list)
        for hit in hits:
            src = hit.get("_source", {})
            ip  = src.get("IP Address")
            agent_name = src.get("agent.name")
            events_by_ip[ip].append(src)

            if agent_name:
                agent_id = get_agent_id_by_identifier(agent_name, token)
            else:
                logger.warning("Cannot resolve agent for event %s", src)
                continue

        for ip in events_by_ip:
            send_agent_ar(agent_id, "!write_contextual_logs_susplog_active_response.sh", [user, events_json], token,
                          data)
            send_agent_ar(agent_id,
                          "!firewall-drop",
                          [ip],
                          token,
                          {"srcip": ip})

        # Trigger disable-sso-user AR on the same agent
        send_agent_ar(agent_id,
                      "!disable_sso_user.py",
                      [],
                      token,
                      {"User ID": user})

        # Respond to execd
        resp = {"version": 1,
                "origin": wrapper.get("origin", {}),
                "command": "continue",
                "parameters": {}}
    else:
        logger.info(f"Ignoring action='{action}' or missing user/start/end/agent_name")
        resp = {"version": 1,
                "origin": wrapper.get("origin", {}),
                "command": "continue",
                "parameters": {}}

    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()
