#!/usr/bin/python3
import sys, os, json, logging, requests
from collections import defaultdict
from datetime import datetime, timedelta, timezone

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
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def read_wrapper():
    raw = sys.stdin.read().strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception as e:
        logger.error("Cannot parse AR wrapper JSON: %s | raw=%r", e, raw[:800])
        return None

def get_token():
    url = f"{WAZUH_API_URL}/security/user/authenticate?raw=true"
    r = requests.post(url, auth=(WAZUH_AUTH_USER, WAZUH_AUTH_PASS), verify=VERIFY_TLS)
    r.raise_for_status()
    return r.text.strip()

def send_agent_ar(agent_id, cmd, args, token, alert_data):
    url = f"{WAZUH_API_URL}/active-response"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    params = {"agents_list": agent_id, "wait_for_complete": True}
    payload = {"command": cmd, "arguments": args, "alert": {"data": alert_data}}
    r = requests.put(url, headers=headers, params=params, data=json.dumps(payload), verify=VERIFY_TLS)
    r.raise_for_status()
    return r.json()

def search_context(user_key, user_val, when_iso, minutes=10):
    """
    Pull a small context window around the current alert from wazuh-archives.
    user_key: "data.dstuser" or "data.srcuser"
    when_iso: ISO8601 timestamp of the alert; we fetch +/- minutes
    """
    if not when_iso:
        return []

    try:
        t = datetime.fromisoformat(when_iso.replace("Z","+00:00"))
    except Exception:
        return []

    gte = (t - timedelta(minutes=minutes)).isoformat()
    lte = (t + timedelta(minutes=1)).isoformat()

    body = {
        "size": MAX_HITS,
        "query": {
            "bool": {
                "must": [
                    {
                        "bool": {
                            "should": [
                                {"term": {f"{user_key}.keyword": user_val}},
                                {"term": {user_key: user_val}}
                            ],
                            "minimum_should_match": 1
                        }
                    },
                    {"range": {"@timestamp": {"gte": gte, "lte": lte}}}
                ]
            }
        },
        "_source": [
            "@timestamp","agent.name","agent.id","rule.id","rule.description",
            "data.srcip","data.dstuser","data.srcuser",
            "data.radar_outcome","data.radar_country_change_i","data.radar_geo_velocity_kmh",
            "location","full_log"
        ],
        "sort": [{"@timestamp": "asc"}]
    }

    url = f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_search"
    r = requests.post(url, auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
                      headers={"Content-Type":"application/json"},
                      data=json.dumps(body), verify=VERIFY_TLS)
    r.raise_for_status()
    return r.json().get("hits",{}).get("hits",[])

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
def main():
    wrapper = read_wrapper()
    if not wrapper:
        print(json.dumps({"version":1,"origin":{},"command":"continue","parameters":{}}))
        return

    action = wrapper.get("command")
    params = wrapper.get("parameters", {})
    alert  = params.get("alert", {})
    data   = alert.get("data", {}) or {}

    if action != "add":
        logger.info("Action '%s' not handled, continuing.", action)
        print(json.dumps({"version":1,"origin":wrapper.get("origin",{}),"command":"continue","parameters":{}}))
        return

    agent      = alert.get("agent", {}) or {}
    agent_id   = agent.get("id")
    agent_name = agent.get("name")
    rule_id    = str(alert.get("rule", {}).get("id") or "")
    when_iso   = alert.get("@timestamp") or alert.get("timestamp")

    srcip   = data.get("srcip") or data.get("src_ip")
    dstuser = data.get("dstuser")
    srcuser = data.get("srcuser")
    outcome = data.get("radar_outcome")

    user_key = None
    user_val = None
    if rule_id in ("210012","210031") and srcuser:
        user_key, user_val = "data.srcuser", srcuser
    elif dstuser:
        user_key, user_val = "data.dstuser", dstuser
    elif srcuser:
        user_key, user_val = "data.srcuser", srcuser

    context_hits = search_context(user_key, user_val, when_iso, minutes=3) if (user_key and user_val and when_iso) else []
    context_payload = [h.get("_source", {}) for h in context_hits]

    try:
        token = get_token()
    except Exception as e:
        logger.exception("Wazuh token error: %s", e)
        print(json.dumps({"version":1,"origin":wrapper.get("origin",{}),"command":"continue","parameters":{}}))
        return

    # Send contextual writer first (if we have an agent)
    if agent_id:
        try:
            send_agent_ar(
                agent_id,
                "!write_contextual_logs_susplog_active_response.sh",
                [user_val or "", json.dumps(context_payload)],
                token,
                data
            )
        except Exception as e:
            logger.exception("Context writer AR failed: %s", e)

    # Decide enforcement based on rule ids/outcomes
    # - 210011/210012 (failed burst)  -> drop srcip (if known)
    # - 210020 (impossible travel)    -> drop srcip + disable user (dstuser)
    # - 210030/210031 (both)   -> drop srcip + disable user
    must_drop = rule_id in ("210011","210012","210020","210030","210031")
    must_disable = rule_id in ("210020","210030","210031")

    if must_drop and agent_id and srcip:
        try:
            send_agent_ar(agent_id, "!firewall-drop", [srcip], token, {"srcip": srcip})
        except Exception as e:
            logger.exception("Firewall-drop AR failed: %s", e)

    if must_disable and (dstuser or srcuser) and agent_id:
        try:
            send_agent_ar(agent_id, "!disable_sso_user.py", [], token, {"dstuser": dstuser or srcuser})
        except Exception as e:
            logger.exception("disable_sso_user AR failed: %s", e)

    print(json.dumps({"version":1,"origin":wrapper.get("origin",{}),"command":"continue","parameters":{}}))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.exception("Unhandled AR error: %s", e)
        print(json.dumps({"version":1,"origin":{},"command":"continue","parameters":{}}))
