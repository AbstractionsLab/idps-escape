#!/usr/bin/python3
import os, sys, json, logging, requests

KC_BASE_URL      = os.getenv("KC_BASE_URL", "http://127.0.0.1:8080")
KC_REALM         = os.getenv("KC_REALM", "demo")
KC_CLIENT_ID     = os.getenv("KC_CLIENT_ID", "wazuh")
KC_CLIENT_SECRET  = os.getenv("KC_CLIENT_SECRET", "zyg1fEAId6JLAGcvUhbRcQovUX4s5kir")          # export KC_SECRET=xxxx

TOKEN_EP = f"{KC_BASE_URL}/realms/{KC_REALM}/protocol/openid-connect/token"
USERS_EP = f"{KC_BASE_URL}/admin/realms/{KC_REALM}/users"
TIMEOUT  = 5

LOG_FILE = "/var/ossec/logs/active-responses.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s disable_sso_user: %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(LOG_FILE, mode="a")  # append mode
    ]
)

LOG = logging.getLogger()

def kc_token():
    res = requests.post(TOKEN_EP, data={
        "grant_type":    "client_credentials",
        "client_id":     KC_CLIENT_ID,
        "client_secret": KC_CLIENT_SECRET,
    }, timeout=TIMEOUT)
    res.raise_for_status()
    return res.json()["access_token"]


def kc_disable(username, token):
    hdr = {"Authorization": f"Bearer {token}"}
    # 1) look up user
    res = requests.get(USERS_EP, params={"username": username},
                       headers=hdr, timeout=TIMEOUT)
    res.raise_for_status()
    users = res.json()
    if not users:
        LOG.warning("User %s not found in Keycloak", username)
        return
    uid = users[0]["id"]

    # 2) disable
    res = requests.put(f"{USERS_EP}/{uid}",
                       headers={**hdr, "Content-Type": "application/json"},
                       json={"enabled": False}, timeout=TIMEOUT)
    res.raise_for_status()
    LOG.info("Locked Keycloak account %s (id=%s)", username, uid)

# ---------- main --------------------------------------------------------------
def main():
    input_str = ""
    for line in sys.stdin.readline().strip():
        input_str += line
    try:
        wrapper = json.loads(input_str)
    except ValueError as e:
        LOG.error(str(e))

    if wrapper.get("command") != "add":
        sys.exit(0)                          # ignore “delete”, etc.

    uid = (
        wrapper.get("parameters", {})
               .get("alert", {})
               .get("data", {})
               .get("User ID")
    )
    LOG.info("UID: %s", str(uid))
    if not uid:
        LOG.error("No User ID in alert data – nothing to lock")
        sys.exit(0)

    try:
        kc_disable(uid, kc_token())
    except Exception as e:
        LOG.error("Keycloak API error: %s", e)


if __name__ == "__main__":
    main()
