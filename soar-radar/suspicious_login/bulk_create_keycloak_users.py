import os, sys, pandas as pd, requests, urllib.parse


KC_BASE   = os.getenv("KC_BASE_URL", "http://localhost:8080")
REALM     = os.getenv("KC_REALM", "demo")
USER      = os.getenv("KC_ADMIN_USER", "admin")
PASSWORD  = os.getenv("KC_ADMIN_PASSWORD", "secret")

CSV_PATH  = sys.argv[1] if len(sys.argv) > 1 else "dataset.csv"

# 1) GET ADMIN TOKEN
token_url  = f"{KC_BASE}/realms/master/protocol/openid-connect/token"
token_resp = requests.post(
    token_url,
    data = {
        "grant_type": "password",
        "client_id":  "admin-cli",   # built-in public client
        "username":   USER,
        "password":   PASSWORD,
    },
    timeout = 10,
)
token_resp.raise_for_status()
ADMIN_TOKEN = token_resp.json()["access_token"]

HEADERS = {
    "Authorization": f"Bearer {ADMIN_TOKEN}",
    "Content-Type":  "application/json",
}


# 2) READ USER IDS FROM CSV

df = pd.read_csv(CSV_PATH)
uid_series = df["User ID"].dropna().astype(str).unique()
print(f"🛈  Found {len(uid_series)} unique User IDs in {CSV_PATH}")


# 3) CREATE USERS

users_endpoint = f"{KC_BASE}/admin/realms/{urllib.parse.quote(REALM)}/users"
created, skipped, failed = 0, 0, 0

for uid in uid_series:
    payload = {
        "username": uid,
        "enabled":  True
    }

    r = requests.post(users_endpoint, headers=HEADERS, json=payload, timeout=10)
    print(f"Creating Keycloak users")
    if r.status_code == 201:
        created += 1
        print(f"Created user {uid}")
    elif r.status_code == 409:  # already exists
        skipped += 1
        #print(f"Skipped existing user {uid}")
    else:
        failed += 1
        #print(f"Failed for {uid}: {r.status_code} {r.text}")

print(f"\nSummary: {created} created")
