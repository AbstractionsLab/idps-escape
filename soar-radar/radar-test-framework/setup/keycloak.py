import os
import glob
import json
import pandas as pd
import requests
import urllib.parse
from setup.config_loader import AppConfig
from pathlib import Path

class KeycloakManager:
    def __init__(self, app_config: AppConfig):
        self.base_url = app_config.keycloak_base_url
        self.realm = app_config.keycloak_realm
        self.admin_user = app_config.keycloak_admin_user
        self.admin_password = app_config.keycloak_admin_pass
        relative_path = app_config.scenario_config["suspicious_login"].get("dataset_dir", "dataset/suspicious_login")
        self.dataset_dir = Path(__file__).resolve().parent.parent.parent / relative_path
        self.token = None
        self.headers = {}

    def get_admin_token(self):
        token_url = f"{self.base_url}/realms/master/protocol/openid-connect/token"
        resp = requests.post(
            token_url,
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self.admin_user,
                "password": self.admin_password,
            },
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def authenticate(self):
        self.token = self.get_admin_token()
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        print("[✓] Admin token acquired")

    def create_realm_if_not_exists(self):
        realm_url = f"{self.base_url}/admin/realms/{urllib.parse.quote(self.realm)}"
        resp = requests.get(realm_url, headers=self.headers, timeout=10)

        if resp.status_code == 200:
            print(f"[✓] Realm '{self.realm}' already exists.")
            return

        print(f"[+] Creating realm '{self.realm}'...")
        create_resp = requests.post(
            f"{self.base_url}/admin/realms",
            headers=self.headers,
            json={
                "realm": self.realm,
                "enabled": True,
                "eventsEnabled": True,
                "eventsListeners": ["jboss-logging"],
                "enabledEventTypes": ["LOGIN", "LOGIN_ERROR"],
            },
            timeout=10,
        )
        create_resp.raise_for_status()
        print(f"[✓] Realm '{self.realm}' created.")

    def create_users_from_dataset(self):
        endpoint = f"{self.base_url}/admin/realms/{urllib.parse.quote(self.realm)}/users"
        created = skipped = failed = 0

        if not os.path.exists(self.dataset_dir):
            print(f"[!] Dataset directory not found: {self.dataset_dir}")
            return

        datasets = [f"{self.dataset_dir}/rba-dataset+0.csv"]

        for csv_path in datasets: # glob.glob(f"{self.dataset_dir}/*.csv")
            print(f"→ Processing {csv_path}")
            print(f"→ Creating Keycloak users")
            df = pd.read_csv(csv_path)
            for uid in df["User ID"].dropna().astype(str).unique():
                payload = {"username": uid, "enabled": True}
                r = requests.post(endpoint, headers=self.headers, json=payload, timeout=10)

                if r.status_code == 201:
                    created += 1
                    #print(f"  [+] Created user {uid}")
                elif r.status_code == 409:
                    skipped += 1
                else:
                    failed += 1
                    #print(f"  [!] Failed for {uid}: {r.status_code} {r.text}")

        print(f"\n[✓] User creation complete → {created} created")

