import time
import json
import random
import requests
import geoip2.database
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
from setup.config_loader import AppConfig

class SuspiciousLoginSimulator:
    def __init__(self, app_config: AppConfig):
        self.keycloak_admin_user = app_config.keycloak_admin_user
        self.keycloak_admin_pass = app_config.keycloak_admin_pass
        self.username = app_config.keycloak_username
        self.password = app_config.keycloak_password
        self.realm = app_config.keycloak_realm
        self.keycloak_url = app_config.keycloak_base_url
        self.geoip_db_path = app_config.geoip_db_path
        self.es_url = app_config.opensearch_url
        self.es_user = app_config.opensearch_user
        self.es_pass = app_config.opensearch_pass
        self.ca_cert = app_config.opensearch_verify_ssl

    def get_token(self):
        url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
        res = requests.post(url, data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": self.username,
            "password": self.password
        })
        res.raise_for_status()
        return res.json()["access_token"]

    def get_admin_token(self):
        url = f"{self.keycloak_url}/realms/master/protocol/openid-connect/token"
        res = requests.post(url, data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": self.keycloak_admin_user,
            "password": self.keycloak_admin_pass
        })
        res.raise_for_status()
        return res.json()["access_token"]

    def simulate_normal_behavior(self):
        print("[*] Simulating 5 minutes of normal behavior (real-time)...")
        token = self.get_admin_token()
        reader = geoip2.database.Reader(self.geoip_db_path)

        ip = "213.180.193.3"  # Poland
        for i in range(5):
            now = datetime.utcnow().replace(second=0, microsecond=0)
            iso_ts = now.isoformat()
            index_name = f"wazuh-ad-suspicious-login-{now.strftime('%Y.%m.%d')}"
            event_hour = now.hour

            try:
                geo = reader.city(ip)
                country = geo.country.iso_code or "PL"
                region = geo.subdivisions[0].name if geo.subdivisions else "-"
                city = geo.city.name or "-"
            except Exception:
                country, region, city = "PL", "-", "-"

            doc = {
                "Login Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "User ID": self.username,
                "Round-Trip Time [ms]": "",
                "IP Address": ip,
                "Country": country,
                "Region": region,
                "City": city,
                "ASN": "-",
                "User Agent String": "Chrome/112",
                "Browser Name and Version": "Chrome 112",
                "OS Name and Version": "Windows 10",
                "Device Type": "desktop",
                "Login Successful": "True",
                "Is Attack IP": "False",
                "Is Account Takeover": "False",
                "@timestamp": iso_ts,
                "event_hour": event_hour,
                "agent.name": "agent.suspicious"
            }

            bulk_payload = json.dumps({"index": {"_index": index_name}}) + "\n"
            bulk_payload += json.dumps(doc) + "\n"

            resp = requests.post(
                f"{self.es_url}/_bulk?refresh=true",
                data=bulk_payload,
                auth=HTTPBasicAuth(self.es_user, self.es_pass),
                headers={"Content-Type": "application/x-ndjson"},
                verify=self.ca_cert,
            )
            resp.raise_for_status()
            print(f"[+] Normal login {i+1}/5 injected at {iso_ts}")
            time.sleep(60)  # wait 1 minute

        print("[✓] Completed 5 minutes of normal behavior.")

    def simulate_abrupt_anomaly(self):
        print("[*] Injecting abrupt anomaly burst...")
        token = self.get_admin_token()
        reader = geoip2.database.Reader(self.geoip_db_path)

        spoof_ips = [
            "8.8.8.8", "202.108.22.5", "139.130.4.5", "41.206.16.130",
            "186.33.216.3", "2.16.5.23", "124.6.181.23", "5.79.97.178", "190.92.86.5"
        ]

        now = datetime.utcnow().replace(second=0, microsecond=0)
        iso_ts = now.isoformat()
        index_name = f"wazuh-ad-suspicious-login-{now.strftime('%Y.%m.%d')}"
        event_hour = 2
        bulk_payload = ""

        for ip in spoof_ips:
            try:
                geo = reader.city(ip)
                country = geo.country.iso_code or "UNKNOWN"
                region = geo.subdivisions[0].name if geo.subdivisions else "-"
                city = geo.city.name or "-"
            except Exception:
                country, region, city = "UNKNOWN", "-", "-"

            doc = {
                "Login Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "User ID": self.username,
                "Round-Trip Time [ms]": "",
                "IP Address": ip,
                "Country": country,
                "Region": region,
                "City": city,
                "ASN": "-",
                "User Agent String": "Simulated",
                "Browser Name and Version": "Simulated",
                "OS Name and Version": "Simulated",
                "Device Type": "desktop",
                "Login Successful": "True",
                "Is Attack IP": "True",
                "Is Account Takeover": "True",
                "@timestamp": iso_ts,
                "event_hour": event_hour,
                "agent.name": "agent.suspicious"
            }

            bulk_payload += json.dumps({"index": {"_index": index_name}}) + "\n"
            bulk_payload += json.dumps(doc) + "\n"

        if bulk_payload:
            resp = requests.post(
                f"{self.es_url}/_bulk?refresh=true",
                data=bulk_payload,
                auth=HTTPBasicAuth(self.es_user, self.es_pass),
                headers={"Content-Type": "application/x-ndjson"},
                verify=self.ca_cert,
            )
            resp.raise_for_status()
            print("[✓] Anomalous burst injected at", iso_ts)
        else:
            print("[!] No anomaly payload created.")

    def simulate_full_attack_scenario(self):
        self.simulate_normal_behavior()
        time.sleep(300)
        self.simulate_abrupt_anomaly()


    def simulate_logins(self, num_logins=50):
        print(f"[+] Simulating {num_logins} login attempts using Keycloak API...")
        for i in range(num_logins):
            try:
                self.get_token()
                print(f"[Login {i + 1}] Success")
            except Exception as e:
                print(f"[Login {i + 1}] Failed: {e}")
            #time.sleep(1.0)

    def collect_and_send_logs(self):
        token = self.get_admin_token()

        spoof_ips = [
            "8.8.8.8",
            "139.130.4.5",
            "213.180.193.3",
            "202.108.22.5",
            "41.206.16.130",
        ]

        headers = {"Authorization": f"Bearer {token}"}
        all_events = []
        page = 0
        page_size = 100

        # Pagination loop to collect all events
        while True:
            url = f"{self.keycloak_url}/admin/realms/{self.realm}/events?first={page * page_size}&max={page_size}"
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            events = resp.json()
            if not events:
                break
            all_events.extend(events)
            page += 1

        print(f"[✓] Total login events collected: {len(all_events)}")

        reader = geoip2.database.Reader(self.geoip_db_path)
        bulk_payload = ""

        for event in all_events:
            if not event.get("type", "").startswith("LOGIN"):
                continue

            ts_obj = datetime.fromtimestamp(event["time"] / 1000)
            adjusted_ts = ts_obj - timedelta(hours=2)
            iso_ts = adjusted_ts.isoformat()
            login_timestamp_str = adjusted_ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            event_hour = adjusted_ts.hour
            index_name = f"wazuh-ad-suspicious-login-{ts_obj.strftime('%Y.%m.%d')}"

            ip = random.choice(spoof_ips)

            try:
                geo = reader.city(ip)
                country = geo.country.iso_code or "UNKNOWN"
                region = geo.subdivisions[0].name if geo.subdivisions else "-"
                city = geo.city.name or "-"
            except Exception:
                country, region, city = "UNKNOWN", "-", "-"

            login_successful = "True" if event.get("type") == "LOGIN" else "False"

            doc = {
                "Login Timestamp": login_timestamp_str,
                "User ID": self.username,
                "Round-Trip Time [ms]": "",
                "IP Address": ip,
                "Country": country,
                "Region": region,
                "City": city,
                "ASN": "-",
                "User Agent String": "Simulated",
                "Browser Name and Version": "Simulated",
                "OS Name and Version": "Simulated",
                "Device Type": "desktop",
                "Login Successful": login_successful,
                "Is Attack IP": "True",
                "Is Account Takeover": "True",
                "@timestamp": iso_ts,
                "event_hour": 2,
                "agent.name": "agent.suspicious"
            }

            bulk_payload += json.dumps({"index": {"_index": index_name}}) + "\n"
            bulk_payload += json.dumps(doc) + "\n"

        if not bulk_payload:
            print("[!] No valid login events found to index.")
            return

        resp = requests.post(
            f"{self.es_url}/_bulk?refresh=true",
            data=bulk_payload,
            auth=HTTPBasicAuth(self.es_user, self.es_pass),
            headers={"Content-Type": "application/x-ndjson"},
            verify=self.ca_cert,
        )
        resp.raise_for_status()

        result = resp.json()
        if result.get("errors"):
            print("Errors occurred during bulk insert:", result["items"])
        else:
            print(f"[✓] Indexed {len(all_events)} login events to Wazuh.")
