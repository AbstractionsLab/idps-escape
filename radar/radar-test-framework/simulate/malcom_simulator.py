import random
import json
import requests
from datetime import datetime, timedelta

class MalwareC2Simulator:
    def __init__(self, app_config):
        self.opensearch_url = app_config.opensearch_url
        self.auth = (app_config.opensearch_user, app_config.opensearch_pass)
        self.verify_cert = app_config.opensearch_verify_ssl
        self.container_name = app_config.scenario_config["malware_communication"]["container_name"]
        self.index_prefix = app_config.scenario_config["malware_communication"]["index_prefix"]
        self.target_ip = self.get_container_ip(self.container_name)
        self.ingest_url = f"{self.opensearch_url}/{self.index_prefix}-" + datetime.utcnow().strftime("%Y.%m.%d") + "/_bulk"

    def get_container_ip(self, container_name):
        import subprocess
        cmd = f"docker inspect -f '{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {container_name}"
        return subprocess.check_output(cmd, shell=True).decode().strip()

    def generate_event(self, ts, uid, dst_ip, dst_port, conn_interval):
        orig_bytes = 150
        resp_bytes = 150
        duration = round(random.uniform(0.01, 5.0), 6)
        conn_state = "S0"
        history = "Sh"
        label = "Malware-C2"
        detailed_label = "C2-Heartbeat"
        print(self.target_ip)

        return {
            "ts": ts.timestamp(),
            "uid": uid,
            "id.orig_h": self.target_ip,
            "id.orig_p": random.randint(30000, 60000),
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "proto": "udp",
            "service": "dns",
            "duration": duration,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "conn_interval": conn_interval,
            "conn_state": conn_state,
            "local_orig": False,
            "local_resp": True,
            "missed_bytes": 0,
            "history": history,
            "orig_pkts": 1,
            "orig_ip_bytes": orig_bytes + 20,
            "resp_pkts": 1,
            "resp_ip_bytes": resp_bytes + 20,
            "label": label,
            "detailed-label": detailed_label,
            "timestamp_readable": ts.isoformat(),
            "@timestamp": ts.isoformat()
        }

    def simulate_attack(self, count=30, interval_seconds=60, dst_ip="8.8.8.8", dst_port=8081):
        now = datetime.utcnow()
        docs = []
        for i in range(count):
            ts = now + timedelta(seconds=i * interval_seconds)
            uid = f"C2-ATTACK-{i}"
            doc = self.generate_event(ts, uid, dst_ip, dst_port, conn_interval=interval_seconds)
            meta = {"index": {"_index": f"{self.index_prefix}-{now.strftime('%Y.%m.%d')}"}}
            docs.append(json.dumps(meta))
            docs.append(json.dumps(doc))

        bulk_payload = "\n".join(docs) + "\n"
        response = requests.post(
            self.ingest_url,
            headers={"Content-Type": "application/x-ndjson"},
            data=bulk_payload,
            auth=self.auth,
            verify=self.verify_cert
        )
        return response.status_code, response.text

