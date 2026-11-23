import re
import stat
from pathlib import Path

from wazuh_api import ar_env, envfile

ROOT = Path(__file__).resolve().parents[2]


def test_key_list_matches_what_radar_ar_reads():
    src = (ROOT / "scenarios/active_responses/radar_ar.py").read_text()
    used = set(re.findall(r'os\.environ\.get\("([A-Z_]+)"', src)) | set(re.findall(r'os\.environ\["([A-Z_]+)"\]', src))
    assert used == set(ar_env.AR_ENV_KEYS)


def test_unrelated_secrets_are_not_copied(tmp_path):
    env = {"OS_PASS": "a", "WAZUH_AUTH_PASS": "b", "MAXMIND_LICENSE_KEY": "m", "WAZUH_CLUSTER_KEY": "c",
           "WEBHOOK_SHARED_SECRET": "w", "DASHBOARD_PASS": "d", "SMTP_PASS": "s", "OS_URL": "https://x:9200"}
    out = tmp_path / "active_responses.env"
    ar_env.write(out, env, {"OS_URL": "https://wazuh.indexer:9200", "RADAR_MANAGER_ADDRESS": "10.0.0.5"})
    got = envfile.load(out)
    assert got == {"OS_PASS": "a", "WAZUH_AUTH_PASS": "b", "SMTP_PASS": "s",
                   "OS_URL": "https://wazuh.indexer:9200", "RADAR_MANAGER_ADDRESS": "10.0.0.5"}
    assert stat.S_IMODE(out.stat().st_mode) == 0o600