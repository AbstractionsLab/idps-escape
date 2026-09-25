from __future__ import annotations

import argparse
import sys
from pathlib import Path

from wazuh_api import envfile

AR_ENV_KEYS = [
    "OS_URL", "OS_USER", "OS_PASS", "OS_VERIFY_SSL", "OS_INDEXES",
    "WAZUH_API_URL", "WAZUH_AUTH_USER", "WAZUH_AUTH_PASS", "WAZUH_VERIFY_SSL", "WAZUH_TIMEOUT_SEC",
    "DECIPHER_BASE_URL", "DECIPHER_VERIFY_SSL", "DECIPHER_TIMEOUT_SEC",
    "SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "SMTP_STARTTLS", "EMAIL_FROM", "EMAIL_TO",
    "AR_LOG_FILE", "AR_RISK_CONFIG", "AR_DEBUG_LOG", "AR_OSSEC_ROOT",
    "AR_CONTEXT_QUERY_ATTEMPTS", "AR_CONTEXT_QUERY_RETRY_SECONDS",
    "WEBHOOK_AGENT_NAME", "AD_ALERTS_LOCATION", "RADAR_MANAGER_ADDRESS",
]

FINAL_MODE = 0o440
FINAL_OWNER = "root:wazuh"


def build(env: dict, overrides: dict | None = None) -> dict:
    merged = dict(env)
    for k, v in (overrides or {}).items():
        if v:
            merged[k] = v
    return {k: merged[k] for k in AR_ENV_KEYS if k in merged}


def write(path, env: dict, overrides: dict | None = None) -> None:
    envfile.write_filtered(path, build(env, overrides), AR_ENV_KEYS, mode=0o600)


def _cli(argv) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m wazuh_api.ar_env")
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("write", help="write a filtered active_responses.env")
    w.add_argument("out")
    w.add_argument("--env-file", default=".env")
    w.add_argument("--os-url", default="")
    w.add_argument("--manager-address", default="")
    a = ap.parse_args(argv)
    env = envfile.load(Path(a.env_file))
    write(a.out, env, {"OS_URL": a.os_url, "RADAR_MANAGER_ADDRESS": a.manager_address})
    return 0


if __name__ == "__main__":
    sys.exit(_cli(sys.argv[1:]))
