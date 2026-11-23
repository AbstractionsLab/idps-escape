import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def sandbox(tmp_path):
    root = tmp_path / "radar"
    shutil.copytree(ROOT / "radar_deploy", root / "radar_deploy")
    shutil.copytree(ROOT / "wazuh_api", root / "wazuh_api", ignore=shutil.ignore_patterns("__pycache__"))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker.log"
    (bin_dir / "docker").write_text(f"""#!/usr/bin/env bash
echo "docker $*" >> "{log}"
if [[ "$*" == *" -i "* ]]; then cat > "{tmp_path}/stdin.txt"; fi
exit 0
""")
    os.chmod(bin_dir / "docker", 0o755)
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path)}
    return root, env, log, tmp_path


def _run(script, args, root, env):
    return subprocess.run(["bash", str(root / "radar_deploy" / script), *args],
                          capture_output=True, text=True, env=env, cwd=root)


def _state(root, expires_at):
    d = root / ".radar-state"
    d.mkdir(exist_ok=True)
    (d / "enrollment-token.expires").write_text(f"{expires_at} wazuh.manager\n")
    return d / "enrollment-token.expires"


@pytest.mark.parametrize("bad", ["1;id", "a[$(id)]", "0", "01", "99999", "-5"])
def test_mint_rejects_bad_expiry_before_touching_docker(sandbox, bad):
    root, env, log, _ = sandbox
    r = _run("manager-mint-token.sh", ["default", bad], root, env)
    assert r.returncode == 2 and "expiry_minutes" in r.stderr
    assert not log.exists()


def test_unexpired_token_is_left_alone(sandbox):
    root, env, log, _ = sandbox
    state = _state(root, int(time.time()) + 600)
    r = _run("manager-revoke-token.sh", ["--if-expired"], root, env)
    assert r.returncode == 0 and not log.exists() and state.exists()


def test_expired_token_is_revoked(sandbox):
    root, env, log, tmp = sandbox
    state = _state(root, int(time.time()) - 5)
    r = _run("manager-revoke-token.sh", ["--if-expired"], root, env)
    assert r.returncode == 0, r.stderr
    calls = log.read_text()
    assert "exec -i -u root wazuh.manager sh -c" in calls and "wazuh-control restart" in calls
    assert len((tmp / "stdin.txt").read_text()) >= 32
    assert not state.exists()