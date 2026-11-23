"""The off-hours step added to the archives Filebeat pipeline file."""

import json
import re
import shutil
from pathlib import Path

import pytest
from wazuh_api import cli
from wazuh_api.filebeat_pipeline import PipelineFileError, add_step

RADAR = Path(__file__).resolve().parents[2]
ARCHIVES = RADAR / "config/wazuh_cluster/pipeline-archives.json"
STEP = RADAR / "scenarios/pipelines/suspicious_login/radar-off-hours-step.json"
# The log_volume patch in manager-apply-scenario.sh (perl, same pattern) must still match after our rewrite.
LOG_VOLUME_RE = re.compile(
    r'\{\s*"date_index_name"\s*:\s*\{.*?"index_name_prefix"\s*:\s*"\{\{fields\.index_prefix\}\}".*?"ignore_failure"\s*:\s*(true|false)\s*\}\s*\},',
    re.S,
)


@pytest.fixture
def pipeline(tmp_path):
    path = tmp_path / "pipeline.json"
    shutil.copy(ARCHIVES, path)
    return path


def test_shipped_step_is_safe_for_a_dropping_pipeline():
    step = json.loads(STEP.read_text())
    assert step == {"pipeline": {"tag": "radar_off_hours", "name": "radar-off-hours", "if": "ctx.data != null", "ignore_failure": True}}
    assert json.loads(ARCHIVES.read_text())["on_failure"] == [{"drop": {}}]  # why ignore_failure is required


def test_add_is_idempotent_and_in_place(pipeline):
    step = json.loads(STEP.read_text())
    before = json.loads(pipeline.read_text())
    inode = pipeline.stat().st_ino
    assert add_step(pipeline, step) == "added"
    assert add_step(pipeline, step) == "unchanged"
    after = json.loads(pipeline.read_text())
    assert after["processors"][:-1] == before["processors"] and after["processors"][-1] == step
    assert after["on_failure"] == before["on_failure"] and after["description"] == before["description"]
    assert pipeline.stat().st_ino == inode


def test_changed_step_replaces_the_old_one(pipeline):
    step = json.loads(STEP.read_text())
    add_step(pipeline, step)
    newer = {"pipeline": dict(step["pipeline"], name="radar-off-hours-v2")}
    assert add_step(pipeline, newer) == "updated"
    tags = [next(iter(p.values())).get("tag") for p in json.loads(pipeline.read_text())["processors"]]
    assert tags.count("radar_off_hours") == 1


def test_log_volume_patch_still_applies_after_rewrite(pipeline):
    add_step(pipeline, json.loads(STEP.read_text()))
    assert LOG_VOLUME_RE.search(pipeline.read_text())


def test_rejects_untagged_steps_and_bad_files(tmp_path, pipeline):
    with pytest.raises(PipelineFileError):
        add_step(pipeline, {"pipeline": {"name": "x"}})
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(PipelineFileError):
        add_step(bad, json.loads(STEP.read_text()))


def test_cli_prints_the_outcome(pipeline, capsys):
    assert cli.main(["filebeat-pipeline-add-step", str(pipeline), str(STEP)]) == 0
    assert capsys.readouterr().out.strip() == "added"
    assert cli.main(["filebeat-pipeline-add-step", str(pipeline), str(STEP)]) == 0
    assert capsys.readouterr().out.strip() == "unchanged"
    assert cli.main(["filebeat-pipeline-add-step", str(pipeline / "missing"), str(STEP)]) == 1
