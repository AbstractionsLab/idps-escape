"""Add a scenario's processor to the Wazuh archives Filebeat pipeline file.

The file is bind-mounted into the manager container as a single file, so it is
rewritten in place (same inode): replacing it with a new file would leave the
container reading the old one until the container is recreated.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PipelineFileError(ValueError):
    """The pipeline file or the step file is not what this helper expects."""


def _processor_tag(processor: dict[str, Any]) -> str | None:
    if not isinstance(processor, dict) or len(processor) != 1:
        return None
    body = next(iter(processor.values()))
    return body.get("tag") if isinstance(body, dict) else None


def add_step(pipeline_path: Path, step: dict[str, Any]) -> str:
    """Append `step` to the pipeline's processors, keyed by its tag.

    Returns "added", "updated" (a step with the same tag differed) or "unchanged".
    """
    tag = _processor_tag(step)
    if not tag:
        raise PipelineFileError("the step must be a single processor with a tag")
    try:
        pipeline = json.loads(pipeline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineFileError(f"cannot read {pipeline_path}: {exc}") from exc
    processors = pipeline.get("processors") if isinstance(pipeline, dict) else None
    if not isinstance(processors, list):
        raise PipelineFileError(f"{pipeline_path} has no processors list")

    same = [i for i, p in enumerate(processors) if _processor_tag(p) == tag]
    if same and processors[same[0]] == step and len(same) == 1:
        return "unchanged"
    for i in reversed(same):
        del processors[i]
    processors.append(step)
    with pipeline_path.open("r+", encoding="utf-8") as f:  # in place: keep the bind-mounted inode
        f.seek(0)
        f.write(json.dumps(pipeline, indent=2) + "\n")
        f.truncate()
    return "updated" if same else "added"
