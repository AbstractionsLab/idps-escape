"""
Delivery watermarks: the last anomalous bucket each sink has accepted, per scenario.

Detection re-scores overlapping windows (every realtime poll, every repeated ``sonar detect``),
so the same anomalous bucket is found again and again. The watermark makes delivery
at-most-once per bucket, scenario and sink: a sink receives only buckets after its watermark,
which advances over the buckets it accepted. It is a small JSON file per scenario, so it
survives restarts. Sinks that store documents by ``anomaly_id`` deduplicate as well, which
covers a crash between delivery and saving the watermark.
"""

import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Optional

import pandas as pd

logger = logging.getLogger(__name__)


def bucket_timestamp(value: Any) -> pd.Timestamp:
    """A bucket start as a UTC timestamp (naive values are taken to be UTC)."""
    ts = pd.Timestamp(value)
    return ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")


def anomaly_id(scenario_id: str, bucket_start: Any) -> str:
    """Deterministic identity of an anomalous bucket: the same scenario and bucket give the same id."""
    return hashlib.sha256(f"{scenario_id}|{bucket_timestamp(bucket_start).isoformat()}".encode("utf-8")).hexdigest()


class Watermark:
    """
    The last bucket each sink has accepted, for one scenario, stored in ``<state_dir>/<scenario_id>.json``.

    Each sink has its own watermark, so a sink that failed receives the missed anomalies
    again on the next run while the sinks that accepted them do not. That matters for sinks
    that cannot recognise a duplicate (the Wazuh manager).
    """

    def __init__(self, state_dir: str, scenario_id: str):
        self.scenario_id = scenario_id
        self.path = Path(state_dir) / f"{scenario_id}.json"

    def _read(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("not a JSON object")
            return data
        except (OSError, ValueError) as e:
            logger.warning("Ignoring unreadable delivery watermark %s (%s); anomalies may be delivered again.", self.path, e)
            return {}

    def load(self, sink: str) -> Optional[pd.Timestamp]:
        """
        The last bucket ``sink`` accepted, or None if it accepted nothing yet.

        An unreadable file is logged and treated as no watermark: anomalies are then
        delivered again (at-least-once) rather than lost.
        """
        data = self._read()
        value = (data.get("sinks") or {}).get(sink)
        try:
            return None if value is None else bucket_timestamp(value)
        except (TypeError, ValueError) as e:
            logger.warning("Ignoring unreadable delivery watermark for %s in %s (%s).", sink, self.path, e)
            return None

    def advance(self, sink: str, bucket_start: Any) -> pd.Timestamp:
        """Move ``sink``'s watermark to ``bucket_start`` unless it is already later; returns the stored value."""
        new = bucket_timestamp(bucket_start)
        current = self.load(sink)
        if current is not None and current >= new:
            return current
        data = self._read()
        sinks = dict(data.get("sinks") or {})
        sinks[sink] = new.isoformat()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"scenario_id": self.scenario_id, "sinks": sinks}, indent=2, sort_keys=True)
        # Write-then-rename, so a crash never leaves a half-written file behind.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return new
