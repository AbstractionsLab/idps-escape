"""
Anomaly sinks and their orchestration.

``output.sinks`` lists where every anomaly goes. Each sink has its own delivery watermark
(``sonar/watermark.py``): it is offered only the anomalies after its watermark, and the
watermark advances over the ones it accepted. A sink that fails is offered the missed
anomalies again on the next run, while the others are not, which keeps sinks without
deduplication (the Wazuh manager) free of duplicates. ``output.fallback`` takes what a sink
rejected, so it is stored somewhere in the meantime.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from sonar.sinks.base import AnomalySink, DeliveryResult
from sonar.watermark import Watermark, bucket_timestamp

logger = logging.getLogger(__name__)

SINK_NAMES = ("wazuh", "datastream", "index", "jsonl", "stdout")
FALLBACK_NAMES = ("none", "datastream", "index")

__all__ = ["AnomalySink", "DeliveryResult", "DeliveryReport", "SINK_NAMES", "FALLBACK_NAMES", "deliver"]


@dataclass
class DeliveryReport:
    """What one run's delivery achieved, per sink."""

    results: Dict[str, DeliveryResult] = field(default_factory=dict)
    fallback: Optional[DeliveryResult] = None

    @property
    def failed(self) -> List[str]:
        return [name for name, r in self.results.items() if not r.ok]

    @property
    def all_failed(self) -> bool:
        """Every sink that had anomalies to deliver failed, and no fallback took them all."""
        if not self.results or not self.failed:
            return False
        if len(self.failed) < len(self.results):
            return False
        return not (self.fallback is not None and self.fallback.ok)


def deliver(docs: List[Dict[str, Any]], sinks: List[AnomalySink], watermark: Optional[Watermark] = None, fallback: Optional[AnomalySink] = None) -> DeliveryReport:
    """
    Deliver anomaly documents (oldest bucket first) to every sink.

    Args:
        docs: Anomaly documents of one run.
        sinks: Configured sinks.
        watermark: Per-sink delivery watermarks; None delivers everything and records nothing
            (debug and dry runs).
        fallback: Sink for the documents a configured sink did not accept.

    Returns:
        The result per sink that had something to deliver, and the fallback's result.
    """
    report = DeliveryReport()
    rejected: Dict[str, Dict[str, Any]] = {}
    for sink in sinks:
        last = watermark.load(sink.name) if watermark is not None else None
        pending = [d for d in docs if last is None or bucket_timestamp(d["timestamp"]) > last]
        if len(pending) < len(docs):
            logger.info("%s: %d anomalies at or before %s were delivered by an earlier run; skipping them.", sink.name, len(docs) - len(pending), last.isoformat())
        if not pending:
            continue
        try:
            result = sink.emit(pending)
        except Exception as e:  # a sink must report failures, but never let one sink stop the others
            logger.exception("Sink %s raised.", sink.name)
            result = DeliveryResult(0, len(pending), str(e))
        report.results[sink.name] = result
        if result.accepted and watermark is not None:
            stored = watermark.advance(sink.name, pending[result.accepted - 1]["timestamp"])
            logger.info("%s: delivered %d anomalies; watermark %s.", sink.name, result.accepted, stored.isoformat())
        if not result.ok:
            logger.error("%s: %d of %d anomalies not delivered (%s); the next run offers them again.", sink.name, result.total - result.accepted, result.total, result.error)
            for d in pending[result.accepted :]:
                rejected[d.get("anomaly_id") or d["timestamp"]] = d

    if rejected and fallback is not None and fallback.name not in report.results:
        batch = sorted(rejected.values(), key=lambda d: bucket_timestamp(d["timestamp"]))
        try:
            report.fallback = fallback.emit(batch)
        except Exception as e:
            report.fallback = DeliveryResult(0, len(batch), str(e))
        if report.fallback.ok:
            logger.warning("Fallback %s stored the %d undelivered anomalies.", fallback.name, len(batch))
        else:
            logger.error("Fallback %s failed too (%s).", fallback.name, report.fallback.error)
    return report
