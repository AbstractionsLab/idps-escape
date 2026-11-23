"""
Post-processing: from detector verdicts (``PointResult``) to anomaly documents.

This module is the single owner of the anomaly document schema. The index templates in
``sonar/shipper/wazuh_base_template.py`` must map the fields built here
(``tests/sonartests/test_shipper.py`` checks it).
"""

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

import pandas as pd

from sonar.backends.base import PointResult
from sonar.config import FeatureConfig
from sonar.watermark import anomaly_id

# Contributors (MVAD interpretation entries) copied into each document.
TOP_CONTRIBUTORS = 3


class MVADPostProcessor:
    """Convert a backend's verdicts (PointResult) into anomaly documents."""

    def __init__(self, feature_cfg: FeatureConfig):
        """
        Initialize post-processor.

        Args:
            feature_cfg: FeatureConfig the features were built with.
        """
        self.feature_cfg = feature_cfg

    def build_wazuh_anomaly_docs(
        self,
        results: Sequence[PointResult],
        context: Dict[str, Any],
        threshold: Optional[float] = None,
        min_consecutive: int = 1,
        feature_values: Optional[pd.DataFrame] = None,
    ) -> List[Dict[str, Any]]:
        """
        Turn a backend's verdicts into anomaly documents.

        ``severity`` (0-1, and 0 for buckets the backend does not flag) is what thresholds
        and consumers compare; ``raw_score`` is the backend's own score and scale.

        Args:
            results: One PointResult per scored bucket, in time order.
            context: Detection context: ``scenario_id`` (also the namespace of each document's
                ``anomaly_id``), ``model_name``, ``model_path``, ``feature_names``,
                ``training_samples``, ``sliding_window``, ``bucket_minutes``,
                ``lookback_minutes``, ``alert_count``, ``anomaly_confidence``.
            threshold: Minimum ``severity`` (0-1) a bucket needs, in addition to the backend's
                own ``is_anomaly`` decision, to be reported. ``None`` means the backend's decision alone.
            min_consecutive: Minimum length of a run of consecutive qualifying buckets;
                shorter runs are dropped. Values below 1 are treated as 1.
            feature_values: The feature matrix that was scored; when given, each contributor
                carries the feature's value in that bucket.

        Returns:
            One document per reported bucket.

        Raises:
            ValueError: If ``threshold`` is outside [0, 1] or the results are not PointResults.
        """
        if threshold is not None and not 0.0 <= float(threshold) <= 1.0:
            raise ValueError(f"threshold is a minimum severity between 0 and 1; got {threshold}")
        if not isinstance(results, (list, tuple)) or not all(isinstance(r, PointResult) for r in results):
            raise ValueError("Detection results must be a list of PointResult (see sonar.backends)")

        threshold_value = float(threshold) if threshold is not None else None
        keep = select_anomalies(results, threshold_value, min_consecutive)

        scenario_id = context.get("scenario_id", "unknown")
        feature_names = list(context.get("feature_names") or [])
        bucket_minutes = context.get("bucket_minutes", self.feature_cfg.bucket_minutes)
        detected_at = datetime.now(timezone.utc).isoformat()

        docs: List[Dict[str, Any]] = []
        for result, kept in zip(results, keep):
            if not kept:
                continue
            ts = result.timestamp
            ts_iso = ts.isoformat()
            doc = {
                # Same scenario and bucket, same id: sinks store by it, so re-delivery is harmless.
                "anomaly_id": anomaly_id(scenario_id, ts),
                "@timestamp": ts_iso,
                "timestamp": ts_iso,
                # Required top-level fields for data stream template
                "is_anomaly": True,
                "anomaly_score": result.severity,
                # Trust in this scenario's anomalies (its measured precision), for consumers such as RADAR.
                "anomaly_confidence": context.get("anomaly_confidence"),
                "threshold": threshold_value,
                "scenario_name": scenario_id,
                "model_name": context.get("model_name", ""),
                "detection_timestamp": detected_at,
                "alert_count": context.get("alert_count", 0),
                "feature_count": len(feature_names),
                # Backend fields (named mvad_* since MVAD was the first backend)
                "mvad_score": result.raw_score,
                "mvad_severity": result.severity,
                "mvad_threshold": threshold_value,
                "sliding_window": context.get("sliding_window", 0),
                "bucket_minutes": bucket_minutes,
                "context": {
                    "model_path": context.get("model_path", ""),
                    "feature_names": feature_names,
                    "training_samples": context.get("training_samples", 0),
                },
                "data": {
                    "mvad_score": result.raw_score,
                    "mvad_severity": result.severity,
                    "mvad_threshold": threshold_value,
                    "bucket_minutes": bucket_minutes,
                    "lookback_minutes": context.get("lookback_minutes"),
                },
            }
            if result.contributors:
                doc["mvad_interpretation"] = [{"variable": c.variable, "contribution": float(c.contribution), "value": _feature_value(feature_values, ts, c.variable)} for c in result.contributors[:TOP_CONTRIBUTORS]]
            docs.append(doc)

        return docs


def select_anomalies(results: Sequence[PointResult], threshold: Optional[float] = None, min_consecutive: int = 1) -> List[bool]:
    """
    Which buckets are reported: the decision rule shared by detection and ``sonar evaluate``.

    A bucket qualifies when the backend flags it and its severity reaches ``threshold``
    (``None``: the backend's decision alone); only runs of at least ``min_consecutive``
    consecutive qualifying buckets are kept (values below 1 count as 1).

    Returns:
        One boolean per result, in order.
    """
    min_run = max(1, int(min_consecutive or 1))
    qualifies = [r.is_anomaly and (threshold is None or r.severity >= threshold) for r in results]
    keep = [False] * len(results)
    run_start = None
    for i, q in enumerate(qualifies + [False]):
        if q and run_start is None:
            run_start = i
        elif not q and run_start is not None:
            if i - run_start >= min_run:
                for j in range(run_start, i):
                    keep[j] = True
            run_start = None
    return keep


def _feature_value(frame: Optional[pd.DataFrame], ts: Any, column: Optional[str]) -> Optional[float]:
    """Value of a feature in the scored bucket, or None if unavailable."""
    if frame is None or column is None or column not in frame.columns:
        return None
    try:
        value = float(frame.at[pd.Timestamp(ts), column])
    except (KeyError, TypeError, ValueError):
        return None
    return None if math.isnan(value) else value
