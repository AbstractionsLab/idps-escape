"""
The SONAR event: one anomalous bucket as a single-line JSON object for the Wazuh manager.

Wazuh's JSON decoder puts every field under ``data.*`` in the alert. ``data.anomaly_grade``
and ``data.anomaly_confidence`` are the fields RADAR's active response reads for anomaly
scenarios (``resolve_ad_scores``), so a SONAR alert can drive RADAR through ``ar.yaml`` alone.
``integration: sonar`` and ``sonar.severity_band`` are what the rules in
``sonar/wazuh/rules/sonar_rules.xml`` match on.
"""

import json
from typing import Any, Dict

from sonar.indexer import json_safe
from sonar.watermark import bucket_timestamp

INTEGRATION = "sonar"
# Sent when a scenario has no measured anomaly_confidence yet.
DEFAULT_ANOMALY_CONFIDENCE = 0.5


def severity_band(severity: float, medium: float = 0.5, high: float = 0.8) -> str:
    """``low``, ``medium`` or ``high``: Wazuh rules match strings, they cannot compare numbers."""
    if severity >= high:
        return "high"
    if severity >= medium:
        return "medium"
    return "low"


def wazuh_event(doc: Dict[str, Any], medium: float = 0.5, high: float = 0.8) -> Dict[str, Any]:
    """The Wazuh event for one anomaly document."""
    severity = float(doc.get("anomaly_score") or 0.0)
    confidence = doc.get("anomaly_confidence")
    bucket_start = bucket_timestamp(doc["timestamp"])
    return {
        "integration": INTEGRATION,
        "anomaly_grade": severity,
        "anomaly_confidence": float(DEFAULT_ANOMALY_CONFIDENCE if confidence is None else confidence),
        "sonar": {
            "anomaly_id": doc.get("anomaly_id"),
            "scenario": doc.get("scenario_name"),
            "model": doc.get("model_name"),
            "bucket_start": bucket_start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "bucket_minutes": doc.get("bucket_minutes"),
            "severity": severity,
            "severity_band": severity_band(severity, medium, high),
            "score": doc.get("mvad_score"),
            "top_contributors": [{"variable": c.get("variable"), "contribution": c.get("contribution"), "value": c.get("value")} for c in doc.get("mvad_interpretation") or []],
        },
    }


def event_line(event: Dict[str, Any]) -> str:
    """One line of JSON; NaN becomes null (NaN is not JSON, and the manager's decoder rejects it)."""
    return json.dumps(json_safe(event), separators=(",", ":"), allow_nan=False)
