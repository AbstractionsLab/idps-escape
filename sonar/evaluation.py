"""
Detection quality against labelled data (``sonar evaluate``).

A label file lists the attack or fault intervals injected into (or recorded in) a dataset:

.. code-block:: json

    {"format": "sonar-labels/1", "dataset": "resource_monitoring test split",
     "span": {"start": "2024-12-20T00:00:00Z", "end": "2024-12-21T00:00:00Z"},
     "events": [{"id": "cpu_spike_1", "type": "cpu_spike",
                 "start": "2024-12-20T03:10:00Z", "end": "2024-12-20T03:55:00Z"}]}

Detections are time intervals with a severity: SONAR's scored buckets, or the results of
another detector (the OpenSearch anomaly detection plugin, a generic export). Reported buckets
that touch each other form one *alarm*, the unit an analyst sees. With a tolerance ``tol``:

- an event is **detected** if an alarm overlaps ``[start - tol, end + tol)``;
- an alarm is a **true alarm** if it overlaps such a window of a counted event, a **false alarm**
  if it overlaps none, and is ignored if it overlaps only events of types not counted;
- precision = true alarms / (true + false alarms); recall = detected events / counted events;
- detection delay = time from an event's start to the end of the first reported bucket in its
  window (the earliest moment the detector could have reported it), at least 0;
- false alarms per day = false alarms / days of evaluated data.

Calibration picks the ``threshold`` (minimum severity) and ``min_consecutive`` with the best F1
on a validation split among those within a false-alarm budget; the scenario's
``anomaly_confidence`` is then the precision those values give on the test split.
"""

import json
import logging
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pandas as pd

from sonar.backends.base import PointResult
from sonar.pipeline import select_anomalies

logger = logging.getLogger(__name__)

LABELS_FORMAT = "sonar-labels/1"
REPORT_FORMAT = "sonar-evaluation/1"
DEFAULT_TOLERANCE_MINUTES = 0
DEFAULT_MAX_FALSE_ALARMS_PER_DAY = 5.0
# Calibration grid: None is the backend's own decision alone.
THRESHOLD_GRID: Tuple[Optional[float], ...] = (None,) + tuple(round(0.05 * i, 2) for i in range(1, 20))
MIN_CONSECUTIVE_GRID: Tuple[int, ...] = (1, 2, 3, 4, 5)


def _ts(value: Any) -> pd.Timestamp:
    """UTC timestamp from an ISO string, epoch milliseconds or a datetime."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return pd.Timestamp(int(value), unit="ms", tz="UTC")
    ts = pd.Timestamp(value)
    return ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")


def _iso(ts: pd.Timestamp) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------- labels ----------


@dataclass(frozen=True)
class LabelledEvent:
    """One labelled anomaly: an interval ``[start, end)`` and its type."""

    id: str
    type: str
    start: pd.Timestamp
    end: pd.Timestamp

    def to_dict(self) -> Dict[str, str]:
        return {"id": self.id, "type": self.type, "start": _iso(self.start), "end": _iso(self.end)}


@dataclass
class Labels:
    """The labelled events of a dataset and the time span the dataset covers."""

    events: List[LabelledEvent]
    span_start: Optional[pd.Timestamp] = None
    span_end: Optional[pd.Timestamp] = None
    dataset: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Labels":
        if data.get("format") not in (None, LABELS_FORMAT):
            raise ValueError(f"Unsupported label format {data.get('format')!r}; expected {LABELS_FORMAT}")
        events = []
        for i, e in enumerate(data.get("events") or []):
            start, end = _ts(e["start"]), _ts(e["end"])
            if end <= start:
                raise ValueError(f"Label {e.get('id', i)}: end {e['end']} is not after start {e['start']}")
            events.append(LabelledEvent(str(e.get("id", f"event_{i + 1}")), str(e.get("type", "anomaly")), start, end))
        span = data.get("span") or {}
        return cls(
            events=sorted(events, key=lambda ev: ev.start),
            span_start=_ts(span["start"]) if span.get("start") else None,
            span_end=_ts(span["end"]) if span.get("end") else None,
            dataset=str(data.get("dataset", "")),
        )

    @classmethod
    def from_file(cls, path: str) -> "Labels":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {"format": LABELS_FORMAT, "dataset": self.dataset}
        if self.span_start is not None and self.span_end is not None:
            data["span"] = {"start": _iso(self.span_start), "end": _iso(self.span_end)}
        data["events"] = [e.to_dict() for e in self.events]
        return data

    def write(self, path: str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")


# ---------- detections ----------


@dataclass(frozen=True)
class Detection:
    """A scored interval (one bucket): reported when ``is_anomaly`` and its severity pass the decision rule."""

    start: pd.Timestamp
    end: pd.Timestamp
    is_anomaly: bool
    severity: float


def detections_from_points(points: Sequence[PointResult], bucket_minutes: int) -> List[Detection]:
    """SONAR's verdicts as detections, one bucket each."""
    width = pd.Timedelta(minutes=int(bucket_minutes))
    return [Detection(_ts(p.timestamp), _ts(p.timestamp) + width, bool(p.is_anomaly), float(p.severity)) for p in points]


def load_external_detections(path: str) -> List[Detection]:
    """
    Detections exported from another detector.

    Accepts a JSON array, JSON lines, or an OpenSearch ``_search`` response (``hits.hits[]._source``)
    of either:

    - OpenSearch anomaly detection plugin results: ``data_start_time``, ``data_end_time``
      (epoch milliseconds or ISO) and ``anomaly_grade`` (> 0 means anomalous); or
    - generic records: ``start``, ``end`` and ``severity`` (0-1), optionally ``is_anomaly``.

    Records with an ``error`` field (the plugin's failed intervals) are skipped.
    """
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(data, dict):
        data = [h.get("_source", h) for h in data.get("hits", {}).get("hits", [])] if "hits" in data else [data]
    detections = []
    for record in data:
        record = record.get("_source", record)
        if record.get("error"):
            continue
        if "data_start_time" in record:
            grade = float(record.get("anomaly_grade") or 0.0)
            detections.append(Detection(_ts(record["data_start_time"]), _ts(record["data_end_time"]), grade > 0, grade))
        else:
            severity = float(record.get("severity", 1.0))
            detections.append(Detection(_ts(record["start"]), _ts(record["end"]), bool(record.get("is_anomaly", severity > 0)), severity))
    return sorted(detections, key=lambda d: d.start)


def reported(detections: Sequence[Detection], threshold: Optional[float], min_consecutive: int) -> List[Detection]:
    """The detections the decision rule reports (the same rule as ``sonar detect``)."""
    points = [PointResult(d.start, d.is_anomaly, d.severity, d.severity) for d in detections]
    return [d for d, keep in zip(detections, select_anomalies(points, threshold, min_consecutive)) if keep]


def alarms(detections: Sequence[Detection]) -> List[List[Detection]]:
    """Group reported intervals that touch or overlap into alarms."""
    groups: List[List[Detection]] = []
    for d in sorted(detections, key=lambda d: d.start):
        if groups and d.start <= groups[-1][-1].end:
            groups[-1].append(d)
        else:
            groups.append([d])
    return groups


# ---------- metrics ----------


@dataclass
class EventOutcome:
    id: str
    type: str
    start: str
    end: str
    detected: bool
    delay_minutes: Optional[float] = None


@dataclass
class Metrics:
    """Event-level detection quality on one labelled dataset."""

    events: int
    detected: int
    alarms: int
    true_alarms: int
    false_alarms: int
    days: float
    precision: Optional[float]
    recall: Optional[float]
    f1: float
    mean_delay_minutes: Optional[float]
    false_alarms_per_day: float
    outcomes: List[EventOutcome] = field(default_factory=list)
    ignored_events: int = 0
    unscored_events: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _overlaps(a_start: pd.Timestamp, a_end: pd.Timestamp, b_start: pd.Timestamp, b_end: pd.Timestamp) -> bool:
    return a_start < b_end and a_end > b_start


def score(
    detections: Sequence[Detection],
    labels: Labels,
    threshold: Optional[float] = None,
    min_consecutive: int = 1,
    tolerance_minutes: float = DEFAULT_TOLERANCE_MINUTES,
    event_types: Optional[Iterable[str]] = None,
) -> Metrics:
    """
    Event-level precision, recall, F1, delay and false alarms of ``detections`` against ``labels``.

    Only the time the detections cover, within the label file's span, is evaluated: events
    outside it are reported as ``unscored_events`` and not counted. Events whose type is not in ``event_types`` (when given)
    are neither counted nor turn the alarms on them into false alarms.
    """
    tol = pd.Timedelta(minutes=float(tolerance_minutes))
    if labels.span_start is not None and labels.span_end is not None:
        # Another detector may have scored more than the labelled data (its training period, say).
        detections = [d for d in detections if _overlaps(d.start, d.end, labels.span_start, labels.span_end)]
    if detections:
        covered_start, covered_end = min(d.start for d in detections), max(d.end for d in detections)
    else:
        covered_start, covered_end = labels.span_start, labels.span_end
    if covered_start is None or covered_end is None:
        raise ValueError("Nothing to evaluate: no detections and no span in the label file")
    days = (covered_end - covered_start) / pd.Timedelta(days=1)

    wanted = set(event_types) if event_types else None
    in_scope = [e for e in labels.events if _overlaps(e.start, e.end, covered_start, covered_end)]
    unscored = len(labels.events) - len(in_scope)
    counted = [e for e in in_scope if wanted is None or e.type in wanted]
    ignored = [e for e in in_scope if wanted is not None and e.type not in wanted]

    groups = alarms(reported(detections, threshold, min_consecutive))
    true_alarms = false_alarms = 0
    for group in groups:
        a_start, a_end = group[0].start, group[-1].end
        if any(_overlaps(a_start, a_end, e.start - tol, e.end + tol) for e in counted):
            true_alarms += 1
        elif not any(_overlaps(a_start, a_end, e.start - tol, e.end + tol) for e in ignored):
            false_alarms += 1

    outcomes, delays = [], []
    for e in counted:
        hits = [d for group in groups for d in group if _overlaps(d.start, d.end, e.start - tol, e.end + tol)]
        if hits:
            delay = max(0.0, (min(d.end for d in hits) - e.start) / pd.Timedelta(minutes=1))
            delays.append(delay)
            outcomes.append(EventOutcome(e.id, e.type, _iso(e.start), _iso(e.end), True, round(delay, 1)))
        else:
            outcomes.append(EventOutcome(e.id, e.type, _iso(e.start), _iso(e.end), False))

    detected = len(delays)
    precision = true_alarms / (true_alarms + false_alarms) if (true_alarms + false_alarms) else None
    recall = detected / len(counted) if counted else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else 0.0
    return Metrics(
        events=len(counted),
        detected=detected,
        alarms=true_alarms + false_alarms,
        true_alarms=true_alarms,
        false_alarms=false_alarms,
        days=round(days, 3),
        precision=_round(precision),
        recall=_round(recall),
        f1=round(f1, 4),
        mean_delay_minutes=round(sum(delays) / len(delays), 1) if delays else None,
        false_alarms_per_day=round(false_alarms / days, 3) if days > 0 else float(false_alarms),
        outcomes=outcomes,
        ignored_events=len(ignored),
        unscored_events=unscored,
    )


def _round(value: Optional[float]) -> Optional[float]:
    return None if value is None else round(value, 4)


# ---------- calibration ----------


@dataclass
class Calibration:
    """Decision-rule values chosen on a validation split."""

    threshold: Optional[float]
    min_consecutive: int
    validation: Metrics
    within_false_alarm_budget: bool
    max_false_alarms_per_day: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threshold": self.threshold,
            "min_consecutive": self.min_consecutive,
            "within_false_alarm_budget": self.within_false_alarm_budget,
            "max_false_alarms_per_day": self.max_false_alarms_per_day,
            "validation": self.validation.to_dict(),
        }


def calibrate(
    detections: Sequence[Detection],
    labels: Labels,
    tolerance_minutes: float = DEFAULT_TOLERANCE_MINUTES,
    event_types: Optional[Iterable[str]] = None,
    max_false_alarms_per_day: float = DEFAULT_MAX_FALSE_ALARMS_PER_DAY,
    thresholds: Sequence[Optional[float]] = THRESHOLD_GRID,
    min_consecutive: Sequence[int] = MIN_CONSECUTIVE_GRID,
) -> Calibration:
    """
    The ``threshold`` and ``min_consecutive`` with the best validation F1 within the false-alarm budget.

    Ties go to fewer false alarms, then the shorter mean delay, then the lower threshold and
    shorter run (the less filtering). If no pair stays within the budget, the pair with the
    fewest false alarms per day (then the best F1) is returned, marked as outside the budget.
    """
    event_types = list(event_types) if event_types else None
    candidates = []
    for t in thresholds:
        for m in min_consecutive:
            metrics = score(detections, labels, t, m, tolerance_minutes, event_types)
            candidates.append((t, m, metrics))

    def filtering(t: Optional[float], m: int) -> Tuple[float, int]:
        return (-1.0 if t is None else t, m)

    within = [c for c in candidates if c[2].false_alarms_per_day <= max_false_alarms_per_day]
    if within:
        best = min(within, key=lambda c: (-c[2].f1, c[2].false_alarms_per_day, c[2].mean_delay_minutes if c[2].mean_delay_minutes is not None else math.inf, filtering(c[0], c[1])))
    else:
        best = min(candidates, key=lambda c: (c[2].false_alarms_per_day, -c[2].f1, filtering(c[0], c[1])))
    return Calibration(best[0], best[1], best[2], bool(within), max_false_alarms_per_day)


# ---------- report ----------


def render_markdown(report: Dict[str, Any]) -> str:
    """A short Markdown summary of an evaluation report (the JSON report is the record)."""
    lines = [f"# SONAR evaluation: {report.get('scenario') or report.get('detector')}", ""]
    lines.append("| Setting | Value |")
    lines.append("|---|---|")
    settings = (
        ("detector", "Detector"),
        ("scenario", "Scenario ID"),
        ("train_file", "Training data"),
        ("training_buckets", "Training buckets"),
        ("training_seconds", "Training time (s)"),
        ("validation_file", "Validation data"),
        ("test_file", "Test data"),
        ("test_labels", "Test labels"),
        ("event_types", "Event types counted"),
        ("tolerance_minutes", "Tolerance (min)"),
        ("sonar_version", "SONAR version"),
    )
    for key, label in settings:
        if report.get(key) not in (None, "", []):
            value = report[key]
            lines.append(f"| {label} | `{', '.join(value) if isinstance(value, list) else value}` |")
    lines.append("")

    cal = report.get("calibration")
    if cal:
        budget = "" if cal["within_false_alarm_budget"] else f" (no setting stays within {cal['max_false_alarms_per_day']} false alarms per day)"
        lines += [f"Calibrated on the validation split: `threshold: {cal['threshold']}`, `min_consecutive: {cal['min_consecutive']}`{budget}.", ""]

    lines.append("| Run | Threshold | Min consecutive | Events | Detected | Alarms | False alarms | Precision | Recall | F1 | Mean delay (min) | False alarms/day |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for run in report.get("runs", []):
        m = run["metrics"]
        lines.append(
            f"| {run['name']} | {run['threshold']} | {run['min_consecutive']} | {m['events']} | {m['detected']} | {m['alarms']} | {m['false_alarms']} | "
            f"{_fmt(m['precision'])} | {_fmt(m['recall'])} | {m['f1']:.2f} | {_fmt(m['mean_delay_minutes'], 1)} | {m['false_alarms_per_day']:.2f} |"
        )
    lines.append("")
    if report.get("anomaly_confidence") is not None:
        lines += [f"`anomaly_confidence` (test precision with the calibrated values): **{report['anomaly_confidence']}**", ""]

    final = next((r for r in reversed(report.get("runs", [])) if r["name"].startswith("test")), None)
    if final:
        lines += ["Events of the test split:", "", "| Event | Type | Start | Detected | Delay (min) |", "|---|---|---|---|---|"]
        for o in final["metrics"]["outcomes"]:
            lines.append(f"| {o['id']} | {o['type']} | {o['start']} | {'yes' if o['detected'] else 'no'} | {_fmt(o['delay_minutes'], 1)} |")
        lines.append("")
    return "\n".join(lines)


def _fmt(value: Optional[float], digits: int = 2) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"
