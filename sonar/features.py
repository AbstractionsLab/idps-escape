"""
Feature extraction and preprocessing for Wazuh alerts.

Feature schema 2. A feature matrix has one row per time bucket on a regular grid
(empty buckets included) and these columns, in this order:

- ``alert_count``: number of alerts in the bucket.
- each ``numeric_fields`` entry: mean over the alerts in the bucket that carry the field.
- ``<field>__max`` for each ``max_numeric_fields`` entry: maximum over those alerts.
- each enabled derived feature: number of alerts in the bucket for which it holds.
- ``<field>__<value>`` for each value in the categorical vocabulary, plus
  ``<field>__other`` for every value outside it: number of alerts with that value.

The column set depends only on the FeatureConfig and the vocabulary, never on the
alerts, so a model and the detection data always agree on it.
"""

import logging
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import pandas as pd

from sonar.config import FeatureConfig

logger = logging.getLogger(__name__)

# Version of the feature-matrix layout. Bump it whenever the columns built from the same
# alerts and FeatureConfig change, so that models trained on an older layout are refused.
FEATURE_SCHEMA_VERSION = 2

ALERT_COUNT = "alert_count"
OTHER_SUFFIX = "other"
NUMERIC_FILL_MODES = ("zero", "ffill")
COUNT_TRANSFORMS = ("none", "log1p")


# ---------- Derived features ----------


def _groups(alert: Dict[str, Any]) -> List[str]:
    groups = (alert.get("rule") or {}).get("groups") or []
    return [str(g) for g in groups] if isinstance(groups, (list, tuple)) else [str(groups)]


def _has_group(alert: Dict[str, Any], *names: str) -> bool:
    groups = _groups(alert)
    return any(name in groups for name in names)


def _to_float(value: Any) -> float:
    """Convert a field value to float; NaN when missing or not numeric."""
    if value is None or isinstance(value, bool):
        return math.nan
    try:
        return float(value)
    except (TypeError, ValueError):
        return math.nan


def _level(alert: Dict[str, Any]) -> float:
    level = _to_float((alert.get("rule") or {}).get("level"))
    return 0.0 if math.isnan(level) else level


def _data_value(alert: Dict[str, Any], key: str) -> float:
    value = _to_float((alert.get("data") or {}).get(key))
    return 0.0 if math.isnan(value) else value


# Name -> predicate on one alert. Each enabled feature becomes a per-bucket count of the
# alerts for which the predicate holds. Order here is the column order.
DERIVED_FEATURES: Dict[str, Callable[[Dict[str, Any]], bool]] = {
    # Authentication
    "is_auth_failure": lambda a: _has_group(a, "failed_login", "authentication_failed", "invalid_login"),
    "is_auth_success": lambda a: _has_group(a, "authentication_success", "session_opened"),
    "is_brute_force": lambda a: _has_group(a, "brute_force"),
    # Privilege escalation
    "is_privilege_event": lambda a: _has_group(a, "sudo", "su", "privilege_escalation", "account_changed"),
    # Severity (Wazuh level 10+ is high, 12+ critical)
    "is_high_severity": lambda a: _level(a) >= 10,
    "is_critical_severity": lambda a: _level(a) >= 12,
    # Remote access
    "is_ssh_event": lambda a: _has_group(a, "ssh", "sshd"),
    "is_windows_logon": lambda a: _has_group(a, "windows_logon", "windows", "win_logon"),
    # Resource utilisation (data block of Wazuh's general_health_check decoder)
    "is_cpu_high": lambda a: _data_value(a, "cpu_usage_%") >= 80.0,
    "is_cpu_critical": lambda a: _data_value(a, "cpu_usage_%") >= 95.0,
    "is_memory_high": lambda a: _data_value(a, "memory_usage_%") >= 80.0,
    "is_memory_critical": lambda a: _data_value(a, "memory_usage_%") >= 95.0,
    "is_high_load": lambda a: _data_value(a, "1min_loadAverage") >= 4.0,
}


_GROUPS = ("rule.groups",)

# Alert fields each derived feature reads. Alert search requests only the fields features
# need, so a predicate that reads a field not listed here silently sees it as missing.
DERIVED_FEATURE_FIELDS: Dict[str, Tuple[str, ...]] = {
    "is_auth_failure": _GROUPS,
    "is_auth_success": _GROUPS,
    "is_brute_force": _GROUPS,
    "is_privilege_event": _GROUPS,
    "is_high_severity": ("rule.level",),
    "is_critical_severity": ("rule.level",),
    "is_ssh_event": _GROUPS,
    "is_windows_logon": _GROUPS,
    "is_cpu_high": ("data.cpu_usage_%",),
    "is_cpu_critical": ("data.cpu_usage_%",),
    "is_memory_high": ("data.memory_usage_%",),
    "is_memory_critical": ("data.memory_usage_%",),
    "is_high_load": ("data.1min_loadAverage",),
}


def resolve_derived_features(setting: Any) -> List[str]:
    """
    Turn the ``derived_features`` setting into the list of enabled feature names.

    Args:
        setting: ``True`` (all), ``False``/``None`` (none) or a list of names.

    Raises:
        ValueError: On an unknown feature name.
    """
    if setting is True:
        return list(DERIVED_FEATURES)
    if not setting:
        return []
    if isinstance(setting, str):
        setting = [setting]
    unknown = [name for name in setting if name not in DERIVED_FEATURES]
    if unknown:
        raise ValueError(f"Unknown derived feature(s) {unknown}; available: {list(DERIVED_FEATURES)}")
    return [name for name in DERIVED_FEATURES if name in set(setting)]


# ---------- Categorical vocabulary ----------


def _sanitize(value: Any) -> str:
    """Make a category value safe for a column name (alphanumerics kept, the rest '_')."""
    return "".join(c if c.isalnum() else "_" for c in str(value))


@dataclass
class FeatureVocabulary:
    """
    Top-k values per categorical field, fitted on training data and stored in the model.

    Detection reuses it, so values unseen in training are counted in ``<field>__other``
    instead of creating or dropping columns.
    """

    categories: Dict[str, List[str]] = field(default_factory=dict)

    @staticmethod
    def column_name(field_path: str, value: Any) -> str:
        """Column for one category value of a field."""
        safe = _sanitize(value)
        if safe == OTHER_SUFFIX:
            safe = f"{OTHER_SUFFIX}_value"  # keep apart from the <field>__other bucket
        return f"{field_path}__{safe}"

    @staticmethod
    def other_column(field_path: str) -> str:
        """Column that counts values outside the vocabulary."""
        return f"{field_path}__{OTHER_SUFFIX}"

    def columns(self, fields: Sequence[str]) -> List[str]:
        """Ordered, de-duplicated columns for the given categorical fields."""
        cols: List[str] = []
        for field_path in fields:
            for value in self.categories.get(field_path, []):
                col = self.column_name(field_path, value)
                if col not in cols:
                    cols.append(col)
            cols.append(self.other_column(field_path))
        return cols

    def column_for(self, field_path: str, value: Any) -> str:
        """Column that counts this value: its own if in the vocabulary, else ``__other``."""
        if str(value) in self._lookup().get(field_path, ()):
            return self.column_name(field_path, value)
        return self.other_column(field_path)

    def _lookup(self) -> Dict[str, set]:
        cached = getattr(self, "_lookup_cache", None)
        if cached is None:
            cached = {f: set(values) for f, values in self.categories.items()}
            object.__setattr__(self, "_lookup_cache", cached)
        return cached

    @classmethod
    def fit(cls, alerts: Sequence[Dict[str, Any]], fields: Sequence[str], top_k: int) -> "FeatureVocabulary":
        """
        Keep the ``top_k`` most frequent values of each field (all values if ``top_k <= 0``).

        Ties are broken by value, so the vocabulary is deterministic.
        """
        categories: Dict[str, List[str]] = {}
        for field_path in fields:
            counts: Counter = Counter()
            for alert in alerts:
                for value in category_values(alert, field_path):
                    counts[value] += 1
            ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
            if top_k and top_k > 0:
                ranked = ranked[:top_k]
            categories[field_path] = [value for value, _ in ranked]
            if not ranked:
                logger.warning("Categorical field '%s' has no values in the training alerts", field_path)
        return cls(categories=categories)

    def to_dict(self) -> Dict[str, Any]:
        """Serialisable form for the model file."""
        return {"categories": {f: list(v) for f, v in self.categories.items()}}

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "FeatureVocabulary":
        """Inverse of ``to_dict``."""
        return cls(categories={f: [str(v) for v in values] for f, values in ((data or {}).get("categories") or {}).items()})


def get_nested_field(alert: Dict[str, Any], path: str) -> Any:
    """Retrieve a dotted-path field; None if any part is missing."""
    cur: Any = alert
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def category_values(alert: Dict[str, Any], field_path: str) -> List[str]:
    """Category values of an alert field: each list element, or the single value."""
    value = get_nested_field(alert, field_path)
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v is not None]
    return [str(value)]


# ---------- Feature builder ----------


class WazuhFeatureBuilder:
    """Converts raw Wazuh alerts into a multivariate time-series DataFrame (feature schema 2)."""

    def __init__(self, cfg: FeatureConfig, vocabulary: Optional[FeatureVocabulary] = None):
        """
        Initialize feature builder.

        Args:
            cfg: FeatureConfig instance with feature specifications.
            vocabulary: Categorical vocabulary. Pass the model's at detection time; when None,
                ``build_timeseries`` fits one on the first alerts it receives.

        Raises:
            ValueError: On an unknown derived feature, fill mode or count transform.
        """
        self.cfg = cfg
        self.vocabulary = vocabulary
        self.derived = resolve_derived_features(getattr(cfg, "derived_features", True))
        self.numeric_fill = getattr(cfg, "numeric_fill", "zero") or "zero"
        if self.numeric_fill not in NUMERIC_FILL_MODES:
            raise ValueError(f"numeric_fill must be one of {NUMERIC_FILL_MODES}; got '{self.numeric_fill}'")
        self.count_transform = getattr(cfg, "count_transform", "none") or "none"
        if self.count_transform not in COUNT_TRANSFORMS:
            raise ValueError(f"count_transform must be one of {COUNT_TRANSFORMS}; got '{self.count_transform}'")

    @staticmethod
    def _parse_timestamp(ts: str) -> datetime:
        """
        Parse ISO 8601 timestamp with timezone information.

        Accepts formats such as:
            - 2025-12-25T19:47:32.017Z
            - 2025-12-25T19:47:32Z
            - 2025-12-25T19:47:32.017+00:00
            - 2025-12-25T19:47:32+0000

        Returns a timezone-aware datetime in UTC.
        """
        if not isinstance(ts, str):
            raise ValueError(f"Invalid timestamp type: {type(ts)}")

        # UTC 'Z' designator (with or without fractional seconds)
        if ts.endswith("Z"):
            for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
                try:
                    dt = datetime.strptime(ts, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
            raise ValueError(f"Invalid timestamp format: '{ts}'")

        # Otherwise, try ISO parsing and normalize timezone offsets like +0000 -> +00:00
        normalized_ts = ts
        if len(normalized_ts) >= 5 and (normalized_ts[-5] in ("+", "-")):
            if ":" not in normalized_ts[-6:]:
                normalized_ts = normalized_ts[:-2] + ":" + normalized_ts[-2:]
        try:
            dt = datetime.fromisoformat(normalized_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError as e:
            raise ValueError(f"Invalid timestamp format: '{ts}'") from e

    # Kept for callers that used the methods on the builder.
    _get_nested_field = staticmethod(get_nested_field)
    _sanitize_cat = staticmethod(_sanitize)

    @property
    def _numeric_fields(self) -> List[str]:
        return list(dict.fromkeys(self.cfg.numeric_fields))

    @property
    def _max_fields(self) -> List[str]:
        return list(dict.fromkeys(getattr(self.cfg, "max_numeric_fields", ()) or ()))

    @property
    def _categorical_fields(self) -> List[str]:
        return list(dict.fromkeys(getattr(self.cfg, "categorical_fields", ()) or ()))

    def required_source_fields(self) -> List[str]:
        """
        The alert fields the features are computed from, for source filtering at search time.

        ``timestamp``, the numeric, max and categorical fields, and the fields read by the
        enabled derived features.
        """
        fields = ["timestamp", *self._numeric_fields, *self._max_fields, *self._categorical_fields]
        for name in self.derived:
            fields.extend(DERIVED_FEATURE_FIELDS[name])
        return list(dict.fromkeys(fields))

    def fit_vocabulary(self, alerts: Sequence[Dict[str, Any]]) -> FeatureVocabulary:
        """Fit and store the categorical vocabulary on these alerts."""
        self.vocabulary = FeatureVocabulary.fit(alerts, self._categorical_fields, int(getattr(self.cfg, "categorical_top_k", 0) or 0))
        return self.vocabulary

    def count_columns(self) -> List[str]:
        """Columns aggregated as per-bucket counts."""
        vocab = self.vocabulary or FeatureVocabulary()
        return [ALERT_COUNT] + self.derived + vocab.columns(self._categorical_fields)

    def columns(self) -> List[str]:
        """The full, ordered column list for this config and vocabulary."""
        vocab = self.vocabulary or FeatureVocabulary()
        return [ALERT_COUNT] + self._numeric_fields + [f"{f}__max" for f in self._max_fields] + self.derived + vocab.columns(self._categorical_fields)

    def _grid(self, first_ts: pd.Timestamp, last_ts: pd.Timestamp, start: Optional[datetime], end: Optional[datetime]) -> pd.DatetimeIndex:
        """Bucket start times: from start (or the first alert) up to end (exclusive) or the last alert."""
        freq = f"{int(self.cfg.bucket_minutes)}min"
        first = _utc(start).floor(freq) if start is not None else first_ts.floor(freq)
        if end is not None:
            return pd.date_range(first, _utc(end), freq=freq, inclusive="left")
        return pd.date_range(first, last_ts.floor(freq), freq=freq)

    def build_timeseries(self, alerts: List[Dict[str, Any]], start: Optional[datetime] = None, end: Optional[datetime] = None) -> pd.DataFrame:
        """
        Aggregate alerts into a regular grid of time buckets.

        Args:
            alerts: Raw Wazuh alert documents.
            start: First bucket is the one containing ``start``. When None, the bucket of the
                first alert (training uses this, so history before the first alert is not
                learned as silence).
            end: Buckets start before ``end``. When None, up to the bucket of the last alert.

        Returns:
            DataFrame indexed by bucket start (UTC) with ``self.columns()``; empty if no alert
            has a valid timestamp.
        """
        parsed = []
        for alert in alerts:
            ts_str = alert.get("timestamp")
            if not ts_str:
                continue
            try:
                parsed.append((self._parse_timestamp(ts_str), alert))
            except ValueError as e:
                logger.warning("Skipping alert with invalid timestamp '%s': %s", ts_str, e)
        if not parsed:
            return pd.DataFrame()

        if self._categorical_fields and self.vocabulary is None:
            self.fit_vocabulary([a for _, a in parsed])
        vocab = self.vocabulary or FeatureVocabulary()

        value_fields = list(dict.fromkeys(self._numeric_fields + self._max_fields))
        count_rows, value_rows = [], []
        for _, alert in parsed:
            counts = {ALERT_COUNT: 1.0}
            for name in self.derived:
                counts[name] = 1.0 if DERIVED_FEATURES[name](alert) else 0.0
            for field_path in self._categorical_fields:
                for value in category_values(alert, field_path):
                    col = vocab.column_for(field_path, value)
                    counts[col] = counts.get(col, 0.0) + 1.0
            count_rows.append(counts)
            value_rows.append({f: _to_float(get_nested_field(alert, f)) for f in value_fields})

        index = pd.DatetimeIndex([ts for ts, _ in parsed]).tz_convert("UTC")
        count_cols = self.count_columns()
        counts_df = pd.DataFrame(count_rows, index=index).reindex(columns=count_cols, fill_value=0.0).fillna(0.0).sort_index()
        values_df = pd.DataFrame(value_rows, index=index, columns=value_fields, dtype=float).sort_index()

        rule = f"{int(self.cfg.bucket_minutes)}min"
        parts = [counts_df.resample(rule, origin="epoch").sum()]
        if self._numeric_fields:
            parts.append(values_df[self._numeric_fields].resample(rule, origin="epoch").mean())
        if self._max_fields:
            parts.append(values_df[self._max_fields].resample(rule, origin="epoch").max().rename(columns={f: f"{f}__max" for f in self._max_fields}))
        agg = pd.concat(parts, axis=1)
        agg = agg.loc[:, ~agg.columns.duplicated()]

        grid = self._grid(index.min(), index.max(), start, end)
        agg = agg.reindex(grid)

        agg[count_cols] = agg[count_cols].fillna(0.0)
        if self.count_transform == "log1p":
            agg[count_cols] = agg[count_cols].apply(lambda s: s.map(math.log1p))

        value_cols = self._numeric_fields + [f"{f}__max" for f in self._max_fields]
        if value_cols:
            if self.numeric_fill == "ffill":
                agg[value_cols] = agg[value_cols].ffill()
            agg[value_cols] = agg[value_cols].fillna(0.0)

        result = agg[self.columns()].astype(float)
        result.index.name = "timestamp"
        logger.info(
            "Feature matrix: %d buckets x %d columns (%d numeric, %d max, %d derived, %d categorical), %d empty buckets",
            len(result),
            result.shape[1],
            len(self._numeric_fields),
            len(self._max_fields),
            len(self.derived),
            len(vocab.columns(self._categorical_fields)),
            int((result[ALERT_COUNT] == 0).sum()),
        )
        return result


def _utc(value: datetime) -> pd.Timestamp:
    """Timestamp in UTC; naive values are taken as UTC."""
    ts = pd.Timestamp(value)
    return ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")
