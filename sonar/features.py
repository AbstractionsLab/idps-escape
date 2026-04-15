"""
Feature extraction and preprocessing for Wazuh alerts.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List

import logging
import pandas as pd

from sonar.config import FeatureConfig

logger = logging.getLogger(__name__)


class WazuhFeatureBuilder:
    """
    Converts raw Wazuh alerts into a multivariate time-series DataFrame.

    - index: timestamp buckets
    - columns: engineered numeric features (counts, aggregates, etc.)
    """

    def __init__(self, cfg: FeatureConfig):
        """
        Initialize feature builder.

        Args:
            cfg: FeatureConfig instance with feature specifications.
        """
        self.cfg = cfg

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
        # If timezone is like +0000 or -0500 (no colon), insert colon
        if len(normalized_ts) >= 5 and (normalized_ts[-5] in ('+', '-')):
            if ':' not in normalized_ts[-6:]:
                normalized_ts = normalized_ts[:-2] + ':' + normalized_ts[-2:]
        try:
            dt = datetime.fromisoformat(normalized_ts)
            if dt.tzinfo is None:
                # Assume UTC if no tzinfo provided
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError as e:
            raise ValueError(f"Invalid timestamp format: '{ts}'") from e

    def _extract_single_alert_features(
        self, alert: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Extract low-level numeric features from a single alert.

        Includes both raw numeric fields and derived security-relevant features.

        Args:
            alert: Raw Wazuh alert document.

        Returns:
            Dictionary of numeric features for this alert.
        """
        feats: Dict[str, float] = {}

        # Extract all configured numeric fields using dot-notation
        for field_path in self.cfg.numeric_fields:
            val = self._get_nested_field(alert, field_path)
            if val is not None and isinstance(val, (int, float, str)):
                try:
                    feats[field_path] = float(val)
                except (ValueError, TypeError):
                    feats[field_path] = 0.0
            else:
                feats[field_path] = 0.0

        # Derived features for attack detection (if enabled)
        if getattr(self.cfg, "derived_features", True):
            feats.update(self._extract_derived_features(alert))

        return feats

    def _extract_derived_features(
        self, alert: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Extract derived security-relevant features from alert content.

        These features help detect attack patterns like brute force,
        lateral movement, and privilege escalation.

        Args:
            alert: Raw Wazuh alert document.

        Returns:
            Dictionary of derived numeric features.
        """
        derived: Dict[str, float] = {}
        rule = alert.get("rule", {})
        groups = rule.get("groups", [])

        # Authentication pattern indicators
        derived["is_auth_failure"] = 1.0 if any(
            g in groups for g in ("failed_login", "authentication_failed", "invalid_login")
        ) else 0.0
        
        derived["is_auth_success"] = 1.0 if any(
            g in groups for g in ("authentication_success", "session_opened")
        ) else 0.0

        derived["is_brute_force"] = 1.0 if "brute_force" in groups else 0.0

        # Privilege escalation indicators
        derived["is_privilege_event"] = 1.0 if any(
            g in groups for g in ("sudo", "su", "privilege_escalation", "account_changed")
        ) else 0.0

        # High severity indicator (level >= 10 is typically critical)
        level = rule.get("level", 0)
        derived["is_high_severity"] = 1.0 if level >= 10 else 0.0
        derived["is_critical_severity"] = 1.0 if level >= 12 else 0.0

        # Network/SSH related
        derived["is_ssh_event"] = 1.0 if "ssh" in groups or "sshd" in groups else 0.0

        # Windows logon events
        derived["is_windows_logon"] = 1.0 if any(
            g in groups for g in ("windows_logon", "windows", "win_logon")
        ) else 0.0

        # Resource utilization thresholds (for linux_resource_monitoring use case).
        # Values come from the data block decoded by Wazuh's general_health_check decoder.
        data = alert.get("data", {})
        try:
            cpu = float(data.get("cpu_usage_%", 0) or 0)
        except (TypeError, ValueError):
            cpu = 0.0
        try:
            mem = float(data.get("memory_usage_%", 0) or 0)
        except (TypeError, ValueError):
            mem = 0.0
        try:
            load1 = float(data.get("1min_loadAverage", 0) or 0)
        except (TypeError, ValueError):
            load1 = 0.0

        derived["is_cpu_high"] = 1.0 if cpu >= 80.0 else 0.0
        derived["is_cpu_critical"] = 1.0 if cpu >= 95.0 else 0.0
        derived["is_memory_high"] = 1.0 if mem >= 80.0 else 0.0
        derived["is_memory_critical"] = 1.0 if mem >= 95.0 else 0.0
        derived["is_high_load"] = 1.0 if load1 >= 4.0 else 0.0

        return derived

    def _get_nested_field(self, alert: Dict[str, Any], path: str):
        """Retrieve a nested field using dot-notation. Returns None if missing."""
        cur = alert
        for part in path.split("."):
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
            if cur is None:
                return None
        return cur

    @staticmethod
    def _sanitize_cat(s: str) -> str:
        """Sanitize a category label into a safe column name fragment."""
        # Keep alphanumeric and replace others with underscore
        return "".join([c if c.isalnum() else "_" for c in str(s)])

    def build_timeseries(
        self, alerts: List[Dict[str, Any]]
    ) -> pd.DataFrame:
        """
        Aggregate alerts into time buckets and return a multivariate time series.

        For each bucket and each feature, we sum or average as appropriate.
        Here we simply compute the average per bucket for each numeric feature.

        Args:
            alerts: List of raw Wazuh alert documents.

        Returns:
            DataFrame with time index and numeric feature columns.
        """
        if not alerts:
            return pd.DataFrame()

        rows = []
        for alert in alerts:
            ts_str = alert.get("timestamp")
            if not ts_str:
                continue
            
            try:
                ts = self._parse_timestamp(ts_str)
            except ValueError as e:
                # Log and skip malformed timestamps
                logger.warning("Skipping alert with invalid timestamp '%s' in alert: %s", ts_str, e)
                continue

            feats = self._extract_single_alert_features(alert)
            # Extract categorical fields (if configured) into a per-alert string
            for field in getattr(self.cfg, "categorical_fields", tuple()):
                val = self._get_nested_field(alert, field)
                if val is None:
                    logger.debug(f"Categorical field '{field}' not found in alert")
                    continue
                # If the field is a list, join using '|' so pandas get_dummies can split
                if isinstance(val, (list, tuple)):
                    joined_val = "|".join([str(x) for x in val if x is not None])
                    feats[f"_cat__{field}"] = joined_val
                    logger.debug(f"Extracted categorical field '{field}' (list): {joined_val}")
                else:
                    feats[f"_cat__{field}"] = str(val)
                    logger.debug(f"Extracted categorical field '{field}' (string): {val}")

            feats["timestamp"] = ts
            rows.append(feats)

        if not rows:
            return pd.DataFrame()

        df = pd.DataFrame(rows)
        df.set_index("timestamp", inplace=True)

        # Handle categorical one-hot encoding if configured
        categorical_cols = []
        logger.info(f"Processing {len(getattr(self.cfg, 'categorical_fields', tuple()))} categorical field(s)")
        for field in getattr(self.cfg, "categorical_fields", tuple()):
            col_name = f"_cat__{field}"
            if col_name not in df.columns:
                logger.warning(f"Categorical field '{field}' not found in DataFrame columns")
                continue
            s = df[col_name].fillna("")
            # Create dummies; drop any empty-string columns
            dummies = s.astype(str).str.get_dummies(sep="|")
            if "" in dummies.columns:
                dummies = dummies.drop(columns=[""])

            # If there are no categories for this field, skip
            if dummies.shape[1] == 0:
                logger.warning(f"No categories found for field '{field}' after one-hot encoding")
                continue

            # Sanitize column names and prepare rename mapping
            rename_map = {}
            for c in dummies.columns:
                safe = self._sanitize_cat(c)
                rename_map[c] = f"{field}__{safe}"

            dummies = dummies.rename(columns=rename_map)
            # Cast dummies to float so downstream resample/mean works
            dummies = dummies.astype(float)
            logger.info(f"Created {dummies.shape[1]} one-hot encoded columns for field '{field}'")

            # Keep top-k categories, aggregate the rest into <field>__other
            top_k = max(0, int(getattr(self.cfg, "categorical_top_k", 0)))
            if top_k > 0 and dummies.shape[1] > top_k:
                counts = dummies.sum().sort_values(ascending=False)
                top_cols = counts.index[:top_k]
                other_cols = [c for c in dummies.columns if c not in top_cols]
                dummies[ f"{field}__other"] = dummies[other_cols].sum(axis=1)
                dummies = dummies[top_cols.tolist() + [f"{field}__other"]]
                logger.info(f"Applied top-{top_k} filtering for field '{field}': kept {len(top_cols)} categories + '__other'")

            # Attach dummies to original DataFrame (per-alert level)
            df = pd.concat([df, dummies], axis=1)
            # Drop the original string column to avoid object dtype during aggregation
            if col_name in df.columns:
                df = df.drop(columns=[col_name])

            categorical_cols.extend(dummies.columns.tolist())

        logger.info(f"Total categorical columns after processing: {len(categorical_cols)}")
        if categorical_cols:
            logger.debug(f"Categorical columns: {categorical_cols[:10]}{'...' if len(categorical_cols) > 10 else ''}")

        # Resample into fixed buckets (e.g., every 5 minutes)
        rule = f"{self.cfg.bucket_minutes}min"
        # Operate only on numeric columns to avoid aggregation errors on object dtypes
        numeric_df = df.select_dtypes(include=['number']).copy()
        # For numeric columns, you can choose sum/mean/max — here: mean
        agg_df = numeric_df.resample(rule).mean().sort_index()

        # Per-bucket max columns for fields listed in max_numeric_fields.
        # Each produces a <field>__max column alongside the default mean.
        max_cols_added: List[str] = []
        max_numeric_fields = list(getattr(self.cfg, "max_numeric_fields", []) or [])
        if max_numeric_fields:
            valid_max_fields = [f for f in max_numeric_fields if f in numeric_df.columns]
            if valid_max_fields:
                max_df = numeric_df[valid_max_fields].resample(rule).max().sort_index()
                rename_map = {f: f"{f}__max" for f in valid_max_fields}
                max_df = max_df.rename(columns=rename_map)
                agg_df = pd.concat([agg_df, max_df], axis=1)
                max_cols_added = list(rename_map.values())
                logger.info("Added %d per-bucket max column(s): %s", len(max_cols_added), max_cols_added)
            else:
                logger.warning("max_numeric_fields configured but none present in data: %s", max_numeric_fields)

        # Collect derived feature columns (those added by _extract_derived_features)
        derived_feature_names = [
            "is_auth_failure", "is_auth_success", "is_brute_force",
            "is_privilege_event", "is_high_severity", "is_critical_severity",
            "is_ssh_event", "is_windows_logon",
            "is_cpu_high", "is_cpu_critical",
            "is_memory_high", "is_memory_critical",
            "is_high_load",
        ]
        derived_cols = [c for c in agg_df.columns if c in derived_feature_names]

        # Ensure consistent column order / names
        for col in self.cfg.numeric_fields:
            if col not in agg_df.columns:
                agg_df[col] = 0.0

        # Ensure max columns are present (fill 0.0 if a bucket had no data)
        for col in max_cols_added:
            if col not in agg_df.columns:
                agg_df[col] = 0.0

        # Ensure categorical columns present and ordered after numerics
        for col in categorical_cols:
            if col not in agg_df.columns:
                agg_df[col] = 0.0

        # Build final column order: numeric fields + max fields + derived features + categorical columns
        final_cols = list(self.cfg.numeric_fields) + max_cols_added + derived_cols + categorical_cols
        # Only include columns that exist in the DataFrame
        final_cols = [c for c in final_cols if c in agg_df.columns]
        logger.info(
            f"Final feature set: {len(self.cfg.numeric_fields)} numeric + "
            f"{len(max_cols_added)} max + {len(derived_cols)} derived + "
            f"{len(categorical_cols)} categorical = {len(final_cols)} total"
        )
        agg_df = agg_df[final_cols]

        # Drop rows that are all NaN
        agg_df = agg_df.dropna(how="all")

        # Simple NA handling: fill remaining NaN with 0
        agg_df = agg_df.fillna(0.0)

        return agg_df
