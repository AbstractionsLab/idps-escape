"""
Feature schema 2: regular time grid, volume (count) features, persisted categorical
vocabulary and the training/detection feature contract.
"""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pandas as pd

from sonar.config import FeatureConfig, PipelineConfig
from sonar.engine import IncompatibleModelError, MVADModelEngine
from sonar.features import DERIVED_FEATURES, FeatureVocabulary, WazuhFeatureBuilder, resolve_derived_features


def _alert(ts, groups=("sshd", "authentication_failed"), level=5, data=None, **extra):
    alert = {"timestamp": ts, "rule": {"level": level, "groups": list(groups)}}
    if data is not None:
        alert["data"] = data
    alert.update(extra)
    return alert


def _burst(minute, count):
    """`count` failed logins inside the 5-minute bucket starting at 00:`minute`."""
    return [_alert(f"2026-01-01T00:{minute + i // 60:02d}:{i % 60:02d}Z") for i in range(count)]


class TestVolumeFeatures(unittest.TestCase):
    def test_volume_changes_the_row(self):
        """1 and 200 failed logins in a bucket give different rows (they were identical in schema 1)."""
        cfg = FeatureConfig(categorical_fields=("rule.groups",), derived_features=["is_auth_failure"])
        df = WazuhFeatureBuilder(cfg).build_timeseries(_burst(0, 1) + _burst(5, 200))
        self.assertEqual(df["alert_count"].tolist(), [1.0, 200.0])
        self.assertEqual(df["is_auth_failure"].tolist(), [1.0, 200.0])
        self.assertEqual(df["rule.groups__authentication_failed"].tolist(), [1.0, 200.0])

    def test_log1p_transform_applies_to_counts_only(self):
        cfg = FeatureConfig(derived_features=False, count_transform="log1p")
        df = WazuhFeatureBuilder(cfg).build_timeseries(_burst(0, 3))
        self.assertAlmostEqual(df["alert_count"].iloc[0], 1.3862943611, places=6)  # log(4)
        self.assertEqual(df["rule.level"].iloc[0], 5.0)


class TestRegularGrid(unittest.TestCase):
    def test_silent_buckets_are_rows_with_zero_counts(self):
        alerts = [_alert("2026-01-01T00:01:00Z")] + _burst(5, 4) + [_alert("2026-01-01T00:21:00Z")]
        df = WazuhFeatureBuilder(FeatureConfig(derived_features=False)).build_timeseries(alerts)
        self.assertEqual([t.strftime("%H:%M") for t in df.index], ["00:00", "00:05", "00:10", "00:15", "00:20"])
        self.assertEqual(df["alert_count"].tolist(), [1.0, 4.0, 0.0, 0.0, 1.0])

    def test_explicit_window_covers_leading_and_trailing_silence(self):
        start, end = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc), datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc)
        df = WazuhFeatureBuilder(FeatureConfig(derived_features=False)).build_timeseries([_alert("2026-01-01T00:12:00Z")], start=start, end=end)
        self.assertEqual(len(df), 6)  # 00:00 ... 00:25, end exclusive
        self.assertEqual(df["alert_count"].tolist(), [0.0, 0.0, 1.0, 0.0, 0.0, 0.0])

    def test_end_only_starts_at_first_alert(self):
        """Training passes only `end`: history before the first alert is not learned as silence."""
        end = datetime(2026, 1, 1, 1, 0, tzinfo=timezone.utc)
        df = WazuhFeatureBuilder(FeatureConfig(derived_features=False)).build_timeseries([_alert("2026-01-01T00:42:00Z")], end=end)
        self.assertEqual(df.index[0].strftime("%H:%M"), "00:40")
        self.assertEqual(df.index[-1].strftime("%H:%M"), "00:55")

    def test_buckets_align_to_epoch_for_any_size(self):
        df = WazuhFeatureBuilder(FeatureConfig(derived_features=False, bucket_minutes=7)).build_timeseries([_alert("2026-01-01T00:13:00Z")])
        self.assertEqual(df.index[0], pd.Timestamp("2026-01-01T00:13:00Z").floor("7min"))

    def test_no_alerts_gives_empty_frame(self):
        start, end = datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 1, 2, tzinfo=timezone.utc)
        self.assertTrue(WazuhFeatureBuilder(FeatureConfig()).build_timeseries([], start=start, end=end).empty)


class TestNumericFields(unittest.TestCase):
    def test_mean_only_over_alerts_carrying_the_field(self):
        alerts = [_alert("2026-01-01T00:00:00Z", data={"cpu": 40.0 + i}) for i in range(10)]
        alerts += [_alert("2026-01-01T00:01:00Z") for _ in range(90)]  # no data.cpu
        df = WazuhFeatureBuilder(FeatureConfig(numeric_fields=("data.cpu",), derived_features=False)).build_timeseries(alerts)
        self.assertAlmostEqual(df["data.cpu"].iloc[0], 44.5)

    def test_numeric_fill_zero_and_ffill(self):
        alerts = [_alert("2026-01-01T00:00:00Z", data={"cpu": 70.0}), _alert("2026-01-01T00:10:00Z", data={"cpu": 90.0})]
        zero = WazuhFeatureBuilder(FeatureConfig(numeric_fields=("data.cpu",), derived_features=False)).build_timeseries(alerts)
        ffill = WazuhFeatureBuilder(FeatureConfig(numeric_fields=("data.cpu",), derived_features=False, numeric_fill="ffill")).build_timeseries(alerts)
        self.assertEqual(zero["data.cpu"].tolist(), [70.0, 0.0, 90.0])
        self.assertEqual(ffill["data.cpu"].tolist(), [70.0, 70.0, 90.0])

    def test_invalid_settings_rejected(self):
        with self.assertRaises(ValueError):
            WazuhFeatureBuilder(FeatureConfig(numeric_fill="mean"))
        with self.assertRaises(ValueError):
            WazuhFeatureBuilder(FeatureConfig(count_transform="sqrt"))


class TestDerivedFeatures(unittest.TestCase):
    def test_resolve_settings(self):
        self.assertEqual(resolve_derived_features(True), list(DERIVED_FEATURES))
        self.assertEqual(resolve_derived_features(False), [])
        # Order follows the registry, not the setting
        self.assertEqual(resolve_derived_features(["is_ssh_event", "is_auth_failure"]), ["is_auth_failure", "is_ssh_event"])
        with self.assertRaises(ValueError):
            resolve_derived_features(["is_typo"])

    def test_list_limits_columns(self):
        cfg = FeatureConfig(derived_features=["is_ssh_event"])
        df = WazuhFeatureBuilder(cfg).build_timeseries([_alert("2026-01-01T00:00:00Z")])
        self.assertEqual(list(df.columns), ["alert_count", "rule.level", "is_ssh_event"])


class TestVocabulary(unittest.TestCase):
    def setUp(self):
        self.cfg = FeatureConfig(categorical_fields=("rule.groups",), categorical_top_k=2, derived_features=False)

    def test_top_k_is_deterministic_and_rest_goes_to_other(self):
        alerts = [_alert("2026-01-01T00:00:00Z", groups=g) for g in [("a", "b"), ("a", "c"), ("b",), ("d",)]]
        fb = WazuhFeatureBuilder(self.cfg)
        df = fb.build_timeseries(alerts)
        self.assertEqual(fb.vocabulary.categories, {"rule.groups": ["a", "b"]})  # counts a=2, b=2 beat c=1, d=1
        self.assertEqual(df[["rule.groups__a", "rule.groups__b", "rule.groups__other"]].iloc[0].tolist(), [2.0, 2.0, 2.0])

    def test_unseen_category_counts_in_other_with_identical_columns(self):
        train = WazuhFeatureBuilder(self.cfg)
        train_df = train.build_timeseries([_alert("2026-01-01T00:00:00Z", groups=("sshd", "authentication_failed"))])
        detect = WazuhFeatureBuilder(self.cfg, vocabulary=train.vocabulary)
        det_df = detect.build_timeseries([_alert("2026-01-02T00:00:00Z", groups=("attack", "sshd"))])
        self.assertEqual(list(det_df.columns), list(train_df.columns))
        self.assertEqual(det_df["rule.groups__other"].iloc[0], 1.0)
        self.assertEqual(det_df["rule.groups__sshd"].iloc[0], 1.0)

    def test_column_names_sanitised_and_other_value_kept_apart(self):
        vocab = FeatureVocabulary({"agent.name": ["web-01", "other"]})
        self.assertEqual(vocab.columns(["agent.name"]), ["agent.name__web_01", "agent.name__other_value", "agent.name__other"])
        self.assertEqual(vocab.column_for("agent.name", "other"), "agent.name__other_value")
        self.assertEqual(vocab.column_for("agent.name", "db-02"), "agent.name__other")

    def test_round_trip(self):
        vocab = FeatureVocabulary({"rule.groups": ["a", "b"]})
        self.assertEqual(FeatureVocabulary.from_dict(vocab.to_dict()), vocab)


class TestFeatureContract(unittest.TestCase):
    """The model stores its feature config and vocabulary; mismatches are errors, not zero-fills."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = PipelineConfig()
        self.cfg.models_dir = self.tmp.name
        self.cfg.model_name = "m"
        self.cfg.mvad.sliding_window = 20
        self.cfg.mvad.extra_params = {"batch_size": 8}
        self.cfg.features = FeatureConfig(categorical_fields=("rule.groups",), derived_features=["is_ssh_event"])

    def tearDown(self):
        self.tmp.cleanup()

    def _train(self):
        fb = WazuhFeatureBuilder(self.cfg.features)
        alerts = [_alert(f"2026-01-01T{h:02d}:{m:02d}:00Z") for h in range(21) for m in range(0, 60, 5)]
        ts = fb.build_timeseries(alerts)
        with patch("sonar.backends.mvad.MultivariateAnomalyDetector"):
            engine = MVADModelEngine(self.cfg)
            engine.train(ts, vocabulary=fb.vocabulary)
        return engine, ts

    def test_model_stores_feature_config_vocabulary_and_columns(self):
        engine, ts = self._train()
        self.assertEqual(engine.metadata["columns"], list(ts.columns))
        self.assertEqual(engine.vocabulary.categories["rule.groups"], ["authentication_failed", "sshd"])
        self.assertEqual(list(engine.feature_config.categorical_fields), ["rule.groups"])
        self.assertEqual(engine.feature_config.derived_features, ["is_ssh_event"])

    def test_predict_refuses_column_mismatch(self):
        engine, ts = self._train()
        with self.assertRaises(ValueError) as ctx:
            engine.predict(ts.drop(columns=["rule.groups__sshd"]))
        self.assertIn("rule.groups__sshd", str(ctx.exception))

    def test_load_refuses_older_feature_schema(self):
        model_dir = Path(self.cfg.model_path)
        model_dir.mkdir()
        (model_dir / "metadata.json").write_text(json.dumps({"format_version": 1, "backend": "mvad", "feature_schema_version": 1, "columns": ["rule.level"]}))
        with self.assertRaises(IncompatibleModelError) as ctx:
            MVADModelEngine(self.cfg).load()
        self.assertIn("Retrain", str(ctx.exception))

    def test_load_refuses_old_pickled_models_without_unpickling(self):
        legacy = Path(self.tmp.name) / "m.pkl"
        legacy.write_bytes(b"not even a pickle")  # never opened: the format alone decides
        with self.assertRaises(IncompatibleModelError) as ctx:
            MVADModelEngine(self.cfg).load()
        self.assertIn("pickle", str(ctx.exception))

    def test_detection_adopts_model_features(self):
        from sonar.cli import _adopt_model_features

        engine, _ = self._train()
        cfg = PipelineConfig()  # scenario features changed since training
        cfg.features = FeatureConfig(categorical_fields=("agent.name",))
        with self.assertLogs("sonar.cli", level="WARNING") as logs:
            _adopt_model_features(cfg, engine)
        self.assertEqual(list(cfg.features.categorical_fields), ["rule.groups"])
        self.assertTrue(any("categorical_fields" in line for line in logs.output))


if __name__ == "__main__":
    unittest.main()
