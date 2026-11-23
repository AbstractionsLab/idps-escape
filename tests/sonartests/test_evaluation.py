"""
Detection-quality metrics, calibration and the ``sonar evaluate`` command (sonar/evaluation.py).
"""

import argparse
import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from sonar import cli
from sonar.evaluation import Detection, Labels, alarms, calibrate, load_external_detections, render_markdown, reported, score

T0 = pd.Timestamp("2024-12-01T00:00:00Z")


def minutes(n: float) -> pd.Timestamp:
    return T0 + pd.Timedelta(minutes=n)


def buckets(flagged: dict, total: int = 1440, width: int = 1) -> list:
    """One detection per bucket; ``flagged`` maps a bucket index to its severity."""
    return [Detection(minutes(i * width), minutes((i + 1) * width), i in flagged, flagged.get(i, 0.0)) for i in range(total)]


def labels(*events, span=None) -> Labels:
    data = {"events": [{"id": f"e{i}", "type": t, "start": minutes(a).isoformat(), "end": minutes(b).isoformat()} for i, (t, a, b) in enumerate(events)]}
    if span:
        data["span"] = {"start": minutes(span[0]).isoformat(), "end": minutes(span[1]).isoformat()}
    return Labels.from_dict(data)


class TestScore(unittest.TestCase):
    def test_detected_events_true_and_false_alarms(self):
        # One day of 1-minute buckets; events at 100-130 and 600-610; alarms at 105-107, 300, 900-901.
        det = buckets({105: 0.9, 106: 0.9, 107: 0.9, 300: 0.5, 900: 0.4, 901: 0.4})
        m = score(det, labels(("spike", 100, 130), ("spike", 600, 610)))
        self.assertEqual((m.events, m.detected, m.alarms, m.true_alarms, m.false_alarms), (2, 1, 3, 1, 2))
        self.assertAlmostEqual(m.precision, 1 / 3, places=3)
        self.assertEqual(m.recall, 0.5)
        self.assertAlmostEqual(m.f1, 2 * (1 / 3) * 0.5 / (1 / 3 + 0.5), places=3)
        # Reported at the end of bucket 105: 6 minutes after the event started.
        self.assertEqual(m.mean_delay_minutes, 6.0)
        self.assertAlmostEqual(m.false_alarms_per_day, 2.0, places=3)
        self.assertEqual([o.detected for o in m.outcomes], [True, False])

    def test_tolerance_extends_the_event_window(self):
        det = buckets({135: 0.9})
        self.assertEqual(score(det, labels(("spike", 100, 130))).detected, 0)
        m = score(det, labels(("spike", 100, 130)), tolerance_minutes=10)
        self.assertEqual((m.detected, m.false_alarms), (1, 0))

    def test_alarm_before_the_event_has_zero_delay(self):
        m = score(buckets({95: 0.9, 96: 0.9}), labels(("spike", 100, 130)), tolerance_minutes=5)
        self.assertEqual(m.mean_delay_minutes, 0.0)

    def test_threshold_and_min_consecutive_use_the_detection_rule(self):
        det = buckets({10: 0.3, 11: 0.3, 50: 0.9, 51: 0.9, 52: 0.9})
        self.assertEqual(len(alarms(reported(det, None, 1))), 2)
        self.assertEqual(len(alarms(reported(det, 0.5, 1))), 1)
        self.assertEqual(len(alarms(reported(det, None, 3))), 1)
        self.assertEqual(reported(det, None, 3)[0].start, minutes(50))

    def test_event_types_ignore_other_events(self):
        det = buckets({105: 0.9, 605: 0.9})
        both = labels(("brute_force", 100, 130), ("lateral_movement", 600, 650))
        m = score(det, both, event_types=["brute_force"])
        # The alarm on the lateral movement is neither a true nor a false alarm.
        self.assertEqual((m.events, m.detected, m.alarms, m.false_alarms, m.ignored_events), (1, 1, 1, 0, 1))
        self.assertEqual(m.precision, 1.0)

    def test_events_outside_the_scored_span_are_not_counted(self):
        det = buckets({}, total=100)  # covers minutes 0-100 only
        m = score(det, labels(("spike", 50, 60), ("spike", 500, 510)))
        self.assertEqual((m.events, m.unscored_events, m.recall, m.precision, m.f1), (1, 1, 0.0, None, 0.0))

    def test_detections_outside_the_labelled_span_are_ignored(self):
        # A detector that also scored its training day: its alarms there are not false alarms of the test split.
        det = buckets({100: 0.9, 1500: 0.9}, total=2880)
        m = score(det, labels(("spike", 1500, 1510), span=(1440, 2880)))
        self.assertEqual((m.alarms, m.false_alarms, m.detected, m.days), (1, 0, 1, 1.0))

    def test_external_intervals_of_any_width(self):
        det = [Detection(minutes(0), minutes(10), False, 0.0), Detection(minutes(10), minutes(20), True, 0.8), Detection(minutes(20), minutes(30), True, 0.7)]
        m = score(det, labels(("spike", 12, 15)))
        self.assertEqual((m.alarms, m.detected, m.mean_delay_minutes), (1, 1, 8.0))


class TestCalibrate(unittest.TestCase):
    def test_best_f1_within_the_false_alarm_budget(self):
        # Events get long high-severity runs; noise is single low-severity buckets.
        flagged = {i: 0.9 for r in (range(100, 110), range(700, 710)) for i in r}
        flagged.update({i: 0.3 for i in range(200, 1400, 50) if i not in flagged})
        cal = calibrate(buckets(flagged), labels(("spike", 100, 110), ("spike", 700, 710)))
        self.assertTrue(cal.within_false_alarm_budget)
        self.assertEqual(cal.validation.f1, 1.0)
        self.assertEqual(cal.validation.false_alarms, 0)
        # The least filtering that removes the noise: the lowest threshold above 0.3, or a run length of 2.
        self.assertEqual((cal.threshold, cal.min_consecutive), (None, 2))

    def test_no_setting_within_the_budget(self):
        # The noise looks exactly like the events: nothing separates them.
        flagged = {i + j: 1.0 for i in range(0, 1440, 20) for j in range(6)}
        cal = calibrate(buckets(flagged), labels(("spike", 0, 6)), max_false_alarms_per_day=5)
        self.assertFalse(cal.within_false_alarm_budget)
        self.assertEqual(cal.validation.false_alarms, 71)


class TestFiles(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)

    def test_labels_round_trip_and_validation(self):
        lab = labels(("spike", 10, 20), span=(0, 1440))
        path = self.root / "labels.json"
        lab.write(str(path))
        again = Labels.from_file(str(path))
        self.assertEqual((again.events, again.span_start, again.span_end), (lab.events, lab.span_start, lab.span_end))
        with self.assertRaises(ValueError):
            Labels.from_dict({"events": [{"start": minutes(5).isoformat(), "end": minutes(5).isoformat()}]})
        with self.assertRaises(ValueError):
            Labels.from_dict({"format": "other/2", "events": []})

    def test_opensearch_anomaly_detection_results(self):
        start = int(minutes(0).timestamp() * 1000)
        hits = [
            {"_source": {"detector_id": "d", "data_start_time": start, "data_end_time": start + 600_000, "anomaly_grade": 0.0, "confidence": 0.9}},
            {"_source": {"detector_id": "d", "data_start_time": start + 600_000, "data_end_time": start + 1_200_000, "anomaly_grade": 0.7, "confidence": 0.9}},
            {"_source": {"detector_id": "d", "data_start_time": start + 1_200_000, "data_end_time": start + 1_800_000, "error": "no data"}},
        ]
        path = self.root / "ad.json"
        path.write_text(json.dumps({"hits": {"hits": hits}}))
        det = load_external_detections(str(path))
        self.assertEqual(len(det), 2)
        self.assertEqual((det[1].start, det[1].end, det[1].is_anomaly, det[1].severity), (minutes(10), minutes(20), True, 0.7))
        self.assertFalse(det[0].is_anomaly)

    def test_generic_json_lines(self):
        path = self.root / "det.jsonl"
        path.write_text("\n".join(json.dumps({"start": minutes(i).isoformat(), "end": minutes(i + 1).isoformat(), "severity": s}) for i, s in ((0, 0.0), (1, 0.6))))
        det = load_external_detections(str(path))
        self.assertEqual([d.is_anomaly for d in det], [False, True])

    def _args(self, **kw):
        base = dict(
            scenario=None,
            config=None,
            backend=None,
            train_file=None,
            validation_file=None,
            validation_labels=None,
            test_file=None,
            test_labels=None,
            detections=None,
            validation_detections=None,
            detector_name="opensearch-ad",
            event_types=None,
            tolerance_minutes=0.0,
            max_false_alarms_per_day=5.0,
            output_dir=str(self.root / "out"),
            name=None,
        )
        base.update(kw)
        return argparse.Namespace(**base)

    def test_evaluate_external_detections_writes_json_and_markdown(self):
        records = [{"start": minutes(i).isoformat(), "end": minutes(i + 1).isoformat(), "severity": 0.8 if 100 <= i < 105 else 0.0} for i in range(1440)]
        det = self.root / "det.json"
        det.write_text(json.dumps(records))
        lab = self.root / "labels.json"
        labels(("spike", 100, 110)).write(str(lab))
        args = self._args(detections=str(det), validation_detections=str(det), test_labels=str(lab), validation_labels=str(lab))
        self.assertEqual(cli.cmd_evaluate(args), 0)
        report = json.loads((self.root / "out" / "opensearch-ad.json").read_text())
        self.assertEqual([r["name"] for r in report["runs"]], ["test (configured)", "validation (calibrated)", "test (calibrated)"])
        self.assertEqual(report["runs"][-1]["metrics"]["f1"], 1.0)
        self.assertEqual(report["anomaly_confidence"], 1.0)
        self.assertIn("| test (calibrated) |", (self.root / "out" / "opensearch-ad.md").read_text())

    def test_evaluate_needs_matching_validation_inputs(self):
        lab = self.root / "labels.json"
        labels(("spike", 1, 2)).write(str(lab))
        self.assertEqual(cli.cmd_evaluate(self._args(detections=str(lab), test_labels=str(lab), validation_labels=str(lab))), 1)
        self.assertEqual(cli.cmd_evaluate(self._args(scenario="x", test_labels=str(lab))), 1)
        self.assertEqual(cli.cmd_evaluate(self._args(test_labels=str(lab))), 1)

    def test_markdown_summary_handles_missing_values(self):
        text = render_markdown({"detector": "x", "runs": [{"name": "test (configured)", "threshold": None, "min_consecutive": 1, "metrics": score([], labels(("spike", 1, 2), span=(0, 1440))).to_dict()}]})
        self.assertIn("n/a", text)


class TestEvaluateScenarioEWMA(unittest.TestCase):
    """``sonar evaluate --scenario`` end to end with the fast ewma backend on generated data."""

    def test_scenario_run(self):
        import random

        from tests.sonartests.e2e_data import metric_alerts, write_alerts

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            rng = random.Random(3)
            write_alerts(root / "train.json", metric_alerts(pd.Timestamp("2024-12-01T00:00:00Z"), 600, rng))
            test = metric_alerts(pd.Timestamp("2024-12-02T00:00:00Z"), 400, rng, spikes=[(250, 270)])
            write_alerts(root / "test.json", test)
            Labels.from_dict({"events": [{"id": "s", "type": "cpu_spike", "start": "2024-12-02T04:10:00Z", "end": "2024-12-02T04:30:00Z"}]}).write(str(root / "labels.json"))
            scenario = root / "scenario.yaml"
            scenario.write_text("name: eval\ntraining:\n  backend: ewma\n  numeric_fields: ['data.cpu_usage_%']\n  bucket_minutes: 1\n  derived_features: false\n" "detection:\n  min_consecutive: 1\n")
            args = argparse.Namespace(
                scenario=str(scenario),
                config=None,
                backend=None,
                train_file=str(root / "train.json"),
                validation_file=None,
                validation_labels=None,
                test_file=str(root / "test.json"),
                test_labels=str(root / "labels.json"),
                detections=None,
                validation_detections=None,
                detector_name="external",
                event_types=None,
                tolerance_minutes=0.0,
                max_false_alarms_per_day=5.0,
                output_dir=str(root / "out"),
                name=None,
            )
            self.assertEqual(cli.cmd_evaluate(args), 0)
            report = json.loads((root / "out" / "eval-ewma.json").read_text())
            self.assertEqual(report["backend"], "ewma")
            m = report["runs"][0]["metrics"]
            self.assertEqual((m["events"], m["detected"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
