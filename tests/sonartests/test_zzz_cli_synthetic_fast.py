"""
Fast tests for CLI synthetic-fill behavior that avoid heavy external imports.
"""
import importlib.util
import sys
import types
import unittest
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

# Stub sonar.config.PipelineConfig and nested configs
adbox_config_stub = types.ModuleType("sonar.config")

class FeatureConfig:
    bucket_minutes = 5
    numeric_fields = ["rule.level"]

@dataclass
class MVADConfig:
    sliding_window: int = 10
    
    def to_params(self):
        return {"sliding_window": self.sliding_window}

class WazuhIndexerConfig:
    def __init__(self):
        self.base_url = "http://localhost:9200"
        self.username = "admin"
        self.password = "admin"
        self.verify_ssl = False
        self.alerts_index_pattern = "wazuh-alerts-*"
        self.anomalies_index = "wazuh-anomalies-mvad"

class DebugConfig:
    def __init__(self):
        self.enabled = False
        self.data_dir = "./test_data"

class PipelineConfig:
    def __init__(self):
        self.wazuh = types.SimpleNamespace(
            base_url="http://localhost:9200",
            username="admin",
            password="admin",
            verify_ssl=False,
            alerts_index_pattern="wazuh-alerts-*",
            anomalies_index="wazuh-anomalies-mvad",
        )
        self.mvad = MVADConfig()
        self.features = FeatureConfig()
        self.debug = types.SimpleNamespace(
            enabled=False,
            data_dir="./test_data"
        )
        self.model_path = "./mvad_model.pkl"

adbox_config_stub.FeatureConfig = FeatureConfig
adbox_config_stub.MVADConfig = MVADConfig
adbox_config_stub.WazuhIndexerConfig = WazuhIndexerConfig
adbox_config_stub.DebugConfig = DebugConfig
adbox_config_stub.PipelineConfig = PipelineConfig
sys.modules["sonar.config"] = adbox_config_stub

# Create stubs for sonar.* packages the CLI expects
# sonar.config is already stubbed above. Provide minimal modules for other imports.
adbox_engine_stub = types.ModuleType("sonar.engine")
adbox_engine_stub.MVADModelEngine = object  # placeholder; we'll patch in tests
sys.modules["sonar.engine"] = adbox_engine_stub

# Map sonar.features to the real implementation file (it will import our stubbed sonar.config)
spec_feat = importlib.util.spec_from_file_location("sonar.features.fast", "sonar/features.py")
feat_mod = importlib.util.module_from_spec(spec_feat)
spec_feat.loader.exec_module(feat_mod)
adbox_features_stub = types.ModuleType("sonar.features")
adbox_features_stub.WazuhFeatureBuilder = feat_mod.WazuhFeatureBuilder
sys.modules["sonar.features"] = adbox_features_stub

# Stub sonar.pipeline
adbox_pipeline_stub = types.ModuleType("sonar.pipeline")
class MVADPostProcessor:
    def __init__(self, cfg):
        self.cfg = cfg
    def build_wazuh_anomaly_docs(self, *args, **kwargs):
        return []
adbox_pipeline_stub.MVADPostProcessor = MVADPostProcessor
sys.modules["sonar.pipeline"] = adbox_pipeline_stub

# Stub sonar.wazuh_client to satisfy imports; tests will patch cli.WazuhIndexerClient to FakeClient
adbox_wazuh_stub = types.ModuleType("sonar.wazuh_client")
class DummyClient:
    def __init__(self, cfg):
        pass
adbox_wazuh_stub.WazuhIndexerClient = DummyClient
sys.modules["sonar.wazuh_client"] = adbox_wazuh_stub

# Load CLI module
spec = importlib.util.spec_from_file_location("sonar.cli.fast", "sonar/cli.py")
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)

class FakeClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.indexed = []
    def check_connection(self):
        return True
    def search_alerts(self, start, end):
        # return 3 alerts that map to 3 different buckets
        now = datetime.now(timezone.utc)
        return [
            {"timestamp": (now - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"), "rule": {"level": 3}, "srcip": "10.0.0.1"},
            {"timestamp": (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"), "rule": {"level": 4}, "srcip": "10.0.0.2"},
            {"timestamp": now.isoformat().replace("+00:00", "Z"), "rule": {"level": 5}, "srcip": "10.0.0.3"},
        ]
    def index_alert(self, doc):
        self.indexed.append(doc)
        return f"synthetic-{len(self.indexed)}"
    def index_anomaly(self, doc):
        return "anomaly-1"

class DummyEngine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.model = None
    def train(self, ts_data):
        # assert that training sees enough points (sliding_window+1)
        required = self.cfg.mvad.to_params()["sliding_window"] + 1
        if len(ts_data) < required:
            raise ValueError("not enough data passed to train")
        self.model = True
    def save(self):
        pass

class TestCLISyntheticFill(unittest.TestCase):
    def test_train_with_synthetic_fill(self):
        # Patch client and engine into cli module
        orig_client = cli.WazuhIndexerClient
        orig_engine = cli.MVADModelEngine
        try:
            cli.WazuhIndexerClient = FakeClient
            cli.MVADModelEngine = DummyEngine

            # Use explicit synthetic count and mode constant/level
            # Use a fake instance so we can assert what was indexed
            fake = FakeClient(None)
            cli.WazuhIndexerClient = lambda cfg: fake

            args = types.SimpleNamespace(
                config=None,
                lookback_hours=1,
                fill_with_synthetic=True,
                synthetic_count=8,  # ensure >= required (required=11-3=8)
                synthetic_mode="constant",
                synthetic_level=9.0,
                synthetic_srcip=None,
                debug=False,
            )
            rc = cli.cmd_train(args)
            self.assertEqual(rc, 0)
            # verify synthetic alerts were indexed and used the constant level
            self.assertGreaterEqual(len(fake.indexed), 8)
            for doc in fake.indexed:
                self.assertIn("rule", doc)
                self.assertEqual(float(doc["rule"]["level"]), 9.0)
        finally:
            cli.WazuhIndexerClient = orig_client
            cli.MVADModelEngine = orig_engine

    def test_train_with_random_mode_and_count(self):
        orig_client = cli.WazuhIndexerClient
        orig_engine = cli.MVADModelEngine
        try:
            fake = FakeClient(None)
            # Monkey-patch cli to use our fake instance via a small wrapper
            fake = FakeClient(None)
            cli.WazuhIndexerClient = lambda cfg: fake
            cli.MVADModelEngine = DummyEngine

            args = types.SimpleNamespace(
                config=None,
                lookback_hours=1,
                fill_with_synthetic=True,
                synthetic_count=3,
                synthetic_mode="random",
                synthetic_level=None,
                synthetic_srcip=None,
                debug=False,
            )
            rc = cli.cmd_train(args)
            self.assertEqual(rc, 0)
            # If requested count < required to reach sliding_window+1, CLI should
            # increase to the minimum required so training can proceed.
            required = cli.load_config(None).mvad.to_params()["sliding_window"] + 1
            existing = 3
            to_add = required - existing
            self.assertEqual(len(fake.indexed), to_add)
            # random mode should include generated srcip field
            for doc in fake.indexed:
                self.assertIn("srcip", doc)
        finally:
            cli.WazuhIndexerClient = orig_client
            cli.MVADModelEngine = orig_engine

    def test_train_without_fill_skips(self):
        orig_client = cli.WazuhIndexerClient
        orig_engine = cli.MVADModelEngine
        try:
            cli.WazuhIndexerClient = FakeClient
            cli.MVADModelEngine = DummyEngine

            args = types.SimpleNamespace(config=None, lookback_hours=1, fill_with_synthetic=False, debug=False)
            rc = cli.cmd_train(args)
            # Should exit successfully but skip training because insufficient data and no flag
            self.assertEqual(rc, 0)
        finally:
            cli.WazuhIndexerClient = orig_client
            cli.MVADModelEngine = orig_engine

    def test_detect_with_synthetic_fill(self):
        orig_client = cli.WazuhIndexerClient
        orig_engine = cli.MVADModelEngine
        try:
            # Fake client and a detector stub that records predictions
            fake = FakeClient(None)
            cli.WazuhIndexerClient = lambda cfg: fake

            class DummyDetector:
                def __init__(self, cfg):
                    self.cfg = cfg
                    self.predicted_on = None
                def load(self):
                    return None
                def predict(self, data):
                    self.predicted_on = data
                    return {"detected": 0}

            cli.MVADModelEngine = DummyDetector

            args = types.SimpleNamespace(
                config=None,
                lookback_minutes=10,
                fill_with_synthetic=True,
                synthetic_count=8,
                synthetic_mode="random",
                synthetic_level=None,
                synthetic_srcip=None,
                debug=False,
            )

            rc = cli.cmd_detect(args)
            self.assertEqual(rc, 0)
            # synthetic alerts should have been indexed to reach required count
            required = cli.load_config(None).mvad.to_params()["sliding_window"] + 1
            existing = 3
            to_add = required - existing
            self.assertEqual(len(fake.indexed), to_add)
            # ensure the detector received at least required number of time points
            # We can reconstruct timeseries via feature builder to verify
            fb = cli.WazuhFeatureBuilder(cli.load_config(None).features)
            ts = fb.build_timeseries(fake.search_alerts(None, None) + fake.indexed)
            self.assertGreaterEqual(len(ts), required)
            # Make sure predict ran (detector stored predicted_on)
            # Recreate detector instance to access stored value - in the CLI we don't keep instance
            # but we assert that cmd returned successfully and synthetic alerts exist
        finally:
            cli.WazuhIndexerClient = orig_client
            cli.MVADModelEngine = orig_engine

    def test_detect_without_fill_skips(self):
        orig_client = cli.WazuhIndexerClient
        orig_engine = cli.MVADModelEngine
        try:
            fake = FakeClient(None)
            cli.WazuhIndexerClient = lambda cfg: fake

            class DummyDetector:
                def __init__(self, cfg):
                    pass
                def load(self):
                    pass
                def predict(self, data):
                    return {}

            cli.MVADModelEngine = DummyDetector

            args = types.SimpleNamespace(config=None, lookback_minutes=10, fill_with_synthetic=False, debug=False)
            rc = cli.cmd_detect(args)
            # Should return 0 and not index any synthetic alerts
            self.assertEqual(rc, 0)
            self.assertEqual(len(fake.indexed), 0)
        finally:
            cli.WazuhIndexerClient = orig_client
            cli.MVADModelEngine = orig_engine

if __name__ == "__main__":
    unittest.main()
