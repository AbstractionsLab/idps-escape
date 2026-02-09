"""
Configuration dataclasses for SONAR pipeline.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Sequence


@dataclass
class WazuhIndexerConfig:
    """Configuration for Wazuh Indexer (OpenSearch) connection."""

    base_url: str = "https://localhost:9200"
    username: str = "admin"
    password: str = "admin"
    verify_ssl: bool = False  # set to CA bundle path in production
    alerts_index_pattern: str = "wazuh-alerts-*"
    anomalies_index: str = "wazuh-anomalies-mvad"


@dataclass
class MVADConfig:
    """Configuration for Multivariate Anomaly Detector model."""

    sliding_window: int = 200
    device: str = "cpu"
    # Add any extra params supported by the library here
    extra_params: Dict[str, Any] = field(default_factory=dict)

    def to_params(self) -> Dict[str, Any]:
        """Convert to parameter dictionary for model initialization."""
        params = {
            "sliding_window": self.sliding_window,
            "device": self.device,
        }
        params.update(self.extra_params)
        return params


@dataclass
class FeatureConfig:
    """Configuration for feature extraction from Wazuh alerts."""

    # Numeric fields we'll extract from each Wazuh alert
    # Adjust based on your environment and use case
    numeric_fields: Sequence[str] = (
        "rule.level",
        # You can add more numeric-ish fields via pre-processing, e.g.:
        # "network.failed_login_count",
        # "network.unique_srcip_count",
    )

    # Time bucket size for aggregating alerts into time points
    bucket_minutes: int = 5

    # Categorical fields to one-hot encode. Each entry is a dotted path
    # into the alert document (e.g. "rule.id" or "rule.groups"). If the
    # value is a list in the alert, each element will be treated as a
    # category. The top-k most frequent categories are retained and the
    # rest are grouped into an "__other" column.
    categorical_fields: Sequence[str] = field(default_factory=tuple)
    categorical_top_k: int = 10

    # Enable derived features for enhanced attack detection
    # These are computed from alert patterns, not raw fields
    derived_features: bool = True


@dataclass
class DebugConfig:
    """Configuration for debug/offline mode without Wazuh instance."""

    enabled: bool = False
    """Enable debug mode (uses local test data instead of Wazuh)."""

    data_dir: str = "./test_data/synthetic_alerts"
    """Directory containing test Wazuh alert JSON files."""

    training_data_file: str = "normal_baseline.json"
    """JSON file to use for training data in debug mode."""

    detection_data_file: str = "with_anomalies.json"
    """JSON file to use for detection data in debug mode."""


@dataclass
class ShippingConfig:
    """Configuration for data shipping to Wazuh data streams."""

    enabled: bool = False
    """Enable data shipping (ship anomalies to dedicated data streams)."""

    install_templates: bool = True
    """Install base templates on first run (disable if already installed)."""

    scenario_id: str = None
    """Optional custom scenario ID (auto-generated from model_path if None)."""


@dataclass
class PipelineConfig:
    """Complete pipeline configuration combining all components."""

    wazuh: WazuhIndexerConfig = field(default_factory=WazuhIndexerConfig)
    mvad: MVADConfig = field(default_factory=MVADConfig)
    features: FeatureConfig = field(default_factory=FeatureConfig)
    debug: DebugConfig = field(default_factory=DebugConfig)
    shipping: ShippingConfig = field(default_factory=ShippingConfig)
    model_path: str = "./mvad_model.pkl"
