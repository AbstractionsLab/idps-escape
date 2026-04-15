"""
Use-case scenario configuration for SONAR (SIEM-Oriented Neural Anomaly Recognition).

Allows users to define training and detection workflows in YAML files,
supporting historical, real-time, and batch detection modes.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Literal
import yaml
import logging

logger = logging.getLogger(__name__)


@dataclass
class TrainingScenario:
    """Training phase configuration."""

    lookback_hours: int = 24
    """Hours of historical data to use for training."""

    numeric_fields: List[str] = field(default_factory=lambda: ["rule.level"])
    """Wazuh alert fields to extract as numeric features."""

    categorical_fields: List[str] = field(default_factory=list)
    """Optional categorical fields for one-hot encoding."""

    categorical_top_k: int = 10
    """Keep top-k categories; group rest into '__other'."""

    bucket_minutes: int = 5
    """Time-series aggregation bucket size."""

    sliding_window: int = 200
    """MVAD sliding window size."""

    device: str = "cpu"
    """Compute device: 'cpu' or 'cuda'."""

    extra_params: Dict[str, Any] = field(default_factory=dict)
    """Additional parameters for MVAD."""

    fill_with_synthetic: bool = False
    """Enable synthetic alert ingestion if history sparse."""

    synthetic_count: int = 100
    """Number of synthetic alerts to generate."""

    synthetic_mode: Literal["constant", "random", "copy"] = "random"
    """Synthetic generation mode."""

    synthetic_level: int = 5
    """Rule level for constant synthetic mode."""

    synthetic_srcip: str = "192.0.2.0"
    """Source IP for synthetic alerts."""

    derived_features: bool = True
    """Enable derived security/resource features in the feature matrix."""

    alert_filter: Optional[Dict[str, Any]] = None
    """Optional OpenSearch query fragment to filter alerts on ingestion (e.g. by rule.groups)."""

    max_numeric_fields: List[str] = field(default_factory=list)
    """Numeric fields for which a per-bucket max column (<field>__max) is also computed."""


@dataclass
class DetectionScenario:
    """Detection/prediction phase configuration."""

    mode: Literal["historical", "realtime", "batch"] = "historical"
    """
    Detection mode:
    - 'historical': one-shot detection on past data
    - 'realtime': continuous polling until user stops
    - 'batch': run detection once then exit
    """

    lookback_minutes: int = 10
    """Minutes of historical data to detect on."""

    polling_interval_seconds: Optional[int] = None
    """
    For 'realtime' mode: polling interval in seconds.
    If None, defaults to bucket_minutes * 60.
    """

    fill_with_synthetic: bool = False
    """Enable synthetic fill for detection."""

    synthetic_count: int = 50
    """Number of synthetic alerts for detection."""

    print_payloads: bool = False
    """Print anomaly payloads before indexing."""

    dry_run: bool = False
    """Simulate indexing without sending to Wazuh."""

    payload_dir: Optional[str] = None
    """Directory to save payloads for inspection."""

    threshold: float = 0.85
    """Anomaly score threshold for classification (0.0-1.0)."""

    min_consecutive: int = 1
    """Minimum consecutive anomalous buckets required."""


@dataclass
class UseCase:
    """Complete use-case scenario combining training and detection."""

    name: str
    """Scenario name for logging."""

    description: str = ""
    """Human-readable scenario description."""

    model_name: str = None
    """Optional model name for saving/loading trained model. If None, auto-generated from scenario name."""

    training: TrainingScenario = field(default_factory=TrainingScenario)
    """Training phase configuration."""

    detection: DetectionScenario = field(default_factory=DetectionScenario)
    """Detection phase configuration."""

    enabled: bool = True
    """Whether this use case is enabled."""

    has_training: bool = False
    """Whether training section was explicitly provided in YAML."""

    has_detection: bool = False
    """Whether detection section was explicitly provided in YAML."""

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "UseCase":
        """
        Load a use-case scenario from a YAML file.

        Args:
            yaml_path: Path to the YAML file.

        Returns:
            UseCase instance.

        Raises:
            ValueError: If YAML is invalid or missing required fields.
        """
        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f) or {}
        except FileNotFoundError as e:
            raise ValueError(f"Use case file not found: {yaml_path}") from e
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {yaml_path}: {e}") from e

        if not isinstance(data, dict):
            raise ValueError(f"Use case YAML must be a dictionary, got {type(data)}")

        # Extract top-level fields
        name = data.get("name", "unnamed_scenario")
        description = data.get("description", "")
        model_name = data.get("model_name", None)
        enabled = data.get("enabled", True)

        # Parse training config
        training_data = data.get("training", {})
        training = TrainingScenario(
            lookback_hours=training_data.get("lookback_hours", 24),
            numeric_fields=training_data.get("numeric_fields", ["rule.level"]),
            categorical_fields=training_data.get("categorical_fields", []),
            categorical_top_k=training_data.get("categorical_top_k", 10),
            bucket_minutes=training_data.get("bucket_minutes", 5),
            sliding_window=training_data.get("sliding_window", 200),
            device=training_data.get("device", "cpu"),
            extra_params=training_data.get("extra_params", {}),
            fill_with_synthetic=training_data.get("fill_with_synthetic", False),
            synthetic_count=training_data.get("synthetic_count", 100),
            synthetic_mode=training_data.get("synthetic_mode", "random"),
            synthetic_level=training_data.get("synthetic_level", 5),
            synthetic_srcip=training_data.get("synthetic_srcip", "192.0.2.0"),
            derived_features=training_data.get("derived_features", True),
            alert_filter=training_data.get("alert_filter", None),
            max_numeric_fields=training_data.get("max_numeric_fields", []),
        )

        # Parse detection config
        detection_data = data.get("detection", {})
        detection = DetectionScenario(
            mode=detection_data.get("mode", "historical"),
            lookback_minutes=detection_data.get("lookback_minutes", 10),
            polling_interval_seconds=detection_data.get("polling_interval_seconds"),
            fill_with_synthetic=detection_data.get("fill_with_synthetic", False),
            synthetic_count=detection_data.get("synthetic_count", 50),
            print_payloads=detection_data.get("print_payloads", False),
            dry_run=detection_data.get("dry_run", False),
            payload_dir=detection_data.get("payload_dir"),
            threshold=detection_data.get("threshold", 0.85),
            min_consecutive=detection_data.get("min_consecutive", 1),
        )

        return cls(
            name=name,
            description=description,
            model_name=model_name,
            training=training,
            detection=detection,
            enabled=enabled,
            has_training="training" in data,
            has_detection="detection" in data,
        )

    def to_yaml(self, yaml_path: str) -> None:
        """
        Save use-case scenario to a YAML file.

        Args:
            yaml_path: Path to save the YAML file.
        """
        data = {
            "name": self.name,
            "description": self.description,
            "model_name": self.model_name,
            "enabled": self.enabled,
            "training": {
                "lookback_hours": self.training.lookback_hours,
                "numeric_fields": self.training.numeric_fields,
                "categorical_fields": self.training.categorical_fields,
                "categorical_top_k": self.training.categorical_top_k,
                "bucket_minutes": self.training.bucket_minutes,
                "sliding_window": self.training.sliding_window,
                "device": self.training.device,
                "extra_params": self.training.extra_params,
                "fill_with_synthetic": self.training.fill_with_synthetic,
                "synthetic_count": self.training.synthetic_count,
                "synthetic_mode": self.training.synthetic_mode,
                "synthetic_level": self.training.synthetic_level,
                "synthetic_srcip": self.training.synthetic_srcip,
                "derived_features": self.training.derived_features,
                "alert_filter": self.training.alert_filter,
                "max_numeric_fields": self.training.max_numeric_fields,
            },
            "detection": {
                "mode": self.detection.mode,
                "lookback_minutes": self.detection.lookback_minutes,
                "polling_interval_seconds": self.detection.polling_interval_seconds,
                "fill_with_synthetic": self.detection.fill_with_synthetic,
                "synthetic_count": self.detection.synthetic_count,
                "print_payloads": self.detection.print_payloads,
                "dry_run": self.detection.dry_run,
                "payload_dir": self.detection.payload_dir,
                "threshold": self.detection.threshold,
                "min_consecutive": self.detection.min_consecutive,
            },
        }

        with open(yaml_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        logger.info("Use case saved to %s", yaml_path)
