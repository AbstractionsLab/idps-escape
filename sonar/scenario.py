"""
Use-case scenario configuration for SONAR (SIEM-Oriented Neural Anomaly Recognition).

Allows users to define training and detection workflows in YAML files,
supporting historical, real-time, and batch detection modes.
"""

import logging
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Literal, Optional, Union

import yaml

logger = logging.getLogger(__name__)

# Top-level keys of a scenario file. wazuh/debug/shipping/output are applied to PipelineConfig in sonar.cli.
TOP_LEVEL_KEYS = {"name", "description", "model_name", "models_dir", "enabled", "training", "detection", "wazuh", "debug", "shipping", "output"}

# Keys of removed features, with the reason they are ignored.
OBSOLETE_KEYS = {key: "synthetic fill was removed: SONAR no longer writes alerts to Wazuh" for key in ("fill_with_synthetic", "synthetic_count", "synthetic_mode", "synthetic_level", "synthetic_srcip")}


def _warn_unknown_keys(source: str, section: str, data: Dict[str, Any], allowed: set) -> None:
    """Log a warning for every key SONAR does not recognise (it would otherwise be ignored silently)."""
    if not isinstance(data, dict):
        return
    for key in sorted(set(data) - set(allowed)):
        if key in OBSOLETE_KEYS:
            logger.warning("%s: obsolete key '%s' in %s section is ignored (%s)", source, key, section, OBSOLETE_KEYS[key])
        else:
            logger.warning("%s: unknown key '%s' in %s section is ignored", source, key, section)


def _validate_threshold(source: str, value: Any) -> Optional[float]:
    """A detection threshold is a minimum severity in [0, 1], or None."""
    if value is None:
        return None
    try:
        threshold = float(value)
    except (TypeError, ValueError) as e:
        raise ValueError(f"{source}: detection.threshold must be a number between 0 and 1 or null; got {value!r}") from e
    if not 0.0 <= threshold <= 1.0:
        raise ValueError(f"{source}: detection.threshold is a minimum severity between 0 and 1; got {threshold}")
    return threshold


def _validate_backend(source: str, value: Any) -> Optional[str]:
    """training.backend is one of the registered detector backends."""
    from sonar.backends import BACKEND_NAMES

    if value is not None and value not in BACKEND_NAMES:
        raise ValueError(f"{source}: training.backend must be one of {', '.join(BACKEND_NAMES)}; got {value!r}")
    return value


def _validate_fraction(source: str, key: str, value: Any) -> Optional[float]:
    """A detection setting between 0 and 1, or None."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.0 <= float(value) <= 1.0:
        raise ValueError(f"{source}: detection.{key} must be a number between 0 and 1 or null; got {value!r}")
    return float(value)


def _validate_int_setting(source: str, key: str, value: Any, minimum: int) -> int:
    """An integer detection setting with a lower bound."""
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{source}: detection.{key} must be an integer of at least {minimum}; got {value!r}")
    return value


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

    derived_features: Union[bool, List[str]] = True
    """Derived features to add: True (all), False (none) or a list of names (see sonar.features.DERIVED_FEATURES)."""

    numeric_fill: str = "zero"
    """Fill for numeric means/maxima in buckets where no alert carries the field: 'zero' or 'ffill'."""

    count_transform: str = "none"
    """Transform for count columns: 'none' or 'log1p'."""

    alert_filter: Optional[Dict[str, Any]] = None
    """Optional OpenSearch query fragment to filter alerts on ingestion (e.g. by rule.groups)."""

    max_numeric_fields: List[str] = field(default_factory=list)
    """Numeric fields for which a per-bucket max column (<field>__max) is also computed."""

    min_gradient_steps: int = 500
    """Warn when MVAD would perform fewer optimiser updates than this during training."""

    backend: Optional[str] = None
    """Detector backend: 'mvad' (multivariate deep model), 'pca' (multivariate linear model, no torch) or 'ewma' (per-feature baseline, no torch).
    None: the configuration's ``backend`` (mvad by default)."""

    ewma: Dict[str, Any] = field(default_factory=dict)
    """Settings of the ewma backend (alpha, z_threshold; see sonar.config.EWMAConfig)."""

    pca: Dict[str, Any] = field(default_factory=dict)
    """Settings of the pca backend (window, variance, z_threshold; see sonar.config.PCAConfig)."""


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
    """Minutes of complete buckets to score, ending at the last complete bucket. The context
    MVAD needs before them is fetched automatically."""

    polling_interval_seconds: Optional[int] = None
    """
    For 'realtime' mode: fixed polling interval in seconds.
    If None, each poll runs once the next bucket has ended (plus ingest_delay_seconds).
    """

    ingest_delay_seconds: int = 60
    """Seconds a bucket must have ended before it is scored, so that alerts indexed late are counted."""

    max_consecutive_failures: int = 5
    """For 'realtime' mode: stop with exit code 1 after this many failed polls in a row."""

    print_payloads: bool = False
    """Print anomaly payloads before indexing."""

    dry_run: bool = False
    """Simulate indexing without sending to Wazuh."""

    payload_dir: Optional[str] = None
    """Directory to save payloads for inspection."""

    threshold: Optional[float] = None
    """Minimum MVAD severity (0-1) a bucket needs, on top of MVAD's own anomaly decision. None: MVAD's decision alone."""

    min_consecutive: int = 1
    """Minimum consecutive anomalous buckets required."""

    anomaly_confidence: Optional[float] = None
    """How far this scenario's anomalies can be trusted (0-1), sent to Wazuh as ``anomaly_confidence``
    next to the severity. Set it to the scenario's measured precision. None: uncalibrated, 0.5 is sent."""


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

        # An empty YAML key (e.g. "categorical_fields:" with only comments under it)
        # loads as None; treat it like an absent key so the dataclass default applies.
        def _get(section: Dict[str, Any], key: str, default: Any) -> Any:
            value = section.get(key)
            return default if value is None else value

        _warn_unknown_keys(yaml_path, "top level", data, TOP_LEVEL_KEYS)

        # Parse training config
        training_data = data.get("training") or {}
        _warn_unknown_keys(yaml_path, "training", training_data, {f.name for f in fields(TrainingScenario)})
        training = TrainingScenario(
            lookback_hours=_get(training_data, "lookback_hours", 24),
            numeric_fields=_get(training_data, "numeric_fields", ["rule.level"]),
            categorical_fields=_get(training_data, "categorical_fields", []),
            categorical_top_k=_get(training_data, "categorical_top_k", 10),
            bucket_minutes=_get(training_data, "bucket_minutes", 5),
            sliding_window=_get(training_data, "sliding_window", 200),
            device=_get(training_data, "device", "cpu"),
            extra_params=_get(training_data, "extra_params", {}),
            derived_features=_get(training_data, "derived_features", True),
            alert_filter=_get(training_data, "alert_filter", None),
            max_numeric_fields=_get(training_data, "max_numeric_fields", []),
            numeric_fill=_get(training_data, "numeric_fill", "zero"),
            count_transform=_get(training_data, "count_transform", "none"),
            min_gradient_steps=_get(training_data, "min_gradient_steps", 500),
            backend=_validate_backend(yaml_path, training_data.get("backend")),
            ewma=_get(training_data, "ewma", {}),
            pca=_get(training_data, "pca", {}),
        )

        # Parse detection config
        detection_data = data.get("detection") or {}
        _warn_unknown_keys(yaml_path, "detection", detection_data, {f.name for f in fields(DetectionScenario)})
        detection = DetectionScenario(
            mode=_get(detection_data, "mode", "historical"),
            lookback_minutes=_get(detection_data, "lookback_minutes", 10),
            polling_interval_seconds=detection_data.get("polling_interval_seconds"),
            ingest_delay_seconds=_validate_int_setting(yaml_path, "ingest_delay_seconds", _get(detection_data, "ingest_delay_seconds", 60), minimum=0),
            max_consecutive_failures=_validate_int_setting(yaml_path, "max_consecutive_failures", _get(detection_data, "max_consecutive_failures", 5), minimum=1),
            print_payloads=_get(detection_data, "print_payloads", False),
            dry_run=_get(detection_data, "dry_run", False),
            payload_dir=detection_data.get("payload_dir"),
            threshold=_validate_threshold(yaml_path, detection_data.get("threshold")),
            anomaly_confidence=_validate_fraction(yaml_path, "anomaly_confidence", detection_data.get("anomaly_confidence")),
            min_consecutive=_get(detection_data, "min_consecutive", 1),
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
                "derived_features": self.training.derived_features,
                "alert_filter": self.training.alert_filter,
                "max_numeric_fields": self.training.max_numeric_fields,
                "numeric_fill": self.training.numeric_fill,
                "count_transform": self.training.count_transform,
                "min_gradient_steps": self.training.min_gradient_steps,
                "backend": self.training.backend,
                "ewma": self.training.ewma,
                "pca": self.training.pca,
            },
            "detection": {
                "mode": self.detection.mode,
                "lookback_minutes": self.detection.lookback_minutes,
                "polling_interval_seconds": self.detection.polling_interval_seconds,
                "ingest_delay_seconds": self.detection.ingest_delay_seconds,
                "max_consecutive_failures": self.detection.max_consecutive_failures,
                "print_payloads": self.detection.print_payloads,
                "dry_run": self.detection.dry_run,
                "payload_dir": self.detection.payload_dir,
                "threshold": self.detection.threshold,
                "anomaly_confidence": self.detection.anomaly_confidence,
                "min_consecutive": self.detection.min_consecutive,
            },
        }

        with open(yaml_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        logger.info("Use case saved to %s", yaml_path)
