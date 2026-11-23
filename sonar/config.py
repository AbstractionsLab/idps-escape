"""
Configuration dataclasses for SONAR pipeline.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from sonar.paths import DEFAULT_MODEL_NAME, STATE_SUBDIR, model_dir, packaged


@dataclass
class WazuhIndexerConfig:
    """Configuration for Wazuh Indexer (OpenSearch) connection."""

    base_url: str = "https://localhost:9200"
    username: str = "admin"
    password: str = "admin"
    verify_ssl: Union[bool, str] = False
    """False: no certificate check; True: the system trust store; a path: that CA bundle (e.g. Wazuh's root-ca.pem)."""
    alerts_index_pattern: str = "wazuh-alerts-*"
    anomalies_index: str = "wazuh-anomalies-mvad"
    timeout_seconds: float = 30.0
    """Timeout for every HTTP request to the indexer."""
    max_alerts: int = 2_000_000
    """Most alerts one search returns; a longer result keeps the most recent alerts, with a warning."""
    exclude_rule_groups: List[str] = field(default_factory=lambda: ["sonar"])
    """Alerts in any of these rule groups are never read, so SONAR does not learn from its own alerts. [] disables."""


@dataclass
class MVADConfig:
    """Configuration for Multivariate Anomaly Detector model."""

    sliding_window: int = 200
    device: str = "cpu"
    # Any other MultiADConfig field of the MVAD library (validated in sonar.training_plan)
    extra_params: Dict[str, Any] = field(default_factory=dict)
    # Warn when the library would perform fewer optimiser updates than this
    min_gradient_steps: int = 500

    def to_params(self) -> Dict[str, Any]:
        """Convert to parameter dictionary for model initialization."""
        params = {
            "sliding_window": self.sliding_window,
            "device": self.device,
        }
        params.update(self.extra_params)
        return params


@dataclass
class EWMAConfig:
    """The ``ewma`` baseline backend: EWMA-smoothed features scored with a robust z-score."""

    alpha: float = 0.5
    """EWMA smoothing factor (0 < alpha <= 1); 1 means no smoothing."""

    z_threshold: float = 4.0
    """Robust z-score (distance to the training median in scaled MADs) from which a bucket is anomalous."""


@dataclass
class PCAConfig:
    """The ``pca`` backend: probabilistic PCA on lagged windows of standardised features (see ``sonar.backends.pca``)."""

    window: int = 3
    """Buckets in the window that scores a bucket (the bucket and the ``window - 1`` before it)."""

    variance: float = 0.95
    """Share of the training variance the principal components keep (0 < variance < 1); the rest is modelled as noise."""

    z_threshold: float = 4.0
    """Robust z-score of a window's distance, against the training windows' distances, from which a bucket is anomalous."""


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

    # Categorical fields counted per value. Each entry is a dotted path into the alert
    # document (e.g. "rule.id" or "rule.groups"); for a list value each element counts.
    # The top-k most frequent training values get a column each (the vocabulary, stored
    # in the model); every other value, including ones unseen in training, is counted in
    # "<field>__other".
    categorical_fields: Sequence[str] = field(default_factory=tuple)
    categorical_top_k: int = 10

    # Derived features (per-bucket counts of alerts matching a rule-group or threshold
    # condition, see sonar.features.DERIVED_FEATURES): True for all, False for none, or a
    # list of names.
    derived_features: Union[bool, Sequence[str]] = True

    # How to fill numeric means and maxima in buckets where no alert carries the field:
    # "zero" or "ffill" (carry the last value forward, for gauge metrics such as CPU).
    numeric_fill: str = "zero"

    # Transform applied to count columns: "none" or "log1p" (compresses bursts).
    count_transform: str = "none"

    # Optional OpenSearch query fragment forwarded to search_alerts(query=...).
    # Use to restrict ingestion to a specific rule group, e.g.:
    #   {"terms": {"rule.groups": ["performance_metric"]}}
    # When None, all alerts in the time window are returned (no extra filter).
    alert_filter: Optional[Dict[str, Any]] = None

    # Numeric fields for which an additional per-bucket *max* column is computed
    # alongside the default per-bucket mean. Each entry produces a column named
    # "<field>__max" in the feature matrix. Useful for detecting brief spikes
    # (e.g., a 55-second CPU burst) that would be smoothed away by averaging.
    max_numeric_fields: Sequence[str] = field(default_factory=tuple)


@dataclass
class DebugConfig:
    """Configuration for debug/offline mode without Wazuh instance."""

    enabled: bool = False
    """Enable debug mode (uses local test data instead of Wazuh)."""

    data_dir: str = str(packaged("test_data", "synthetic_alerts"))
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

    rollover_days: int = 7
    """Age at which a data stream's write index rolls over (ISM policy)."""

    retention_days: int = 30
    """Age at which a data stream's backing index is deleted (ISM policy)."""


@dataclass
class WazuhSinkConfig:
    """The ``wazuh`` sink: anomalies as events for the Wazuh manager."""

    transport: str = "file"
    """``file``: SONAR runs on the manager host and appends to a file the manager reads;
    ``api``: SONAR runs elsewhere and posts to the Wazuh server API (``POST /events``)."""

    file_path: str = "/var/log/sonar/anomalies.json"
    """``file`` transport: the file the manager's ``<localfile>`` (log_format json) reads."""

    max_file_bytes: int = 10 * 1024 * 1024
    """``file`` transport: rotate the file when a write would make it larger than this."""

    backup_count: int = 5
    """``file`` transport: rotated files kept (``anomalies.json.1`` ...)."""

    api_url: str = "https://localhost:55000"
    """``api`` transport: Wazuh server API URL."""

    api_username: str = "sonar"
    """``api`` transport: API user, ideally one whose role allows only ``event:ingest``."""

    api_password: str = ""
    """``api`` transport: API password; empty reads the SONAR_WAZUH_API_PASSWORD environment variable."""

    verify_ssl: Union[bool, str] = False
    """``api`` transport: False, True (system trust store) or a CA bundle path."""

    timeout_seconds: float = 30.0
    """``api`` transport: timeout per request."""

    severity_medium: float = 0.5
    """Lowest severity of the ``medium`` band (Wazuh rules match bands, they cannot compare numbers)."""

    severity_high: float = 0.8
    """Lowest severity of the ``high`` band."""


@dataclass
class OutputConfig:
    """Where SONAR delivers anomalies, and where it keeps its delivery state."""

    sinks: List[str] = field(default_factory=lambda: ["wazuh"])
    """Sinks every anomaly goes to: wazuh, datastream, index, jsonl, stdout. ``--ship`` adds datastream."""

    fallback: str = "none"
    """Sink that takes the anomalies a configured sink rejected: none, datastream or index."""

    debug_sinks: List[str] = field(default_factory=lambda: ["stdout"])
    """Sinks used instead of ``sinks`` with ``--debug`` (any sink but ``index``); e.g. [wazuh] sends the
    local test data's anomalies to a lab manager."""

    jsonl_path: Optional[str] = None
    """File of the ``jsonl`` sink; None: ``anomalies.jsonl`` in the SONAR home."""

    wazuh: WazuhSinkConfig = field(default_factory=WazuhSinkConfig)
    """Settings of the ``wazuh`` sink."""

    state_dir: Optional[str] = None
    """Directory of the per-scenario delivery watermarks; None: a ``state/`` directory next to the model."""


@dataclass
class PipelineConfig:
    """Complete pipeline configuration combining all components."""

    wazuh: WazuhIndexerConfig = field(default_factory=WazuhIndexerConfig)
    mvad: MVADConfig = field(default_factory=MVADConfig)
    features: FeatureConfig = field(default_factory=FeatureConfig)
    debug: DebugConfig = field(default_factory=DebugConfig)
    shipping: ShippingConfig = field(default_factory=ShippingConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    ewma: EWMAConfig = field(default_factory=EWMAConfig)
    pca: PCAConfig = field(default_factory=PCAConfig)
    backend: str = "mvad"
    """Detector backend trained by ``sonar train``: ``mvad``, ``pca`` or ``ewma`` (a loaded model brings its own)."""
    models_dir: Optional[str] = None
    """Directory of the models; None: ``models/`` in the SONAR home (see ``sonar.paths``)."""
    model_name: str = DEFAULT_MODEL_NAME
    """The model is the directory ``<models_dir>/<model_name>``."""
    agent: Optional[str] = None
    """Only this agent's alerts (``agent.name``), set by ``--agent``: one model per host, like RADAR's per-entity detectors."""

    @property
    def model_path(self) -> str:
        """
        The model's directory, ``<models_dir>/<model_name>``.

        Raises:
            ValueError: For a model named like the default state directory (``state``).
        """
        if self.model_name == STATE_SUBDIR and not self.output.state_dir:
            raise ValueError(f"model_name '{STATE_SUBDIR}' is reserved for the delivery state directory <models_dir>/{STATE_SUBDIR}; choose another name or set output.state_dir")
        return str(model_dir(self.models_dir, self.model_name))

    @model_path.setter
    def model_path(self, value: str) -> None:
        path = Path(value)
        self.models_dir = str(path.parent)
        self.model_name = path.stem if path.suffix == ".pkl" else path.name
