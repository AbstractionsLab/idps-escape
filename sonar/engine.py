"""
The model engine: a trained detector backend plus the feature contract it was trained under.

A model is a directory ``<models_dir>/<model_name>/``:

- ``metadata.json``: format and SONAR versions, the backend's name and training record,
  the feature schema version, the FeatureConfig, the categorical vocabulary and the column
  order (the feature contract), and the number of training buckets;
- the backend's state files (``mvad_config.json`` and ``mvad_weights.pt``, ``pca_state.json`` or ``ewma_state.json``).

No file is unpickled when a model is loaded. Model files are still inputs to trust: protect
``models_dir`` as you would the configuration.
"""

import dataclasses
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from sonar import __version__ as SONAR_VERSION
from sonar.backends import DetectorBackend, PointResult, backend_class, new_backend
from sonar.config import FeatureConfig, PipelineConfig
from sonar.features import FEATURE_SCHEMA_VERSION, FeatureVocabulary

logger = logging.getLogger(__name__)

MODEL_FORMAT_VERSION = 1
METADATA_FILE = "metadata.json"


class IncompatibleModelError(ValueError):
    """Raised when a model file was trained on a feature layout or in a format this SONAR cannot use."""


class ModelEngine:
    """Train, save, load and run a detector backend under a fixed feature contract."""

    def __init__(self, cfg: PipelineConfig):
        self.cfg = cfg
        self.backend: Optional[DetectorBackend] = None
        self.training_columns: Optional[List[str]] = None
        self.metadata: Dict[str, Any] = {}
        self._training_samples = 0

    # ---------- training ----------

    def train(self, ts_data: pd.DataFrame, vocabulary: Optional[FeatureVocabulary] = None) -> None:
        """
        Train ``cfg.backend`` on a feature matrix.

        Args:
            ts_data: DataFrame with time index and numeric feature columns.
            vocabulary: Categorical vocabulary the features were built with; stored in the
                model so detection builds the same columns.

        Raises:
            ValueError: If the training data is empty or a backend parameter is invalid.
            InsufficientTrainingDataError: If the backend could not learn from this many buckets.
        """
        if ts_data.empty:
            raise ValueError("Training data is empty.")
        ts_data = ts_data.dropna()
        if len(ts_data) == 0:
            raise ValueError("Training data has no valid samples after removing NaN values.")

        backend = new_backend(self.cfg)
        backend.fit(ts_data)

        self.backend = backend
        self.training_columns = ts_data.columns.tolist()
        self._training_samples = len(ts_data)
        self.metadata = {
            "format_version": MODEL_FORMAT_VERSION,
            "sonar_version": SONAR_VERSION,
            "backend": backend.name,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_config": dataclasses.asdict(self.cfg.features),
            "vocabulary": (vocabulary or FeatureVocabulary()).to_dict(),
            "columns": list(self.training_columns),
            "training_samples": self._training_samples,
            **backend.metadata,
        }
        logger.info("Trained the %s backend on %d buckets x %d columns", backend.name, len(ts_data), len(self.training_columns))

    # ---------- model directory ----------

    def save(self) -> None:
        """
        Write the model directory, replacing an existing one only once the new one is complete.

        Raises:
            RuntimeError: If no model has been trained.
        """
        if self.backend is None:
            raise RuntimeError("No model to save; train first.")
        target = Path(self.cfg.model_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(dir=target.parent, prefix=f".{target.name}."))
        try:
            (staging / METADATA_FILE).write_text(json.dumps(self.metadata, indent=2, default=_json_default), encoding="utf-8")
            self.backend.save_state(staging)
            if target.exists():
                previous = target.with_name(f".{target.name}.previous")
                shutil.rmtree(previous, ignore_errors=True)
                os.replace(target, previous)
                os.replace(staging, target)
                shutil.rmtree(previous, ignore_errors=True)
            else:
                os.replace(staging, target)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        logger.info("Model saved to %s", target)

    def load(self) -> None:
        """
        Load the model directory.

        Raises:
            FileNotFoundError: If there is no model at ``cfg.model_path``.
            IncompatibleModelError: For a model in an older format or feature schema.
        """
        directory = Path(self.cfg.model_path)
        legacy = directory if directory.suffix == ".pkl" else directory.with_name(f"{directory.name}.pkl")
        if not (directory / METADATA_FILE).is_file():
            if legacy.is_file():
                target = directory.with_name(directory.name[: -len(".pkl")]) if directory.suffix == ".pkl" else directory
                raise IncompatibleModelError(f"{legacy} is a model in the old pickle format, which SONAR {SONAR_VERSION} no longer loads (unpickling can run code). Retrain the model; it will be saved as {target}/.")
            raise FileNotFoundError(f"No model at {directory}")

        metadata = json.loads((directory / METADATA_FILE).read_text(encoding="utf-8"))
        schema = metadata.get("feature_schema_version")
        if schema != FEATURE_SCHEMA_VERSION:
            raise IncompatibleModelError(f"Model {directory} was built with feature schema {schema or 'unknown'}, but this SONAR builds schema {FEATURE_SCHEMA_VERSION} features. Retrain the model with SONAR {SONAR_VERSION} or later.")
        if metadata.get("format_version") != MODEL_FORMAT_VERSION:
            raise IncompatibleModelError(f"Model {directory} has format version {metadata.get('format_version')}; this SONAR reads version {MODEL_FORMAT_VERSION}. Retrain the model.")

        self.backend = backend_class(metadata.get("backend", "mvad")).from_state(directory, metadata)
        self.metadata = metadata
        self.training_columns = metadata.get("columns")
        self._training_samples = int(metadata.get("training_samples", 0))
        if self.backend.name == "mvad" and metadata.get("gradient_steps", 0) < 1:
            logger.warning("Model %s records 0 gradient steps: it is untrained. Retrain it.", directory)
        logger.info("Loaded %s model %s (%d columns, %d training buckets)", self.backend.name, directory, len(self.training_columns or []), self._training_samples)

    # ---------- feature contract ----------

    @property
    def feature_config(self) -> Optional[FeatureConfig]:
        """FeatureConfig the model was trained with, or None if not recorded."""
        stored = self.metadata.get("feature_config")
        if not isinstance(stored, dict):
            return None
        known = set(FeatureConfig.__dataclass_fields__)
        return FeatureConfig(**{k: v for k, v in stored.items() if k in known})

    @property
    def vocabulary(self) -> FeatureVocabulary:
        """Categorical vocabulary the model was trained with."""
        return FeatureVocabulary.from_dict(self.metadata.get("vocabulary"))

    # ---------- window ----------

    def _backend(self) -> DetectorBackend:
        return self.backend if self.backend is not None else new_backend(self.cfg)

    @property
    def backend_name(self) -> str:
        return self._backend().name

    @property
    def sliding_window(self) -> int:
        """MVAD's sliding window (0 for backends without one)."""
        return int(getattr(self._backend(), "sliding_window", 0) or 0)

    @property
    def window(self) -> tuple:
        """MVAD's ``(input_size, threshold_window)``."""
        return self._backend().window

    @property
    def min_detection_points(self) -> int:
        """Fewest buckets the backend accepts at prediction time."""
        return int(self._backend().min_points)

    @property
    def context_buckets(self) -> int:
        """Buckets needed before the first bucket that gets a verdict."""
        return self.min_detection_points - 1

    # ---------- inference ----------

    def predict(self, ts_data: pd.DataFrame) -> List[PointResult]:
        """
        Verdicts for ``ts_data``, from bucket ``context_buckets`` on.

        Raises:
            RuntimeError: If no model has been trained or loaded.
            ValueError: If the data is empty, not numeric, or not the model's columns.
        """
        if self.backend is None:
            raise RuntimeError("Model not loaded; call load() or train().")
        if ts_data.empty:
            raise ValueError("Cannot predict on empty data.")
        numeric_cols = ts_data.select_dtypes(include=["number"]).columns.tolist()
        if not numeric_cols:
            raise ValueError("No numeric columns found in prediction data.")
        ts_clean = ts_data[numeric_cols].astype(float)

        # The feature contract (stored config and vocabulary) makes the detection columns
        # identical to the training columns. A difference is a bug: refuse rather than
        # zero-fill or drop columns, which used to hide exactly the columns that changed.
        if self.training_columns is not None:
            missing = [c for c in self.training_columns if c not in ts_clean.columns]
            extra = [c for c in ts_clean.columns if c not in self.training_columns]
            if missing or extra:
                raise ValueError(f"Detection features do not match the model's training columns (missing: {missing[:10]}, extra: {extra[:10]}). Build detection features with the model's feature config and vocabulary.")
            ts_clean = ts_clean[self.training_columns]

        ts_clean = ts_clean.fillna(0.0).replace([float("inf"), float("-inf")], 0.0)
        logger.debug("Prediction data: shape=%s, columns=%s", ts_clean.shape, ts_clean.columns.tolist())
        return self.backend.predict(ts_clean)


# The engine predates the backends, when MVAD was the only detector.
MVADModelEngine = ModelEngine


def _json_default(value: Any) -> Any:
    if hasattr(value, "item"):
        return value.item()
    if hasattr(value, "tolist"):
        return value.tolist()
    return str(value)
