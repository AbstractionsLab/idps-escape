"""
The ``mvad`` backend: Microsoft's multivariate anomaly detector (``time-series-anomaly-detector``
0.4.0), a graph-attention network that forecasts and reconstructs every feature.

The model file holds the library's configuration as JSON (``mvad_config.json``) and the
network's weights as a plain tensor dictionary (``mvad_weights.pt``), loaded with
``torch.load(weights_only=True)``: loading a model runs no code from the file. The library's
own checkpoint format (a pickle) is never used outside training.
"""

import dataclasses
import json
import logging
import tempfile
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from sonar.backends.base import Contributor, PointResult
from sonar.config import MVADConfig
from sonar.training_plan import InsufficientTrainingDataError, describe_shortfall, plan_training, validate_mvad_params, window_sizes

logger = logging.getLogger(__name__)

MVAD_LIBRARY = "time-series-anomaly-detector"
CONFIG_FILE = "mvad_config.json"
WEIGHTS_FILE = "mvad_weights.pt"

# Imported lazily (torch and mlflow are slow to import). Tests patch this name.
MultivariateAnomalyDetector = None


def package_version(name: str) -> str:
    """Installed version of a distribution, or 'unknown'."""
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return "unknown"


def _detector_class():
    if MultivariateAnomalyDetector is not None:
        return MultivariateAnomalyDetector
    from anomaly_detector import MultivariateAnomalyDetector as MAD  # type: ignore

    return MAD


def _as_float(value: Any) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def mvad_results_to_points(results: Any) -> List[PointResult]:
    """
    Convert the library's ``predict`` output (one dict per bucket) to PointResults.

    Raises:
        ValueError: If the output is not a list of per-bucket dicts.
    """
    if not isinstance(results, list):
        raise ValueError(f"Unexpected MVAD result format: expected a list of per-bucket dicts, got {type(results).__name__}")
    points = []
    for r in results:
        if not isinstance(r, dict) or "index" not in r:
            raise ValueError(f"Unexpected MVAD result entry: {r!r}")
        contributors = [Contributor(str(c.get("variable_name", "")), float(c.get("contribution_score", 0.0))) for c in r.get("interpretation") or []]
        points.append(
            PointResult(
                timestamp=pd.Timestamp(r["index"]),
                is_anomaly=bool(r.get("is_anomaly", False)),
                severity=float(r.get("severity", 0.0)),
                raw_score=float(r.get("score", 0.0)),
                contributors=contributors,
            )
        )
    return points


class MVADBackend:
    """MVAD behind the DetectorBackend contract."""

    name = "mvad"

    def __init__(self, cfg: Optional[MVADConfig] = None):
        self.cfg = cfg or MVADConfig()
        self.model: Any = None
        self.metadata: Dict[str, Any] = {}

    # ---------- window ----------

    @property
    def sliding_window(self) -> int:
        recorded = (self.metadata.get("mvad_params") or {}).get("sliding_window")
        return int(recorded if recorded is not None else self.cfg.sliding_window)

    @property
    def window(self) -> tuple:
        """The library's ``(input_size, threshold_window)``."""
        plan = self.metadata.get("training_plan") or {}
        if "input_size" in plan and "threshold_window" in plan:
            return int(plan["input_size"]), int(plan["threshold_window"])
        return window_sizes(self.sliding_window)

    @property
    def min_points(self) -> int:
        """
        The library forecasts each bucket from the ``input_size`` before it and compares its
        score with the scores of the ``threshold_window`` buckets before that, so it needs
        ``input_size + threshold_window`` buckets and returns verdicts from position
        ``input_size + threshold_window - 1`` on.
        """
        input_size, threshold_window = self.window
        return input_size + threshold_window

    # ---------- training ----------

    def fit(self, df: pd.DataFrame) -> None:
        """
        Train, after reproducing the library's window arithmetic (``sonar.training_plan``).

        Raises:
            ValueError: On an unknown parameter or a sliding window below 2.
            InsufficientTrainingDataError: If the library would perform no gradient step or
                have no validation window.
        """
        params = self.cfg.to_params()
        validate_mvad_params(params)
        sliding_window = int(params.get("sliding_window") or 0)
        if sliding_window < 2:
            raise ValueError(f"sliding_window must be at least 2; got {sliding_window}.")

        plan = plan_training(len(df), params)
        if not plan.is_trainable:
            raise InsufficientTrainingDataError(describe_shortfall(plan, params))
        min_steps = int(getattr(self.cfg, "min_gradient_steps", 0) or 0)
        if plan.gradient_steps < min_steps:
            logger.warning(
                "MVAD will perform only %d gradient steps (%d batches/epoch x %d epochs), below min_gradient_steps=%d. The model may be undertrained; use more history, a smaller batch_size or interval=1.",
                plan.gradient_steps,
                plan.batches_per_epoch,
                plan.epochs,
                min_steps,
            )

        logger.info(
            "Fitting MVAD on %d time buckets: %d training windows, %d batches/epoch x %d epochs = %d gradient steps, %d validation windows",
            plan.samples,
            plan.train_windows,
            plan.batches_per_epoch,
            plan.epochs,
            plan.gradient_steps,
            plan.val_windows,
        )
        model = _detector_class()()
        # The library writes its checkpoint to params["save"] (default ./model in the working
        # directory). Use a private directory per run so concurrent trainings never collide.
        with tempfile.TemporaryDirectory(prefix="sonar-mvad-") as checkpoint_dir:
            fit_params = dict(params)
            fit_params.setdefault("save", checkpoint_dir)
            model.fit(df, params=fit_params)

        self.model = model
        self.metadata = {
            "mvad_library": MVAD_LIBRARY,
            "mvad_library_version": package_version(MVAD_LIBRARY),
            "mvad_params": {k: v for k, v in params.items() if k != "save"},
            "training_plan": dataclasses.asdict(plan),
            "gradient_steps": plan.gradient_steps,
            "library_threshold": _as_float(getattr(model, "threshold", None)),
            "train_score_min": _as_float(getattr(model, "train_score_min", None)),
            "train_score_max": _as_float(getattr(model, "train_score_max", None)),
        }

    # ---------- inference ----------

    def predict(self, df: pd.DataFrame) -> List[PointResult]:
        if self.model is None:
            raise RuntimeError("The MVAD model is not trained or loaded.")
        try:
            results = self.model.predict(None, data=df)
        except Exception as e:
            logger.error("MVAD prediction failed. Data shape: %s, columns: %s. Error: %s", df.shape, df.columns.tolist(), e)
            raise
        return mvad_results_to_points(results)

    # ---------- state ----------

    def save_state(self, directory: Path) -> None:
        import torch

        model = self.model
        if model is None or getattr(model, "model", None) is None:
            raise RuntimeError("No trained MVAD model to save.")
        config = dataclasses.asdict(model.config)
        config["save"] = ""  # the training run's temporary checkpoint directory
        state = {
            "config": config,
            "pct_weight": _plain(model.pct_weight),
            "threshold": _as_float(model.threshold),
            "train_score_max": _as_float(model.train_score_max),
            "train_score_min": _as_float(model.train_score_min),
            "variables": list(model.variables or []),
        }
        (directory / CONFIG_FILE).write_text(json.dumps(state, indent=2), encoding="utf-8")
        model.model.cpu()
        torch.save(model.model.state_dict(), directory / WEIGHTS_FILE)

    @classmethod
    def from_state(cls, directory: Path, metadata: Dict[str, Any]) -> "MVADBackend":
        import torch
        from anomaly_detector.multivariate.contract import MultiADConfig, NormalizeBase
        from anomaly_detector.multivariate.module import MultivariateGraphAttnDetector

        state = json.loads((directory / CONFIG_FILE).read_text(encoding="utf-8"))
        config_values = dict(state["config"])
        normalize_base = config_values.pop("normalize_base", None)
        config = MultiADConfig(**config_values, normalize_base=NormalizeBase(**normalize_base) if normalize_base else None)

        model = _detector_class()()
        model.config = config
        model.model = MultivariateGraphAttnDetector(config)
        model.model.load_state_dict(torch.load(directory / WEIGHTS_FILE, map_location="cpu", weights_only=True))
        model.pct_weight = state.get("pct_weight")
        model.threshold = state.get("threshold")
        model.train_score_max = state.get("train_score_max")
        model.train_score_min = state.get("train_score_min")
        model.variables = state.get("variables")

        params = metadata.get("mvad_params") or {}
        backend = cls(MVADConfig(sliding_window=int(params.get("sliding_window", MVADConfig().sliding_window)), device=str(params.get("device", "cpu"))))
        backend.model = model
        backend.metadata = {k: v for k, v in metadata.items()}
        return backend


def _plain(value: Any) -> Any:
    """Lists of numbers from numpy arrays (and nested lists), for JSON. NaN stays NaN (json round-trips it)."""
    if value is None:
        return None
    if hasattr(value, "tolist"):
        value = value.tolist()
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value
