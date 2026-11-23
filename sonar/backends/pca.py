"""
The ``pca`` backend: a linear multivariate model of normal behaviour, without torch.

Each bucket is scored on the window of its last ``window`` buckets, every feature
standardised with its training median and scaled MAD (as in ``ewma``). Training fits a
probabilistic PCA to these window vectors: the principal components that explain
``variance`` of the training variance, and an isotropic noise variance for the rest. A
window's score is its Mahalanobis distance under that model, per dimension::

    d^2 = sum_i (v_i . x)^2 / lambda_i  +  |x - V V^T x|^2 / sigma^2,   score = sqrt(d^2 / D)

The first term catches a window that is far out along a direction normal data varies in (a
spike, a drift to a level never seen); the second one a window that breaks the correlations
between features and lags (a feature moving alone, a category that never moved). Normal
windows score about 1.

A bucket is anomalous when the robust z-score of its score against the training scores
reaches ``z_threshold``; severity and the anomaly decision follow ``ewma``'s conventions
(0.5 at the threshold, 1 from twice the threshold, 0 when not anomalous). Each feature
contributes its share of ``d^2``, summed over the lags of the window.

An anomalous bucket stays in the window for ``window`` buckets, so alarms last up to
``window - 1`` buckets after the anomaly ends.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from sonar.backends.base import Contributor, PointResult
from sonar.config import PCAConfig
from sonar.training_plan import InsufficientTrainingDataError

STATE_FILE = "pca_state.json"
MAD_TO_SIGMA = 1.4826
MIN_TRAINING_WINDOWS = 20
MIN_NOISE_VARIANCE = 0.01
"""Floor of the noise variance (standardised units), so features that never moved in training
score a change as a large but finite distance instead of dividing by zero."""


def _robust_scale(values: np.ndarray) -> tuple:
    """Median and scale of each column: the scaled MAD, else the standard deviation, else 1."""
    center = np.median(values, axis=0)
    mad = np.median(np.abs(values - center), axis=0) * MAD_TO_SIGMA
    std = np.std(values, axis=0)
    scale = np.where(mad > 0, mad, np.where(std > 0, std, 1.0))
    return center, scale


class PCABackend:
    """Probabilistic PCA on lagged windows of standardised features; Mahalanobis distance."""

    name = "pca"

    def __init__(self, cfg: Optional[PCAConfig] = None):
        self.cfg = cfg or PCAConfig()
        if int(self.cfg.window) < 1:
            raise ValueError(f"pca.window must be at least 1; got {self.cfg.window}")
        if not 0.0 < float(self.cfg.variance) < 1.0:
            raise ValueError(f"pca.variance must be in (0, 1); got {self.cfg.variance}")
        if float(self.cfg.z_threshold) <= 0.0:
            raise ValueError(f"pca.z_threshold must be positive; got {self.cfg.z_threshold}")
        self.columns: List[str] = []
        self.center = np.zeros(0)
        self.scale = np.zeros(0)
        self.mean = np.zeros(0)
        self.components = np.zeros((0, 0))
        self.eigenvalues = np.zeros(0)
        self.noise_variance = 1.0
        self.score_center = 0.0
        self.score_scale = 1.0
        self.metadata: Dict[str, Any] = {}

    @property
    def window_buckets(self) -> int:
        return int(self.cfg.window)

    @property
    def min_points(self) -> int:
        return self.window_buckets

    def _windows(self, df: pd.DataFrame) -> np.ndarray:
        """One row per bucket from position ``window - 1`` on: the standardised window ending there, lag-major."""
        z = (df[self.columns].to_numpy(dtype=float) - self.center) / self.scale
        n, w = len(z), self.window_buckets
        return np.stack([z[i : n - w + 1 + i] for i in range(w)], axis=1).reshape(n - w + 1, w * z.shape[1])

    def _terms(self, x: np.ndarray) -> np.ndarray:
        """Per-dimension terms of d^2 (rows sum to d^2): x * C^-1 x under the fitted model."""
        x = x - self.mean
        projected = x @ self.components
        residual = x - projected @ self.components.T
        return x * ((projected / self.eigenvalues) @ self.components.T + residual / self.noise_variance)

    def _scores(self, terms: np.ndarray) -> np.ndarray:
        return np.sqrt(np.clip(terms.sum(axis=1), 0.0, None) / terms.shape[1])

    def fit(self, df: pd.DataFrame) -> None:
        needed = self.window_buckets - 1 + MIN_TRAINING_WINDOWS
        if len(df) < needed:
            raise InsufficientTrainingDataError(f"The pca backend needs at least {needed} time buckets to train (window {self.window_buckets}); got {len(df)}.")
        self.columns = list(df.columns)
        self.center, self.scale = _robust_scale(df.to_numpy(dtype=float))
        x = self._windows(df)
        self.mean = x.mean(axis=0)
        _, singular, vt = np.linalg.svd(x - self.mean, full_matrices=False)
        variances = singular**2 / max(len(x) - 1, 1)
        dims = x.shape[1]
        total = float(variances.sum())
        if total > 0:
            k = int(np.searchsorted(np.cumsum(variances) / total, float(self.cfg.variance)) + 1)
        else:
            k = 0
        k = min(k, len(variances), dims - 1) if dims > 1 else 0
        discarded = float(variances[k:].sum()) / (dims - k) if dims > k else 0.0
        self.noise_variance = max(discarded, MIN_NOISE_VARIANCE)
        self.components = vt[:k].T
        self.eigenvalues = np.maximum(variances[:k], self.noise_variance)
        scores = self._scores(self._terms(x))
        self.score_center = float(np.median(scores))
        mad = float(np.median(np.abs(scores - self.score_center))) * MAD_TO_SIGMA
        std = float(np.std(scores))
        self.score_scale = mad if mad > 0 else (std if std > 0 else 1.0)
        self.metadata = {
            "pca": {"window": self.window_buckets, "variance": float(self.cfg.variance), "z_threshold": float(self.cfg.z_threshold)},
            "components": k,
            "dimensions": dims,
            "noise_variance": self.noise_variance,
            "training_points": len(df),
        }

    def predict(self, df: pd.DataFrame) -> List[PointResult]:
        if not self.columns:
            raise RuntimeError("The pca backend is not trained or loaded.")
        if len(df) < self.min_points:
            raise ValueError(f"Not enough data. Minimum size is {self.min_points}")
        terms = self._terms(self._windows(df))
        scores = self._scores(terms)
        per_feature = np.clip(terms, 0.0, None).reshape(len(terms), self.window_buckets, len(self.columns)).sum(axis=1)
        threshold = float(self.cfg.z_threshold)
        points = []
        for row, score, contributions in zip(range(self.window_buckets - 1, len(df)), scores, per_feature):
            z = (float(score) - self.score_center) / self.score_scale
            is_anomaly = z >= threshold
            total = float(contributions.sum())
            order = np.argsort(-contributions)
            points.append(
                PointResult(
                    timestamp=pd.Timestamp(df.index[row]),
                    is_anomaly=is_anomaly,
                    severity=min(1.0, z / (2.0 * threshold)) if is_anomaly else 0.0,
                    raw_score=z,
                    contributors=[Contributor(self.columns[j], float(contributions[j] / total)) for j in order if contributions[j] > 0] if total > 0 else [],
                )
            )
        return points

    def save_state(self, directory: Path) -> None:
        arrays = {"center": self.center, "scale": self.scale, "mean": self.mean, "components": self.components, "eigenvalues": self.eigenvalues}
        state = {
            "window": self.window_buckets,
            "variance": float(self.cfg.variance),
            "z_threshold": float(self.cfg.z_threshold),
            "columns": self.columns,
            "noise_variance": self.noise_variance,
            "score_center": self.score_center,
            "score_scale": self.score_scale,
            "shape": {name: list(a.shape) for name, a in arrays.items()},
            **{name: a.ravel().tolist() for name, a in arrays.items()},
        }
        (directory / STATE_FILE).write_text(json.dumps(state), encoding="utf-8")

    @classmethod
    def from_state(cls, directory: Path, metadata: Dict[str, Any]) -> "PCABackend":
        state = json.loads((directory / STATE_FILE).read_text(encoding="utf-8"))
        backend = cls(PCAConfig(window=state["window"], variance=state["variance"], z_threshold=state["z_threshold"]))
        backend.columns = list(state["columns"])
        for name, shape in state["shape"].items():
            setattr(backend, name, np.asarray(state[name], dtype=float).reshape(shape))
        backend.noise_variance = float(state["noise_variance"])
        backend.score_center = float(state["score_center"])
        backend.score_scale = float(state["score_scale"])
        backend.metadata = dict(metadata)
        return backend
