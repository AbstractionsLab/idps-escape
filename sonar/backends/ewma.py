"""
The ``ewma`` backend: a cheap, transparent baseline without torch.

Each feature is smoothed with an exponentially weighted moving average and compared with
its training distribution through a robust z-score, the distance to the training median in
units of the scaled median absolute deviation (MAD). A bucket is anomalous when its largest
z-score reaches ``z_threshold``. Its severity is that largest z-score divided by twice the
threshold, capped at 1 (a bucket exactly at the threshold has severity 0.5), and 0 when the
bucket is not anomalous, like MVAD's. Each feature contributes its share of the summed
z-scores.

It ignores correlations between features, which MVAD models; that is what makes it a useful
baseline: MVAD has to beat it to justify its cost.
"""

import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from sonar.backends.base import Contributor, PointResult
from sonar.config import EWMAConfig
from sonar.training_plan import InsufficientTrainingDataError

STATE_FILE = "ewma_state.json"
MAD_TO_SIGMA = 1.4826  # scales the MAD of normally distributed data to its standard deviation
MIN_TRAINING_POINTS = 10


class EWMABackend:
    """EWMA-smoothed robust z-score per feature, maximum over features."""

    name = "ewma"

    def __init__(self, cfg: Optional[EWMAConfig] = None):
        self.cfg = cfg or EWMAConfig()
        if not 0.0 < float(self.cfg.alpha) <= 1.0:
            raise ValueError(f"ewma.alpha must be in (0, 1]; got {self.cfg.alpha}")
        if float(self.cfg.z_threshold) <= 0.0:
            raise ValueError(f"ewma.z_threshold must be positive; got {self.cfg.z_threshold}")
        self.columns: List[str] = []
        self.center: Dict[str, float] = {}
        self.scale: Dict[str, float] = {}
        self.metadata: Dict[str, Any] = {}

    @property
    def warmup(self) -> int:
        """Buckets before the first verdict, so the average has settled (none without smoothing)."""
        alpha = float(self.cfg.alpha)
        return 0 if alpha >= 1.0 else int(math.ceil(1.0 / alpha))

    @property
    def min_points(self) -> int:
        return self.warmup + 1

    def _smooth(self, df: pd.DataFrame) -> pd.DataFrame:
        return df.astype(float).ewm(alpha=float(self.cfg.alpha), adjust=False).mean()

    def fit(self, df: pd.DataFrame) -> None:
        if len(df) < max(MIN_TRAINING_POINTS, self.min_points + 1):
            raise InsufficientTrainingDataError(f"The ewma backend needs at least {max(MIN_TRAINING_POINTS, self.min_points + 1)} time buckets to train; got {len(df)}.")
        smoothed = self._smooth(df).iloc[self.warmup :]
        self.columns = list(df.columns)
        for column in self.columns:
            values = smoothed[column].to_numpy()
            center = float(np.median(values))
            mad = float(np.median(np.abs(values - center))) * MAD_TO_SIGMA
            std = float(np.std(values))
            # Count features are often constant (MAD 0); fall back to the standard deviation,
            # then to 1, so a feature that never moved scores one unit of change as z = 1.
            self.center[column] = center
            self.scale[column] = mad if mad > 0 else (std if std > 0 else 1.0)
        self.metadata = {
            "ewma": {"alpha": float(self.cfg.alpha), "z_threshold": float(self.cfg.z_threshold)},
            "training_points": len(df),
        }

    def predict(self, df: pd.DataFrame) -> List[PointResult]:
        if not self.columns:
            raise RuntimeError("The ewma backend is not trained or loaded.")
        if len(df) < self.min_points:
            raise ValueError(f"Not enough data. Minimum size is {self.min_points}")
        smoothed = self._smooth(df[self.columns])
        center = np.array([self.center[c] for c in self.columns])
        scale = np.array([self.scale[c] for c in self.columns])
        z = np.abs(smoothed.to_numpy() - center) / scale
        threshold = float(self.cfg.z_threshold)
        points = []
        for i in range(self.min_points - 1, len(df)):
            row = z[i]
            z_max = float(row.max()) if len(row) else 0.0
            is_anomaly = z_max >= threshold
            total = float(row.sum())
            order = np.argsort(-row)
            contributors = [Contributor(self.columns[j], float(row[j] / total) if total > 0 else 0.0) for j in order if row[j] > 0]
            points.append(
                PointResult(
                    timestamp=pd.Timestamp(df.index[i]),
                    is_anomaly=is_anomaly,
                    severity=min(1.0, z_max / (2.0 * threshold)) if is_anomaly else 0.0,
                    raw_score=z_max,
                    contributors=contributors,
                )
            )
        return points

    def save_state(self, directory: Path) -> None:
        state = {"alpha": float(self.cfg.alpha), "z_threshold": float(self.cfg.z_threshold), "columns": self.columns, "center": self.center, "scale": self.scale}
        (directory / STATE_FILE).write_text(json.dumps(state, indent=2), encoding="utf-8")

    @classmethod
    def from_state(cls, directory: Path, metadata: Dict[str, Any]) -> "EWMABackend":
        state = json.loads((directory / STATE_FILE).read_text(encoding="utf-8"))
        backend = cls(EWMAConfig(alpha=state["alpha"], z_threshold=state["z_threshold"]))
        backend.columns = list(state["columns"])
        backend.center = {k: float(v) for k, v in state["center"].items()}
        backend.scale = {k: float(v) for k, v in state["scale"].items()}
        backend.metadata = dict(metadata)
        return backend
