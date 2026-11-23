"""
The detector backend contract.

A backend learns what normal looks like from a feature matrix (``fit``) and gives a verdict
per time bucket (``predict``). Everything SONAR does around it (features, the scored window,
post-processing, sinks, the model file) is backend-independent, and post-processing
consumes only ``PointResult``.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Protocol

import pandas as pd


@dataclass
class Contributor:
    """How much one feature contributed to a bucket's score (contributions of a bucket sum to about 1)."""

    variable: str
    contribution: float


@dataclass
class PointResult:
    """The verdict on one time bucket."""

    timestamp: pd.Timestamp
    is_anomaly: bool
    severity: float
    """0-1, comparable across backends and scenarios; 0 when the bucket is not anomalous."""
    raw_score: float
    """The backend's own score, on its own scale."""
    contributors: List[Contributor] = field(default_factory=list)
    """Features ordered by contribution, largest first."""


class DetectorBackend(Protocol):
    """A trainable anomaly detector for SONAR's feature matrices."""

    name: str
    """Registry name, stored in the model file (``training.backend``)."""

    metadata: Dict[str, Any]
    """How the backend was trained (parameters, library versions, training statistics); JSON-serialisable."""

    @property
    def min_points(self) -> int:
        """Fewest buckets ``predict`` needs; it gives verdicts from bucket ``min_points - 1`` on."""
        ...

    def fit(self, df: pd.DataFrame) -> None:
        """Train on a feature matrix (time index, one numeric column per feature)."""
        ...

    def predict(self, df: pd.DataFrame) -> List[PointResult]:
        """Verdicts for the buckets of ``df`` from position ``min_points - 1`` on, in time order."""
        ...

    def save_state(self, directory: Path) -> None:
        """Write the trained state into ``directory`` (which exists), without pickle."""
        ...

    @classmethod
    def from_state(cls, directory: Path, metadata: Dict[str, Any]) -> "DetectorBackend":
        """Rebuild a trained backend from ``save_state``'s files and its ``metadata``."""
        ...
