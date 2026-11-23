"""
Detector backends: ``mvad`` (default), ``pca`` (linear, no torch) and ``ewma`` (baseline). See ``sonar.backends.base``.
"""

from typing import Type

from sonar.backends.base import Contributor, DetectorBackend, PointResult
from sonar.config import PipelineConfig

BACKEND_NAMES = ("mvad", "pca", "ewma")

__all__ = ["BACKEND_NAMES", "Contributor", "DetectorBackend", "PointResult", "backend_class", "new_backend"]


def backend_class(name: str) -> Type:
    """The backend class registered under ``name``."""
    if name == "mvad":
        from sonar.backends.mvad import MVADBackend

        return MVADBackend
    if name == "ewma":
        from sonar.backends.ewma import EWMABackend

        return EWMABackend
    if name == "pca":
        from sonar.backends.pca import PCABackend

        return PCABackend
    raise ValueError(f"unknown backend '{name}'; choose from {', '.join(BACKEND_NAMES)}")


def new_backend(cfg: PipelineConfig) -> DetectorBackend:
    """An untrained backend for ``cfg.backend``, with its settings from ``cfg``."""
    cls = backend_class(cfg.backend)
    return cls({"mvad": cfg.mvad, "ewma": cfg.ewma, "pca": cfg.pca}[cfg.backend])
