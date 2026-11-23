"""
Training-plan arithmetic for the MVAD library.

``time-series-anomaly-detector`` builds its training windows with a stride
(``interval``), drops incomplete batches (``drop_last=True``) and picks the best
checkpoint on a validation split. With too few time buckets the training loader
yields no batch at all, ``fit()`` returns without a single gradient step, and a
randomly initialised network gets saved. This module reproduces the library's
window arithmetic so SONAR can refuse such a fit before it happens.

The constants below mirror ``anomaly_detector.multivariate.contract.MultiADConfig``
in version 0.4.0. They are copied rather than imported so that the check runs
without importing torch. ``tests/sonartests/test_engine_real_mvad.py`` asserts that
they still match the installed library.
"""

import difflib
from dataclasses import dataclass
from typing import Any, Dict

# Defaults of MultiADConfig (time-series-anomaly-detector 0.4.0) that the plan depends on.
LIBRARY_DEFAULTS: Dict[str, Any] = {
    "epochs": 100,
    "batch_size": 128,
    "interval": 10,
    "horizon": 1,
    "train_ratio": 0.8,
    "val_ratio": 0.1,
}

# Every field of MultiADConfig (0.4.0).
LIBRARY_CONFIG_FIELDS = frozenset(
    {
        "data_dim",
        "cnn_kernel_size",
        "input_size",
        "gat_window_size",
        "hidden_size",
        "epochs",
        "batch_size",
        "seed",
        "z_dim",
        "enc_dim",
        "dec_dim",
        "interval",
        "lr",
        "beta",
        "gamma",
        "device",
        "horizon",
        "dropout",
        "save",
        "train_ratio",
        "val_ratio",
        "normalize_base",
        "threshold_window",
        "level",
    }
)

# Keys the library consumes before building MultiADConfig.
LIBRARY_PRE_CONFIG_KEYS = frozenset({"sliding_window", "fill_na_method", "fill_na_value"})

# Fields the library sets itself; a user value would be overwritten or is meaningless.
LIBRARY_DERIVED_FIELDS = frozenset({"data_dim", "input_size", "threshold_window", "normalize_base"})

# Names people commonly use for a library field.
PARAM_ALIASES = {"learning_rate": "lr", "window": "sliding_window", "window_size": "sliding_window"}

ACCEPTED_PARAMS = (LIBRARY_CONFIG_FIELDS - LIBRARY_DERIVED_FIELDS) | LIBRARY_PRE_CONFIG_KEYS


class InsufficientTrainingDataError(ValueError):
    """Raised when the MVAD library would train on the data without a single update."""


def validate_mvad_params(params: Dict[str, Any]) -> None:
    """
    Reject parameters the MVAD library would silently ignore or overwrite.

    Args:
        params: Parameters that will be passed to ``MultivariateAnomalyDetector.fit``.

    Raises:
        ValueError: On the first unknown or library-derived key, naming a likely replacement.
    """
    for key in params:
        if key in ACCEPTED_PARAMS:
            continue
        if key in LIBRARY_DERIVED_FIELDS:
            raise ValueError(f"MVAD parameter '{key}' is derived by the library (from 'sliding_window' or the data) and cannot be set.")
        suggestion = PARAM_ALIASES.get(key) or next(iter(difflib.get_close_matches(key, sorted(ACCEPTED_PARAMS), n=1)), None)
        hint = f" Did you mean '{suggestion}'?" if suggestion else ""
        raise ValueError(f"Unknown MVAD parameter '{key}': the library would ignore it.{hint}")


def window_sizes(sliding_window: int) -> tuple:
    """Return the library's ``(input_size, threshold_window)`` for a sliding window."""
    if sliding_window:
        input_size = int(sliding_window) // 2
        return input_size, min(200, int(sliding_window) - input_size)
    return 200, 200


@dataclass(frozen=True)
class TrainingPlan:
    """What ``MultivariateAnomalyDetector.fit`` will do with a given number of time buckets."""

    samples: int
    sliding_window: int
    input_size: int
    threshold_window: int
    interval: int
    batch_size: int
    epochs: int
    train_windows: int
    batches_per_epoch: int
    val_windows: int

    @property
    def gradient_steps(self) -> int:
        """Total optimiser updates over all epochs."""
        return self.batches_per_epoch * self.epochs

    @property
    def is_trainable(self) -> bool:
        """True if training updates the model and validation selects a checkpoint."""
        return self.batches_per_epoch >= 1 and self.val_windows >= 1

    @property
    def min_detection_points(self) -> int:
        """Smallest number of buckets the library accepts at prediction time."""
        return self.input_size + self.threshold_window


def plan_training(samples: int, params: Dict[str, Any]) -> TrainingPlan:
    """
    Compute the training plan the MVAD library will follow.

    Mirrors ``MultivariateAnomalyDetector.fit`` and ``MultiADDataset.get_x_end_idx`` (0.4.0).

    Args:
        samples: Number of time buckets (rows) passed to ``fit``.
        params: Parameters passed to ``fit`` (``sliding_window`` plus library overrides).

    Returns:
        TrainingPlan for these inputs.
    """
    p = {**LIBRARY_DEFAULTS, **params}
    sliding_window = int(p.get("sliding_window") or 0)
    input_size, threshold_window = window_sizes(sliding_window)
    interval, horizon = int(p["interval"]), int(p["horizon"])
    train_len = int(samples * float(p["train_ratio"]))
    val_len = int(samples * float(p["val_ratio"]))

    train_windows = len(range(input_size, train_len - horizon + 1)) // interval
    # Validation uses interval=1 and horizon=1.
    val_windows = len(range(input_size, val_len))
    return TrainingPlan(
        samples=samples,
        sliding_window=sliding_window,
        input_size=input_size,
        threshold_window=threshold_window,
        interval=interval,
        batch_size=int(p["batch_size"]),
        epochs=int(p["epochs"]),
        train_windows=train_windows,
        batches_per_epoch=train_windows // int(p["batch_size"]),
        val_windows=val_windows,
    )


def required_samples(params: Dict[str, Any], limit: int = 10_000_000) -> int:
    """
    Smallest number of time buckets for which training is possible with these parameters.

    Args:
        params: Parameters passed to ``fit``.
        limit: Upper bound for the search.

    Returns:
        Minimum bucket count, or ``limit`` if none below it works.
    """
    lo, hi = 2, limit
    if not plan_training(hi, params).is_trainable:
        return limit
    while lo < hi:
        mid = (lo + hi) // 2
        if plan_training(mid, params).is_trainable:
            hi = mid
        else:
            lo = mid + 1
    return lo


def describe_shortfall(plan: TrainingPlan, params: Dict[str, Any]) -> str:
    """Human-readable explanation of why a plan cannot train, with the bucket count needed."""
    reasons = []
    if plan.batches_per_epoch < 1:
        reasons.append(f"{plan.train_windows} training windows (stride interval={plan.interval}) fill no batch of batch_size={plan.batch_size}")
    if plan.val_windows < 1:
        reasons.append(f"the validation split is shorter than the input window ({plan.input_size} buckets)")
    needed = required_samples(params)
    return (
        f"MVAD cannot train on {plan.samples} time buckets with sliding_window={plan.sliding_window}: "
        f"{'; '.join(reasons)}. At least {needed} buckets are needed with these settings. "
        "Increase lookback_hours, decrease bucket_minutes or sliding_window, or lower batch_size/interval in extra_params."
    )
