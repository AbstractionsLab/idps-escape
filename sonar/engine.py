"""
Multivariate Anomaly Detection model engine.
"""

import logging
import pickle
from typing import Any, Optional, List

import pandas as pd
# Defer importing the heavy anomaly_detector until train() runs to avoid import-time
# side-effects during test collection. Tests can still patch
# `sonar.engine.MultivariateAnomalyDetector` when needed.
MultivariateAnomalyDetector = None

from sonar.config import PipelineConfig

logger = logging.getLogger(__name__)


class MVADModelEngine:
    """Wrapper for MultivariateAnomalyDetector model lifecycle."""

    def __init__(self, cfg: PipelineConfig):
        """
        Initialize MVAD engine.

        Args:
            cfg: PipelineConfig instance.
        """
        self.cfg = cfg
        self.model: Optional[MultivariateAnomalyDetector] = None
        self.training_columns: Optional[List[str]] = None  # Store column names from training

    # ---------- Training ----------

    def train(self, ts_data: pd.DataFrame) -> None:
        """
        Train MultivariateAnomalyDetector on a multivariate time series.

        Args:
            ts_data: DataFrame with time index and numeric feature columns.

        Raises:
            ValueError: If training data is empty or has insufficient rows.
        """
        if ts_data.empty:
            raise ValueError("Training data is empty.")
        
        # Drop rows with NaN values to ensure valid samples for DataLoader
        ts_data = ts_data.dropna()
        
        if len(ts_data) == 0:
            raise ValueError("Training data has no valid samples after removing NaN values.")
        
        if len(ts_data) < 2:
            raise ValueError("Training data must have at least 2 samples; got {}.".format(len(ts_data)))

        params = self.cfg.mvad.to_params()
        sliding_window = params.get("sliding_window", 0)
        logger.debug("Training data samples=%d, sliding_window=%d", len(ts_data), sliding_window)

        n_windows = len(ts_data) - sliding_window + 1
        logger.debug("Computed training windows: %d", n_windows)

        if n_windows <= 0:
            # If user explicitly set an unreasonable sliding_window, raise.
            # But if they're using the library default, allow a safe fallback
            # for small test cases (do not mutate the user's config).
            from sonar.config import MVADConfig

            default_sw = MVADConfig.__dataclass_fields__["sliding_window"].default
            if sliding_window == default_sw:
                effective_sw = max(1, len(ts_data) - 1)
                logger.warning(
                    "Configured sliding_window (%d) is too large for samples=%d; "
                    "using effective_sliding_window=%d for this fit (no config change).",
                    sliding_window,
                    len(ts_data),
                    effective_sw,
                )
                params["sliding_window"] = effective_sw
            else:
                logger.error(
                    "Sliding window (%d) is too large for training data (samples=%d).",
                    sliding_window,
                    len(ts_data),
                )
                raise ValueError(
                    f"Sliding window ({sliding_window}) is too large for training data "
                    f"(samples={len(ts_data)}); need at least sliding_window+1 time points."
                )

        # Ensure the model class is imported (lazy import to keep tests fast)
        if MultivariateAnomalyDetector is None:
            from anomaly_detector import MultivariateAnomalyDetector as _MAD  # type: ignore
            MAD = _MAD
        else:
            MAD = MultivariateAnomalyDetector

        model = MAD()
        # The library expects a DataFrame with rows = time points, cols = variables.
        logger.info("Fitting MVAD model on %d windows", n_windows)
        model.fit(ts_data, params=params)

        self.model = model
        
        # Store training column names for alignment during prediction
        self.training_columns = ts_data.columns.tolist()
        logger.info("Stored %d training columns for prediction alignment", len(self.training_columns))
        
        # Store training sample count for metadata
        self._training_samples = len(ts_data)
        logger.debug("Stored training sample count: %d", self._training_samples)

    def save(self) -> None:
        """
        Save trained model to disk.

        Raises:
            RuntimeError: If no model has been trained.
        """
        if self.model is None:
            raise RuntimeError("No model to save; train first.")
        
        # Save both model and training columns
        with open(self.cfg.model_path, "wb") as f:
            pickle.dump({
                "model": self.model,
                "training_columns": self.training_columns,
                "training_samples": getattr(self, '_training_samples', 0),
            }, f)
        
        logger.info("Model, training columns, and metadata saved to %s", self.cfg.model_path)

    def load(self) -> None:
        """
        Load model from disk.

        Raises:
            FileNotFoundError: If model file does not exist.
        """
        with open(self.cfg.model_path, "rb") as f:
            data = pickle.load(f)
        
        # Handle both old (model only) and new (model + columns + metadata) format
        if isinstance(data, dict):
            self.model = data["model"]
            self.training_columns = data.get("training_columns")
            self._training_samples = data.get("training_samples", 0)
            logger.info("Model loaded with %d training columns and %d training samples", 
                       len(self.training_columns) if self.training_columns else 0,
                       self._training_samples)
        else:
            # Old format: just the model
            self.model = data
            self.training_columns = None
            self._training_samples = 0
            logger.warning("Loaded model without training columns; column alignment disabled")
        
        logger.info("Model loaded from %s", self.cfg.model_path)

    # ---------- Inference ----------

    def predict(self, ts_data: pd.DataFrame) -> Any:
        """
        Run anomaly detection on new multivariate time series.

        Args:
            ts_data: DataFrame with time index and numeric feature columns.

        Returns:
            Raw prediction result from MultivariateAnomalyDetector.

        Raises:
            RuntimeError: If model has not been trained or loaded.
            ValueError: If prediction data is invalid or incompatible.
        """
        if self.model is None:
            raise RuntimeError("Model not loaded; call load() or train().")

        if ts_data.empty:
            raise ValueError("Cannot predict on empty data.")

        # Ensure all columns are numeric
        ts_clean = ts_data.copy()
        
        # Convert all columns to float, dropping non-numeric columns
        numeric_cols = ts_clean.select_dtypes(include=['number']).columns.tolist()
        if not numeric_cols:
            raise ValueError("No numeric columns found in prediction data.")
        
        ts_clean = ts_clean[numeric_cols].astype(float)
        
        # Align columns to match training data
        if self.training_columns is not None:
            logger.debug("Aligning %d prediction columns to %d training columns", 
                        len(ts_clean.columns), len(self.training_columns))
            
            # Add missing columns (fill with 0)
            for col in self.training_columns:
                if col not in ts_clean.columns:
                    logger.debug("Adding missing column: %s", col)
                    ts_clean[col] = 0.0
            
            # Remove extra columns  
            extra_cols = [c for c in ts_clean.columns if c not in self.training_columns]
            if extra_cols:
                logger.debug("Removing %d extra columns: %s", len(extra_cols), extra_cols[:5])
                ts_clean = ts_clean.drop(columns=extra_cols)
            
            # Reorder columns to match training
            ts_clean = ts_clean[self.training_columns]
        
        # Fill any remaining NaN/inf values
        ts_clean = ts_clean.fillna(0.0)
        ts_clean = ts_clean.replace([float('inf'), float('-inf')], 0.0)
        
        logger.debug(
            "Prediction data: shape=%s, columns=%s, non-null=%d",
            ts_clean.shape,
            ts_clean.columns.tolist(),
            ts_clean.count().sum()
        )

        # Try passing a context dict (newer versions require it) but fall back
        # to the older signature if the model doesn't accept the kwarg.
        try:
            results = self.model.predict(data=ts_clean, context={"pipeline_config": self.cfg})
        except TypeError as e:
            logger.debug("Model.predict did not accept 'context' kwarg: %s. Falling back.", e)
            try:
                results = self.model.predict(data=ts_clean)
            except Exception as predict_err:
                logger.error(
                    "Model prediction failed. Data shape: %s, columns: %s. Error: %s",
                    ts_clean.shape,
                    ts_clean.columns.tolist(),
                    predict_err
                )
                raise
        except Exception as e:
            logger.error(
                "Model prediction failed. Data shape: %s, columns: %s. Error: %s",
                ts_clean.shape,
                ts_clean.columns.tolist(),
                e
            )
            raise
        
        return results
