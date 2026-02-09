"""
Post-processing: from MVAD output to Wazuh anomalies.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence

from sonar.config import FeatureConfig


class MVADPostProcessor:
    """Convert MVAD prediction results into anomaly alerts for Wazuh."""

    def __init__(self, feature_cfg: FeatureConfig):
        """
        Initialize post-processor.

        Args:
            feature_cfg: FeatureConfig instance for context.
        """
        self.feature_cfg = feature_cfg

    def _extract_score_from_result(self, results: Any) -> float:
        """
        Extract anomaly score from MVAD result structure.
        
        Handles various result formats including:
        - Direct score fields: score, anomaly_score, severity
        - MVAD library format: interpretation.isAnomaly, severity
        - Nested structures
        
        Args:
            results: MVAD prediction result (dict or other structure).
            
        Returns:
            Extracted score as float, or 0.0 if not found.
        """
        if not isinstance(results, dict):
            return 0.0
        
        # Try common top-level score fields
        for field in ["score", "anomaly_score", "severity"]:
            if field in results:
                val = results[field]
                if isinstance(val, (int, float)):
                    return float(val)
        
        # Try MVAD library interpretation structure
        if "interpretation" in results:
            interp = results["interpretation"]
            if isinstance(interp, dict):
                # Check for isAnomaly (boolean) or score
                if "isAnomaly" in interp and interp["isAnomaly"]:
                    # If boolean isAnomaly is True, check for severity or default to 1.0
                    if "severity" in interp and isinstance(interp["severity"], (int, float)):
                        return float(interp["severity"])
                    return 1.0
                if "score" in interp and isinstance(interp["score"], (int, float)):
                    return float(interp["score"])
        
        # Try to find severity anywhere in the structure
        if "severity" in results:
            val = results["severity"]
            if isinstance(val, (int, float)):
                return float(val)
        
        # Last resort: look for any numeric field that might be a score
        for key, val in results.items():
            if isinstance(val, (int, float)) and key.lower() in ["value", "result", "anomaly"]:
                return float(val)
        
        return 0.0

    def build_wazuh_anomaly_docs(
        self,
        timestamps: Sequence[datetime],
        results: Any,
        context: Dict[str, Any],
        threshold: float = None,
    ) -> List[Dict[str, Any]]:
        """
        Transform MVAD model results into Wazuh-style anomaly documents.

        MVAD returns a list of dicts with format:
            [{'index': Timestamp, 'is_anomaly': bool, 'score': float, 
              'severity': float, 'interpretation': [...]}, ...]

        Args:
            timestamps: List of timestamps corresponding to predictions.
            results: MVAD prediction result (list of dicts, one per time point).
            context: Metadata context (time window, bucket size, etc.).
            threshold: Anomaly detection threshold (from config or results).

        Returns:
            List of Wazuh anomaly documents (only for detected anomalies).
        """
        docs: List[Dict[str, Any]] = []
        
        # Set default threshold
        threshold_value = threshold if threshold is not None else 0.0

        # Handle MVAD's actual output format: list of dicts
        if isinstance(results, list):
            for result in results:
                if not isinstance(result, dict):
                    continue
                
                # Extract fields from MVAD result
                is_anom = result.get('is_anomaly', False)
                score = result.get('score', 0.0)
                severity = result.get('severity', 0.0)
                ts = result.get('index')
                
                # Skip non-anomalies
                if not is_anom:
                    continue
                
                # Use timestamp from result if available, otherwise from input
                if ts is None and timestamps:
                    ts = timestamps[len(docs)] if len(docs) < len(timestamps) else datetime.now(timezone.utc)
                elif ts is None:
                    ts = datetime.now(timezone.utc)
                
                doc = {
                    "@timestamp": ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
                    "timestamp": ts.isoformat() if hasattr(ts, 'isoformat') else str(ts),
                    
                    # Required top-level fields for data stream template
                    "is_anomaly": True,
                    "anomaly_score": float(score),
                    "threshold": threshold_value,
                    "scenario_name": context.get("scenario_id", "unknown"),
                    "detection_timestamp": datetime.now(timezone.utc).isoformat(),
                    "alert_count": context.get("alert_count", 0),
                    "feature_count": len(self.feature_cfg.numeric_fields),
                    
                    # MVAD-specific fields
                    "mvad_score": float(score),
                    "mvad_severity": float(severity),
                    "mvad_threshold": threshold_value,
                    "sliding_window": context.get("sliding_window", 0),
                    "bucket_minutes": context.get("bucket_minutes", 5),
                    
                    # Context as structured object
                    "context": {
                        "model_path": context.get("model_path", ""),
                        "feature_names": self.feature_cfg.numeric_fields,
                        "training_samples": context.get("training_samples", 0),
                    },
                    
                    "rule": {
                        "level": 10,
                        "description": "MVAD: multivariate anomaly detected.",
                        "id": "900001",
                        "groups": ["mvad", "ml", "anomaly"],
                    },
                    "data": {
                        "mvad_score": float(score),
                        "mvad_severity": float(severity),
                        "mvad_threshold": threshold_value,
                        "bucket_minutes": context.get("bucket_minutes", 5),
                        "lookback_minutes": context.get("lookback_minutes"),
                    },
                }
                
                # Add interpretation data if available for explainability
                interpretation = result.get('interpretation')
                if interpretation and isinstance(interpretation, list):
                    doc['mvad_interpretation'] = [
                        {
                            'variable': interp.get('variable_name', ''),
                            'contribution': interp.get('contribution_score', 0.0)
                        }
                        for interp in interpretation[:3]  # Top 3 contributors
                    ]
                
                docs.append(doc)
        
        else:
            # Fallback for unexpected format (shouldn't happen with MVAD)
            # Log warning and create a single document
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                "Unexpected MVAD result format. Expected list, got %s. "
                "Creating single anomaly document.",
                type(results).__name__
            )
            
            score_value = self._extract_score_from_result(results)
            now = datetime.now(timezone.utc)
            
            doc = {
                "@timestamp": now.isoformat(),
                "timestamp": now.isoformat(),
                "is_anomaly": True,
                "anomaly_score": score_value,
                "threshold": threshold_value,
                "scenario_name": context.get("scenario_id", "unknown"),
                "detection_timestamp": now.isoformat(),
                "alert_count": context.get("alert_count", 0),
                "feature_count": len(self.feature_cfg.numeric_fields),
                "mvad_score": score_value,
                "mvad_threshold": threshold_value,
                "rule": {
                    "level": 10,
                    "description": "MVAD: anomaly detected (unexpected format).",
                    "id": "900001",
                    "groups": ["mvad", "ml", "anomaly"],
                },
                "data": {
                    "result_type": type(results).__name__,
                    "result_repr": str(results)[:500],
                },
            }
            docs.append(doc)

        return docs
