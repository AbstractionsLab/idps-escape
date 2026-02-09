"""
SONAR: SIEM-Oriented Neural Anomaly Recognition

Multivariate time-series anomaly detection for Wazuh, leveraging Microsoft's
time-series-anomaly-detector library for improved performance and maintainability.
"""

__version__ = "2.0.0"
__author__ = "IDPS-ESCAPE Team"

from sonar.config import MVADConfig, PipelineConfig, WazuhIndexerConfig
from sonar.engine import MVADModelEngine
from sonar.features import WazuhFeatureBuilder
from sonar.wazuh_client import WazuhIndexerClient

__all__ = [
    "MVADConfig",
    "PipelineConfig",
    "WazuhIndexerConfig",
    "MVADModelEngine",
    "WazuhFeatureBuilder",
    "WazuhIndexerClient",
]
