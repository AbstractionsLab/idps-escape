"""
Local data provider for offline/debug mode testing.

Instead of connecting to a Wazuh instance, this module loads pre-recorded
Wazuh alert data from local JSON files. Useful for:
- Running tests without a Wazuh instance
- Consistent reproducible scenarios
- CI/CD pipelines
- Development and prototyping
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class LocalDataProvider:
    """Load Wazuh alerts from local JSON files instead of live indexer."""

    def __init__(self, data_dir: str, data_file: Optional[str] = None):
        """
        Initialize local data provider.

        Args:
            data_dir: Directory containing Wazuh alert JSON files.
            data_file: Specific JSON file to load (optional). If provided, only
                      this file will be loaded. Otherwise all JSON files in
                      data_dir are loaded.

        Raises:
            FileNotFoundError: If data_dir doesn't exist or data_file not found.
            ValueError: If data_dir contains no JSON files (when data_file not specified).
        """
        self.data_dir = Path(data_dir)
        if not self.data_dir.exists():
            raise FileNotFoundError(f"Data directory does not exist: {data_dir}")

        # Determine which files to load
        if data_file:
            # Load specific file
            file_path = self.data_dir / data_file
            if not file_path.exists():
                raise FileNotFoundError(f"Data file does not exist: {file_path}")
            self.alert_files = [file_path]
            logger.info(f"Using specific alert file: {data_file}")
        else:
            # Discover all JSON files in the directory
            self.alert_files = sorted(self.data_dir.glob("*.json"))
            if not self.alert_files:
                raise ValueError(f"No JSON files found in data directory: {data_dir}")
            logger.info(f"Found {len(self.alert_files)} alert files in {data_dir}")

        # Load all alerts once into memory
        self._alerts: List[Dict[str, Any]] = []
        self._load_alerts()

    def _load_alerts(self) -> None:
        """Load all alerts from JSON files into memory.
        
        Supports multiple formats:
        1. JSON array: [{...}, {...}]
        2. Single JSON object: {...}
        3. OpenSearch API response: {hits: {hits: [{_source: {...}}, ...]}}
        """
        for file_path in self.alert_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if not content:
                        logger.warning(f"Skipping empty file: {file_path}")
                        continue

                    data = json.loads(content)
                    
                    # Detect and handle OpenSearch API response format
                    if isinstance(data, dict) and "hits" in data:
                        if "hits" in data["hits"] and isinstance(data["hits"]["hits"], list):
                            # Extract _source from each hit
                            alerts = [hit["_source"] for hit in data["hits"]["hits"] if "_source" in hit]
                            if alerts:
                                self._alerts.extend(alerts)
                                logger.info(f"Loaded {len(alerts)} alerts from OpenSearch response format in {file_path.name}")
                            else:
                                logger.warning(f"No _source documents found in OpenSearch response in {file_path}")
                            continue
                    
                    # Handle JSON array format
                    if isinstance(data, list):
                        self._alerts.extend(data)
                        logger.debug(f"Loaded {len(data)} alerts from array in {file_path.name}")
                    # Handle single JSON object
                    elif isinstance(data, dict):
                        self._alerts.append(data)
                        logger.debug(f"Loaded 1 alert from object in {file_path.name}")
                    else:
                        logger.warning(f"Unexpected JSON type in {file_path}: {type(data)}")

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON in {file_path}: {e}")
            except Exception as e:
                logger.error(f"Failed to load alerts from {file_path}: {e}")

        logger.info(f"Loaded total of {len(self._alerts)} alerts from all files")

    def search_alerts(
        self,
        start: datetime,
        end: datetime,
        query: Optional[Dict[str, Any]] = None,
        ignore_time_range: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Filter alerts by timestamp range.

        Similar interface to WazuhIndexerClient.search_alerts() to ensure
        compatibility with existing code.

        Args:
            start: Start datetime (UTC).
            end: End datetime (UTC).
            query: Optional query filter (currently ignored for local data).
            ignore_time_range: If True, return all alerts regardless of timestamp.
                              Useful for debug mode with historical test data.

        Returns:
            List of alert documents within the time range (or all if ignore_time_range=True).
        """
        if not self._alerts:
            logger.warning("No alerts loaded from local data")
            return []

        # If ignore_time_range is True, return all alerts (for debug mode with historical data)
        if ignore_time_range:
            logger.info(f"Returning all {len(self._alerts)} alerts (time range filter disabled)")
            return self._alerts.copy()

        filtered_alerts: List[Dict[str, Any]] = []

        for alert in self._alerts:
            # Extract timestamp from alert
            ts_str = alert.get("timestamp")
            if not ts_str:
                logger.debug(f"Skipping alert without timestamp: {alert}")
                continue

            try:
                # Parse timestamp (handle various ISO 8601 formats)
                alert_ts = self._parse_timestamp(ts_str)

                # Check if within range
                if start <= alert_ts <= end:
                    filtered_alerts.append(alert)
            except ValueError as e:
                logger.debug(f"Skipping alert with unparseable timestamp '{ts_str}': {e}")

        logger.info(
            f"Found {len(filtered_alerts)} alerts in range {start.isoformat()} to {end.isoformat()}"
        )
        return filtered_alerts

    @staticmethod
    def _parse_timestamp(ts: str) -> datetime:
        """
        Parse ISO 8601 timestamp with various formats.

        Accepts:
            - 2025-12-25T19:47:32.017Z
            - 2025-12-25T19:47:32Z
            - 2025-12-25T19:47:32.017+00:00
            - 2025-12-25T19:47:32+0000

        Returns:
            Timezone-aware datetime in UTC.
        """
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"

        # Remove trailing timezone if just +00:00 and no fractional seconds
        if "+00:00" in ts or "-" in ts[-6:]:  # Has timezone info
            # Use fromisoformat for Python 3.7+
            try:
                return datetime.fromisoformat(ts)
            except ValueError:
                # Fallback for non-standard formats
                pass

        # Try parsing without timezone
        for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"]:
            try:
                dt = datetime.strptime(ts.split("+")[0].split("Z")[0], fmt)
                # Assume UTC if no timezone
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

        raise ValueError(f"Unable to parse timestamp: {ts}")

    def check_connection(self) -> bool:
        """
        Mock connection check (always returns True if data loaded).

        Returns:
            True if data is available, False otherwise.
        """
        return len(self._alerts) > 0

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """
        Get all loaded alerts.

        Useful for testing or inspecting available data.

        Returns:
            List of all loaded alerts.
        """
        return self._alerts.copy()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics about loaded data.

        Returns:
            Dictionary with data statistics.
        """
        if not self._alerts:
            return {"total_alerts": 0}

        timestamps = []
        for alert in self._alerts:
            ts_str = alert.get("timestamp")
            if ts_str:
                try:
                    ts = self._parse_timestamp(ts_str)
                    timestamps.append(ts)
                except ValueError:
                    pass

        if timestamps:
            timestamps.sort()
            return {
                "total_alerts": len(self._alerts),
                "start_time": timestamps[0].isoformat(),
                "end_time": timestamps[-1].isoformat(),
                "time_range_hours": (timestamps[-1] - timestamps[0]).total_seconds() / 3600,
            }
        else:
            return {"total_alerts": len(self._alerts), "warning": "Could not parse timestamps"}
