#!/usr/bin/env python3
"""
Inject synthetic Wazuh alert data into a Wazuh Indexer (OpenSearch) instance.

This tool populates a Wazuh installation with synthetic alerts to enable:
- Testing SONAR in production mode without waiting for real data accumulation
- Integration testing with realistic data volumes
- Demos and development with controlled scenarios
- Validation of the full pipeline (WazuhIndexerClient → OpenSearch → MVAD)

Usage:
    # Inject recent data (last 24 hours) for immediate testing
    python inject_wazuh_data.py --config ../default_config.yaml --hours 24 --source generated_scenarios/normal_training.json
    
    # Inject data with attacks for detection testing
    python inject_wazuh_data.py --config ../default_config.yaml --hours 48 --source generated_scenarios/attack_scenarios.json
    
    # Inject 14 days of baseline data
    python inject_wazuh_data.py --config ../default_config.yaml --days 14 --source synthetic_alerts/normal_baseline.json
    
    # Dry run to preview what would be injected
    python inject_wazuh_data.py --config ../default_config.yaml --hours 24 --dry-run
    
    # Custom time range
    python inject_wazuh_data.py --config ../default_config.yaml --start "2025-12-29 00:00:00" --end "2025-12-30 00:00:00"

Features:
- Reads existing synthetic alerts from JSON files
- Adjusts timestamps to specified time range
- Maintains temporal distribution patterns
- Uses bulk indexing for performance
- Validates Wazuh connection before injection
- Supports dry-run mode for safety
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sonar.cli import load_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)


class WazuhDataInjector:
    """Inject synthetic alerts into Wazuh Indexer (OpenSearch)."""
    
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        index_pattern: str = "wazuh-alerts-4.x-*",
        verify_ssl: bool = False,
        bulk_size: int = 1000
    ):
        """
        Initialize Wazuh data injector.
        
        Args:
            base_url: Wazuh Indexer base URL (e.g., https://localhost:9200)
            username: Authentication username
            password: Authentication password
            index_pattern: Target index pattern for alerts
            verify_ssl: Whether to verify SSL certificates
            bulk_size: Number of documents per bulk request
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.index_pattern = index_pattern
        self.verify_ssl = verify_ssl
        self.bulk_size = bulk_size
        
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = verify_ssl
        
        # Suppress SSL warnings if not verifying
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def test_connection(self) -> bool:
        """Test connection to Wazuh Indexer."""
        try:
            url = f"{self.base_url}/_cluster/health"
            resp = self.session.get(url, timeout=10)
            resp.raise_for_status()
            health = resp.json()
            logger.info(f"✓ Connected to Wazuh Indexer - Cluster: {health.get('cluster_name', 'unknown')}, Status: {health.get('status', 'unknown')}")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"✗ Failed to connect to Wazuh Indexer: {e}")
            return False
    
    def get_index_name(self, timestamp: datetime) -> str:
        """
        Generate index name based on timestamp.
        
        Wazuh typically uses daily indices: wazuh-alerts-4.x-2025.12.30
        """
        date_suffix = timestamp.strftime("%Y.%m.%d")
        # Extract base pattern without wildcard (keep trailing dash if present)
        base = self.index_pattern.replace("*", "")
        if not base.endswith("-"):
            base += "-"
        return f"{base}{date_suffix}"
    
    def load_alerts(self, filepath: Path) -> List[Dict[str, Any]]:
        """Load alerts from JSON file."""
        logger.info(f"Loading alerts from {filepath}")
        
        if not filepath.exists():
            raise FileNotFoundError(f"Alert file not found: {filepath}")
        
        with open(filepath, 'r') as f:
            alerts = json.load(f)
        
        logger.info(f"Loaded {len(alerts)} alerts")
        return alerts
    
    def adjust_timestamps(
        self,
        alerts: List[Dict[str, Any]],
        target_start: datetime,
        target_end: datetime
    ) -> List[Dict[str, Any]]:
        """
        Adjust alert timestamps to fit within target time range.
        
        Maintains relative temporal distribution of alerts.
        
        Args:
            alerts: List of alert documents
            target_start: Target start datetime (UTC)
            target_end: Target end datetime (UTC)
            
        Returns:
            Alerts with adjusted timestamps
        """
        if not alerts:
            return alerts
        
        # Find original time range
        timestamps = []
        for alert in alerts:
            ts_str = alert.get("timestamp", "")
            if ts_str:
                try:
                    # Handle various timestamp formats
                    if "T" in ts_str:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    else:
                        ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    timestamps.append(ts)
                except (ValueError, AttributeError):
                    pass
        
        if not timestamps:
            logger.warning("No valid timestamps found in alerts, using even distribution")
            # Distribute evenly across target range
            delta = (target_end - target_start) / len(alerts)
            for i, alert in enumerate(alerts):
                new_ts = target_start + (delta * i)
                alert["timestamp"] = new_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-3]
            return alerts
        
        orig_start = min(timestamps)
        orig_end = max(timestamps)
        orig_duration = (orig_end - orig_start).total_seconds()
        target_duration = (target_end - target_start).total_seconds()
        
        logger.info(f"Original time range: {orig_start} to {orig_end} ({orig_duration/3600:.1f} hours)")
        logger.info(f"Target time range: {target_start} to {target_end} ({target_duration/3600:.1f} hours)")
        
        # Adjust each timestamp proportionally
        adjusted_count = 0
        for alert in alerts:
            ts_str = alert.get("timestamp", "")
            if not ts_str:
                continue
            
            try:
                if "T" in ts_str:
                    orig_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                else:
                    orig_ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                
                # Calculate relative position in original range
                if orig_duration > 0:
                    relative_pos = (orig_ts - orig_start).total_seconds() / orig_duration
                else:
                    relative_pos = 0.5
                
                # Map to target range
                new_ts = target_start + timedelta(seconds=relative_pos * target_duration)
                
                # Update timestamp in ISO format with milliseconds
                alert["timestamp"] = new_ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                
                # Also update @timestamp if present (OpenSearch convention)
                if "@timestamp" in alert:
                    alert["@timestamp"] = alert["timestamp"]
                
                adjusted_count += 1
                
            except (ValueError, AttributeError) as e:
                logger.debug(f"Could not adjust timestamp '{ts_str}': {e}")
                continue
        
        logger.info(f"Adjusted {adjusted_count} timestamps")
        return alerts
    
    def bulk_index(
        self,
        alerts: List[Dict[str, Any]],
        dry_run: bool = False
    ) -> int:
        """
        Bulk index alerts into Wazuh Indexer.
        
        Args:
            alerts: List of alert documents
            dry_run: If True, don't actually index (just log)
            
        Returns:
            Number of successfully indexed documents
        """
        if not alerts:
            logger.warning("No alerts to index")
            return 0
        
        total_indexed = 0
        
        # Group alerts by index (based on timestamp)
        index_groups: Dict[str, List[Dict[str, Any]]] = {}
        for alert in alerts:
            ts_str = alert.get("timestamp", "")
            if ts_str:
                try:
                    # Parse adjusted timestamps (ISO format with milliseconds and Z)
                    if ts_str.endswith("Z"):
                        ts_str_clean = ts_str[:-1]
                    else:
                        ts_str_clean = ts_str
                    ts = datetime.fromisoformat(ts_str_clean)
                    
                    index_name = self.get_index_name(ts)
                    if index_name not in index_groups:
                        index_groups[index_name] = []
                    index_groups[index_name].append(alert)
                except (ValueError, AttributeError) as e:
                    logger.debug(f"Invalid timestamp '{ts_str}': {e}")
        
        logger.info(f"Indexing to {len(index_groups)} indices: {', '.join(index_groups.keys())}")
        
        # Process each index
        for index_name, index_alerts in index_groups.items():
            logger.info(f"Processing {len(index_alerts)} alerts for index {index_name}")
            
            # Process in batches
            for i in range(0, len(index_alerts), self.bulk_size):
                batch = index_alerts[i:i + self.bulk_size]
                
                if dry_run:
                    logger.info(f"[DRY RUN] Would index {len(batch)} documents to {index_name}")
                    total_indexed += len(batch)
                    continue
                
                # Build bulk request body
                bulk_body = []
                for doc in batch:
                    # Action line (index operation)
                    action = {"index": {"_index": index_name}}
                    bulk_body.append(json.dumps(action))
                    
                    # Document line
                    bulk_body.append(json.dumps(doc, default=str))
                
                bulk_data = "\n".join(bulk_body) + "\n"
                
                # Send bulk request
                try:
                    url = f"{self.base_url}/_bulk"
                    headers = {"Content-Type": "application/x-ndjson"}
                    resp = self.session.post(url, data=bulk_data, headers=headers, timeout=30)
                    resp.raise_for_status()
                    
                    result = resp.json()
                    if result.get("errors"):
                        # Log individual errors
                        error_count = 0
                        for item in result.get("items", []):
                            if "error" in item.get("index", {}):
                                error_count += 1
                                if error_count <= 3:  # Log first 3 errors
                                    logger.error(f"Index error: {item['index']['error']}")
                        logger.warning(f"Bulk request had {error_count} errors")
                        total_indexed += len(batch) - error_count
                    else:
                        total_indexed += len(batch)
                        logger.info(f"✓ Indexed batch of {len(batch)} documents to {index_name}")
                    
                except requests.exceptions.RequestException as e:
                    logger.error(f"Failed to index batch: {e}")
        
        return total_indexed


def parse_datetime(dt_str: str) -> datetime:
    """Parse datetime string in various formats."""
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(dt_str, fmt)
        except ValueError:
            continue
    
    raise ValueError(f"Could not parse datetime: {dt_str}")


def main():
    parser = argparse.ArgumentParser(
        description="Inject synthetic Wazuh alert data for testing SONAR",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Inject last 24 hours of data
  python inject_wazuh_data.py --config ../default_config.yaml --hours 24
  
  # Inject specific attack scenario
  python inject_wazuh_data.py --config ../default_config.yaml --hours 48 --source generated_scenarios/attack_scenarios.json
  
  # Inject 14 days of baseline
  python inject_wazuh_data.py --config ../default_config.yaml --days 14 --source synthetic_alerts/normal_baseline.json
  
  # Custom time range
  python inject_wazuh_data.py --config ../default_config.yaml --start "2025-12-29 00:00:00" --end "2025-12-30 00:00:00"
  
  # Dry run (preview only)
  python inject_wazuh_data.py --config ../default_config.yaml --hours 24 --dry-run
        """
    )
    
    # Connection options
    parser.add_argument(
        "--config",
        type=Path,
        help="Path to SONAR config YAML (default: ../default_config.yaml)"
    )
    parser.add_argument("--host", help="Wazuh Indexer host (overrides config)")
    parser.add_argument("--port", type=int, help="Wazuh Indexer port (overrides config)")
    parser.add_argument("--username", help="Wazuh Indexer username (overrides config)")
    parser.add_argument("--password", help="Wazuh Indexer password (overrides config)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    
    # Data source
    parser.add_argument(
        "--source",
        type=Path,
        help="Path to JSON file with synthetic alerts (default: generated_scenarios/normal_training.json)"
    )
    
    # Time range options (mutually exclusive groups)
    time_group = parser.add_mutually_exclusive_group()
    time_group.add_argument(
        "--hours",
        type=int,
        help="Inject data for last N hours (e.g., --hours 24)"
    )
    time_group.add_argument(
        "--days",
        type=int,
        help="Inject data for last N days (e.g., --days 7)"
    )
    time_group.add_argument(
        "--range",
        nargs=2,
        metavar=("START", "END"),
        help='Custom time range: --range "2025-12-29 00:00:00" "2025-12-30 00:00:00"'
    )
    
    # Indexing options
    parser.add_argument(
        "--bulk-size",
        type=int,
        default=1000,
        help="Number of documents per bulk request (default: 1000)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be injected without actually indexing"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config_path = args.config or Path(__file__).parent.parent / "default_config.yaml"
    
    if config_path.exists():
        logger.info(f"Loading config from {config_path}")
        cfg = load_config(str(config_path))
        wazuh_cfg = cfg.wazuh
    else:
        logger.warning(f"Config file not found: {config_path}")
        wazuh_cfg = None
    
    # Build connection parameters (CLI args override config)
    host = args.host or (wazuh_cfg.base_url.split("://")[-1].split(":")[0] if wazuh_cfg and wazuh_cfg.base_url else "localhost")
    port = args.port or (int(wazuh_cfg.base_url.split(":")[-1]) if wazuh_cfg and wazuh_cfg.base_url and ":" in wazuh_cfg.base_url.split("://")[-1] else 9200)
    username = args.username or (wazuh_cfg.username if wazuh_cfg else "admin")
    password = args.password or (wazuh_cfg.password if wazuh_cfg else "admin")
    verify_ssl = not args.no_verify_ssl and (wazuh_cfg.verify_ssl if wazuh_cfg else True)
    
    base_url = f"https://{host}:{port}"
    
    # Determine source file
    if args.source:
        source_file = args.source
    else:
        source_file = Path(__file__).parent / "generated_scenarios" / "normal_training.json"
        # Fallback to synthetic_alerts if generated_scenarios doesn't exist
        if not source_file.exists():
            source_file = Path(__file__).parent / "synthetic_alerts" / "normal_baseline.json"
    
    if not source_file.exists():
        logger.error(f"Source file not found: {source_file}")
        logger.info("Available test data files:")
        test_data_dir = Path(__file__).parent
        for json_file in test_data_dir.rglob("*.json"):
            logger.info(f"  - {json_file.relative_to(test_data_dir)}")
        return 1
    
    # Determine time range
    now = datetime.utcnow()
    
    if args.range:
        target_start = parse_datetime(args.range[0])
        target_end = parse_datetime(args.range[1])
    elif args.hours:
        target_start = now - timedelta(hours=args.hours)
        target_end = now
    elif args.days:
        target_start = now - timedelta(days=args.days)
        target_end = now
    else:
        # Default: last 24 hours
        target_start = now - timedelta(hours=24)
        target_end = now
    
    logger.info("="*70)
    logger.info("Wazuh Data Injector for SONAR")
    logger.info("="*70)
    logger.info(f"Wazuh Indexer: {base_url}")
    logger.info(f"Source file: {source_file}")
    logger.info(f"Target time range: {target_start} to {target_end}")
    logger.info(f"Bulk size: {args.bulk_size}")
    logger.info(f"Dry run: {args.dry_run}")
    logger.info("="*70)
    
    # Initialize injector
    injector = WazuhDataInjector(
        base_url=base_url,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        bulk_size=args.bulk_size
    )
    
    # Test connection
    if not args.dry_run:
        if not injector.test_connection():
            logger.error("Cannot proceed without valid Wazuh Indexer connection")
            return 1
    
    # Load alerts
    try:
        alerts = injector.load_alerts(source_file)
    except Exception as e:
        logger.error(f"Failed to load alerts: {e}")
        return 1
    
    if not alerts:
        logger.error("No alerts loaded")
        return 1
    
    # Adjust timestamps
    alerts = injector.adjust_timestamps(alerts, target_start, target_end)
    
    # Index alerts
    indexed_count = injector.bulk_index(alerts, dry_run=args.dry_run)
    
    logger.info("="*70)
    if args.dry_run:
        logger.info(f"[DRY RUN] Would have indexed {indexed_count} alerts")
    else:
        logger.info(f"✓ Successfully indexed {indexed_count} of {len(alerts)} alerts")
    logger.info("="*70)
    
    if indexed_count > 0:
        logger.info("")
        logger.info("Next steps:")
        logger.info("  1. Wait a few seconds for indexing to complete")
        logger.info("  2. Run SONAR training:")
        logger.info(f"     poetry run sonar train --scenario scenarios/example_scenario.yaml")
        logger.info("  3. Run SONAR detection:")
        logger.info(f"     poetry run sonar detect --scenario scenarios/example_scenario.yaml")
        logger.info("")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
