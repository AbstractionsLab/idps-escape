"""
CLI entry point for SONAR (SIEM-Oriented Neural Anomaly Recognition).

Usage:
    sonar train [--config CONFIG_YAML] [--lookback-hours HOURS]
    sonar detect [--config CONFIG_YAML] [--lookback-minutes MINUTES] [--mode MODE]
    sonar scenario [--use-case YAML_FILE]
    sonar check                     # Check Wazuh connection
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import yaml

from sonar.config import PipelineConfig
from sonar.engine import MVADModelEngine
from sonar.features import WazuhFeatureBuilder
from sonar.pipeline import MVADPostProcessor
from sonar.wazuh_client import WazuhIndexerClient
from sonar.scenario import UseCase, TrainingScenario, DetectionScenario
from sonar.local_data_provider import LocalDataProvider

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# --- Shipping Helper Functions ---

def _get_scenario_id(cfg: PipelineConfig) -> str:
    """
    Get scenario ID for data stream naming.
    
    Uses custom scenario_id from config if provided, otherwise generates from model_path.
    
    Args:
        cfg: Pipeline configuration.
        
    Returns:
        8-character scenario ID.
    """
    if cfg.shipping.scenario_id:
        return cfg.shipping.scenario_id
    
    import hashlib
    return hashlib.md5(cfg.model_path.encode()).hexdigest()[:8]


def _should_ship(cfg: PipelineConfig, args: argparse.Namespace) -> bool:
    """
    Determine if shipping should be enabled.
    
    Shipping is enabled if:
    - CLI --ship flag is set OR config shipping.enabled is True
    - AND debug mode is NOT enabled
    
    Args:
        cfg: Pipeline configuration.
        args: CLI arguments.
        
    Returns:
        True if shipping should be enabled.
    """
    cli_ship = getattr(args, "ship", False)
    config_ship = cfg.shipping.enabled
    debug_mode = cfg.debug.enabled or getattr(args, "debug", False)
    
    return (cli_ship or config_ship) and not debug_mode


def _create_scenario_stream(cfg: PipelineConfig, ts_data, scenario_name: str = None):
    """
    Create data stream for a scenario during training.
    
    Args:
        cfg: Pipeline configuration.
        ts_data: Training time series data (for feature extraction).
        scenario_name: Optional custom scenario name.
    """
    try:
        from sonar.shipper.wazuh_data_shipper import WazuhDataShipper

        logger.info("Initializing data shipper for stream creation...")
        shipper = WazuhDataShipper(cfg.wazuh, install=cfg.shipping.install_templates)

        # Generate scenario ID
        scenario_id = _get_scenario_id(cfg)
        if not scenario_name:
            scenario_name = f"sonar_scenario_{scenario_id}"

        # Extract feature names from trained model for template
        feature_types = {col: "float" for col in ts_data.columns}

        logger.info(f"Creating data stream for scenario: {scenario_name}")
        stream_name = shipper.create_scenario_stream(scenario_id, scenario_name, feature_types)
        logger.info(f"✓ Data stream ready: {stream_name}")
        logger.info("  Future detection runs with shipping enabled will index anomalies to this stream")
    except Exception as e:
        logger.error(f"Failed to setup data shipping: {e}")
        logger.warning("Training completed but shipping setup failed")


def _ship_anomalies(cfg: PipelineConfig, client, anomaly_docs: list) -> bool:
    """
    Ship anomaly documents to data stream.
    
    Args:
        cfg: Pipeline configuration.
        client: Wazuh client (for fallback).
        anomaly_docs: List of anomaly documents to ship.
        
    Returns:
        True if shipping succeeded, False if fell back to standard indexing.
    """
    try:
        from sonar.shipper.wazuh_data_shipper import WazuhDataShipper

        logger.info("Shipping anomalies to Wazuh data stream...")
        shipper = WazuhDataShipper(cfg.wazuh, install=False)

        # Generate scenario ID and stream name
        scenario_id = _get_scenario_id(cfg)
        stream_name = f"sonar_anomalies_mvad_{scenario_id}"

        # Ship each anomaly document
        shipped_count = 0
        for doc in anomaly_docs:
            try:
                response = shipper.ship_single(stream_name, doc)
                logger.info(f"  Shipped anomaly to {stream_name}: {response.get('_id', 'N/A')}")
                shipped_count += 1
            except Exception as e:
                logger.warning(f"  Failed to ship anomaly: {e}")
        
        logger.info(f"✓ Shipped {shipped_count}/{len(anomaly_docs)} anomalies to data stream")
        return True
        
    except Exception as e:
        logger.error(f"Failed to ship anomalies: {e}")
        logger.info("Falling back to standard anomaly indexing...")
        
        # Fall back to standard indexing
        for doc in anomaly_docs:
            try:
                doc_id = client.index_anomaly(doc)
                logger.info(f"  Indexed anomaly: {doc_id}")
            except Exception as e:
                logger.warning(f"  Failed to index anomaly: {e}")
        
        return False


# --- Synthetic Data Generation ---


def _generate_and_index_synthetic_alerts(
    cfg: PipelineConfig,
    fb: WazuhFeatureBuilder,
    client,
    alerts: list,
    ts_data,
    target_count: int,
    synthetic_mode: str = "constant",
    synthetic_level: float = None,
    synthetic_srcip: str = None,
) -> list:
    """
    Generate synthetic alerts to fill insufficient data and index them to Wazuh.
    
    Creates synthetic alerts by examining the training data columns and generating
    alerts that will reproduce those same fields when processed by the feature builder.
    This ensures synthetic data matches the actual scenario's feature structure.
    
    Args:
        cfg: Pipeline configuration.
        fb: WazuhFeatureBuilder instance (for field extraction).
        client: Wazuh client or LocalDataProvider for indexing.
        alerts: Existing alerts (for 'copy' mode).
        ts_data: Existing time series data (used to determine what fields to generate).
        target_count: Number of synthetic alerts to generate.
        synthetic_mode: Mode for synthetic content ('constant', 'random', 'copy').
        synthetic_level: Level value for 'constant' mode.
        synthetic_srcip: Source IP for 'constant' mode.
    
    Returns:
        List of synthetic alert dictionaries that were indexed.
    """
    from datetime import datetime, timedelta, timezone
    import random
    
    # Determine base timestamp
    bucket_min = cfg.features.bucket_minutes
    if len(ts_data) > 0:
        base_ts = ts_data.index[0]
    else:
        base_ts = datetime.now(timezone.utc)
    
    # Analyze the training data columns to understand what fields we need to generate
    # The columns in ts_data represent the features that the scenario uses
    columns_needed = list(ts_data.columns) if len(ts_data) > 0 else ["rule.level"]
    
    # Extract configured fields from the feature builder config
    numeric_fields = cfg.features.numeric_fields
    categorical_fields = cfg.features.categorical_fields
    
    # Compute default values from existing data
    default_values = {}
    for col in columns_needed:
        if col in ts_data.columns and len(ts_data) > 0:
            if ts_data[col].dtype in ['float64', 'int64']:
                default_values[col] = float(ts_data[col].mean())
            else:
                default_values[col] = str(ts_data[col].mode()[0]) if len(ts_data[col].mode()) > 0 else "default"
        else:
            default_values[col] = 5.0 if "level" in col else "default_value"
    
    # Fallback default level
    default_level = default_values.get("rule.level", 0.0)
    
    def _make_random_ip(i: int) -> str:
        """Generate a deterministic test IP address."""
        # Use TEST-NET-1 space to avoid real IPs (192.0.2.x)
        return f"192.0.2.{(i % 250) + 1}"
    
    def _choose_from_existing(field: str, i: int):
        """Choose a value from existing alerts for the given nested field."""
        if not alerts:
            return None
        for a in alerts:
            val = a
            for key in field.split("."):
                val = val.get(key) if isinstance(val, dict) else None
                if val is None:
                    break
            if val is not None:
                return val
        return None
    
    def _set_nested_value(obj: dict, path: str, value):
        """Set a value in a nested dictionary using dot notation."""
        parts = path.split(".")
        target = obj
        for part in parts[:-1]:
            if part not in target:
                target[part] = {}
            target = target[part]
        target[parts[-1]] = value
    
    logger.info(
        f"Generating synthetic alerts to match training data structure: "
        f"{len(columns_needed)} features from {len(alerts)} existing alerts"
    )
    
    synthetic_alerts = []
    for i in range(target_count):
        # Compute timestamp for this synthetic alert (going back in time)
        delta = (i + 1) * bucket_min
        ts = (base_ts - timedelta(minutes=delta)).astimezone(timezone.utc)
        ts_str = ts.isoformat().replace("+00:00", "Z")
        
        # Base alert structure
        alert: Dict[str, Any] = {
            "timestamp": ts_str,
            "rule": {"id": "999999", "description": "Synthetic alert for MVAD"},
            "agent": {"name": "synthetic-agent"},
            "data": {},
        }
        
        # Generate values for all numeric fields needed
        for field in numeric_fields:
            if synthetic_mode == "constant":
                if field == "rule.level":
                    value = synthetic_level if synthetic_level is not None else default_level
                else:
                    # Use default value from training data if available
                    value = default_values.get(field, default_level)
            elif synthetic_mode == "random":
                if field == "rule.level":
                    value = float(random.randint(1, 15))
                else:
                    # Random value around the default
                    base_val = default_values.get(field, 50.0)
                    value = base_val + random.uniform(-10, 10)
            elif synthetic_mode == "copy":
                # Try to copy from existing alerts
                value = _choose_from_existing(field, i)
                if value is None:
                    value = default_values.get(field, default_level)
            else:
                value = default_values.get(field, default_level)
            
            _set_nested_value(alert, field, float(value))
        
        # Generate values for all categorical fields needed
        for field in categorical_fields:
            if synthetic_mode == "constant":
                if "srcip" in field.lower():
                    value = synthetic_srcip if synthetic_srcip else "192.0.2.100"
                elif "dstip" in field.lower():
                    value = "192.0.2.1"
                elif "user" in field.lower():
                    value = "synthetic_user"
                else:
                    value = default_values.get(field, f"synthetic_{field.split('.')[-1]}")
            elif synthetic_mode == "random":
                if "ip" in field.lower():
                    value = _make_random_ip(i)
                elif "user" in field.lower():
                    value = f"user_{random.randint(1, 100)}"
                else:
                    value = f"random_{field.split('.')[-1]}_{random.randint(1, 1000)}"
            elif synthetic_mode == "copy":
                value = _choose_from_existing(field, i)
                if value is None:
                    value = default_values.get(field, f"synthetic_{field.split('.')[-1]}")
            else:
                value = default_values.get(field, f"synthetic_{field.split('.')[-1]}")
            
            _set_nested_value(alert, field, value)
        
        # Try to index the alert
        try:
            alert_id = client.index_alert(alert)
            logger.info("Indexed synthetic alert: %s", alert_id)
        except Exception as e:
            logger.warning("Failed to index synthetic alert: %s", e)
        
        synthetic_alerts.append(alert)
    
    logger.info(
        f"Generated and indexed {len(synthetic_alerts)} synthetic alerts "
        f"(mode={synthetic_mode}, level={synthetic_level or default_level:.1f}, "
        f"fields={len(numeric_fields) + len(categorical_fields)})"
    )
    
    return synthetic_alerts


# --- Model Naming Utilities ---


def generate_model_name(scenario_name: str) -> str:
    """
    Generate a unique model name from scenario name.
    
    Args:
        scenario_name: Scenario name or identifier.
        
    Returns:
        Model name safe for filesystem (alphanumeric + underscores).
    """
    import re
    from datetime import datetime
    
    # Sanitize scenario name for filesystem
    safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', scenario_name)
    safe_name = re.sub(r'_+', '_', safe_name).strip('_').lower()
    
    # Add timestamp for uniqueness
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    return f"{safe_name}_{timestamp}"


def ensure_model_directory(model_path: str) -> None:
    """
    Ensure the directory for the model file exists.
    
    Args:
        model_path: Path to the model file.
    """
    import os
    model_dir = os.path.dirname(model_path)
    if model_dir and not os.path.exists(model_dir):
        os.makedirs(model_dir, exist_ok=True)
        logger.info(f"Created model directory: {model_dir}")


# --- Configuration Loading ---


def load_scenario_for_phase(scenario_path: str, phase: str, base_config_path: str = None) -> tuple:
    """
    Load scenario YAML and extract configuration for a specific phase.
    
    Args:
        scenario_path: Path to scenario YAML file.
        phase: Either 'training' or 'detection'.
        base_config_path: Optional base config to merge with.
        
    Returns:
        Tuple of (PipelineConfig, phase_scenario_object)
    """
    # Load scenario
    uc = UseCase.from_yaml(scenario_path)
    
    # Load base config
    cfg = load_config(base_config_path)
    
    # Load scenario YAML for debug/shipping/wazuh sections
    with open(scenario_path, 'r') as f:
        scenario_yaml = yaml.safe_load(f)
    
    # Apply wazuh config if present
    if "wazuh" in scenario_yaml:
        cfg.wazuh.__dict__.update(scenario_yaml["wazuh"])
    
    # Apply debug config if present
    if "debug" in scenario_yaml:
        cfg.debug.__dict__.update(scenario_yaml["debug"])
    
    # Apply shipping config if present
    if "shipping" in scenario_yaml:
        cfg.shipping.__dict__.update(scenario_yaml["shipping"])
    
    # Set model path based on model_name
    if uc.model_name:
        # Use provided model name
        model_name = uc.model_name
        logger.info(f"Using model name from scenario: {model_name}")
    else:
        # Generate unique model name from scenario name
        model_name = generate_model_name(uc.name)
        logger.info(f"Generated model name: {model_name}")
    
    cfg.model_path = f"./sonar/models/{model_name}.pkl"
    
    if phase == 'training':
        # Apply training-specific config
        cfg.features.numeric_fields = uc.training.numeric_fields
        cfg.features.categorical_fields = uc.training.categorical_fields
        cfg.features.categorical_top_k = uc.training.categorical_top_k
        cfg.features.bucket_minutes = uc.training.bucket_minutes
        cfg.mvad.sliding_window = uc.training.sliding_window
        cfg.mvad.device = uc.training.device
        cfg.mvad.extra_params.update(uc.training.extra_params)
        
        return cfg, uc.training
    
    elif phase == 'detection':
        # Apply training config first (for feature extraction consistency)
        cfg.features.numeric_fields = uc.training.numeric_fields
        cfg.features.categorical_fields = uc.training.categorical_fields
        cfg.features.categorical_top_k = uc.training.categorical_top_k
        cfg.features.bucket_minutes = uc.training.bucket_minutes
        
        # Return detection scenario so caller can access threshold/min_consecutive
        return cfg, uc.detection
    
    else:
        raise ValueError(f"Unknown phase: {phase}")


def load_config(config_path: str) -> PipelineConfig:
    """
    Load PipelineConfig from YAML file.

    If config_path is not provided, uses default_config.yaml from the sonar directory.

    Args:
        config_path: Path to config YAML (optional).

    Returns:
        PipelineConfig instance.
    """
    # Determine which config file to use
    if not config_path:
        # Use default config file from sonar directory
        default_config_path = Path(__file__).parent / "default_config.yaml"
        config_path = str(default_config_path)
        logger.info(f"No config provided, using default: {config_path}")
    
    # Load YAML file
    with open(config_path, "r") as f:
        raw = yaml.safe_load(f)
    
    # Create base config
    cfg = PipelineConfig()
    
    # Update each section if present in YAML
    if "wazuh" in raw:
        cfg.wazuh.__dict__.update(raw["wazuh"])
    if "mvad" in raw:
        cfg.mvad.__dict__.update(raw["mvad"])
    if "features" in raw:
        # Handle both lists and tuples for sequence fields
        features_data = raw["features"]
        if "numeric_fields" in features_data:
            cfg.features.numeric_fields = tuple(features_data["numeric_fields"])
        if "categorical_fields" in features_data:
            cfg.features.categorical_fields = tuple(features_data["categorical_fields"])
        if "categorical_top_k" in features_data:
            cfg.features.categorical_top_k = features_data["categorical_top_k"]
        if "bucket_minutes" in features_data:
            cfg.features.bucket_minutes = features_data["bucket_minutes"]
        if "derived_features" in features_data:
            cfg.features.derived_features = features_data["derived_features"]
    if "debug" in raw:
        cfg.debug.__dict__.update(raw["debug"])
    if "shipping" in raw:
        cfg.shipping.__dict__.update(raw["shipping"])
    if "model_path" in raw:
        cfg.model_path = raw["model_path"]
    
    return cfg


def cmd_train(args: argparse.Namespace) -> int:
    """
    Train MVAD model on historical Wazuh data.

    Args:
        args: Parsed CLI arguments with config, lookback_hours.

    Returns:
        0 on success, 1 on failure.
    """
    try:
        # Check if scenario mode
        if hasattr(args, 'scenario') and args.scenario:
            logger.info("Loading configuration from scenario file: %s", args.scenario)
            cfg, training = load_scenario_for_phase(args.scenario, 'training', args.config)
            # Model path already set in load_scenario_for_phase
            # Override if --model-name provided via CLI
            if hasattr(args, 'model_name') and args.model_name:
                cfg.model_path = f"./sonar/models/{args.model_name}.pkl"
                logger.info(f"Overriding model name from CLI: {args.model_name}")
            
            # Use scenario values as defaults, CLI arguments override if explicitly set
            # For lookback_hours, check if it's the default value (24)
            if args.lookback_hours != 24:
                lookback_hours = args.lookback_hours
            else:
                lookback_hours = training.lookback_hours
                
            fill_synthetic = args.fill_with_synthetic or training.fill_with_synthetic
            synthetic_count = args.synthetic_count if args.synthetic_count is not None else training.synthetic_count
            synthetic_mode = args.synthetic_mode if args.synthetic_mode != "constant" else training.synthetic_mode
            synthetic_level = args.synthetic_level if args.synthetic_level is not None else training.synthetic_level
            synthetic_srcip = args.synthetic_srcip if args.synthetic_srcip is not None else training.synthetic_srcip
            
            logger.info("Scenario: %s", training)
        else:
            # Standard config loading
            logger.info("Loading configuration...")
            cfg = load_config(args.config)
            
            # Handle model naming
            if hasattr(args, 'model_name') and args.model_name:
                cfg.model_path = f"./sonar/models/{args.model_name}.pkl"
                logger.info(f"Using model name: {args.model_name}")
            elif cfg.model_path == "./mvad_model.pkl":
                # Generate unique model name if using default path
                model_name = generate_model_name("sonar_train")
                cfg.model_path = f"./sonar/models/{model_name}.pkl"
                logger.info(f"Generated model name: {model_name}")
            
            lookback_hours = args.lookback_hours
            fill_synthetic = args.fill_with_synthetic
            synthetic_count = args.synthetic_count
            synthetic_mode = args.synthetic_mode
            synthetic_level = args.synthetic_level
            synthetic_srcip = args.synthetic_srcip

        # Check if debug mode is enabled
        if args.debug:
            logger.info("🔧 DEBUG MODE ENABLED - Using local test data")
            try:
                data_file = cfg.debug.training_data_file
                logger.info(f"Using training data file: {data_file}")
                client = LocalDataProvider(cfg.debug.data_dir, data_file=data_file)
                logger.info(f"✓ Loaded local data from {cfg.debug.data_dir}/{data_file}")
                stats = client.get_stats()
                logger.info(f"  Data statistics: {stats}")
            except (FileNotFoundError, ValueError) as e:
                logger.error(f"Failed to load local data: {e}")
                return 1
        else:
            logger.info("Connecting to Wazuh Indexer...")
            try:
                client = WazuhIndexerClient(
                    cfg.wazuh,
                    print_payloads=getattr(args, "print_payloads", False),
                    dry_run=getattr(args, "dry_run", False),
                    payload_dir=getattr(args, "payload_dir", None),
                )
            except TypeError:
                # Backwards-compatible for stubs/mocks that accept only (cfg,)
                client = WazuhIndexerClient(cfg.wazuh)
            if not client.check_connection():
                logger.error("Failed to connect to Wazuh Indexer.")
                return 1

        logger.info("Fetching historical alerts...")
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=args.lookback_hours)
        # In debug mode, ignore time range filter (use all test data)
        if args.debug:
            alerts = client.search_alerts(start, end, ignore_time_range=True)
        else:
            alerts = client.search_alerts(start, end)
        logger.info(f"Retrieved {len(alerts)} alerts.")

        logger.info("Building feature time series...")
        fb = WazuhFeatureBuilder(cfg.features)
        ts_data = fb.build_timeseries(alerts)

        # If there are not enough time points for training, optionally fill with synthetic alerts
        params = cfg.mvad.to_params()
        sliding_window = params.get("sliding_window", 0)
        required_points = sliding_window + 1 if sliding_window > 0 else 2

        if len(ts_data) < required_points:
            logger.warning(
                "Insufficient time points for training (have=%d, need=%d).",
                len(ts_data),
                required_points,
            )
            if fill_synthetic:
                logger.info("Filling with synthetic alerts to reach required sample count...")
                # Compute how many buckets to add
                to_add = required_points - len(ts_data)
                
                # Determine the target number of synthetic alerts
                if synthetic_count is not None:
                    target_count = max(synthetic_count, to_add)
                else:
                    target_count = to_add
                
                # Generate and index synthetic alerts using consolidated function
                synthetic_alerts = _generate_and_index_synthetic_alerts(
                    cfg=cfg,
                    fb=fb,
                    client=client,
                    alerts=alerts,
                    ts_data=ts_data,
                    target_count=target_count,
                    synthetic_mode=synthetic_mode,
                    synthetic_level=synthetic_level,
                    synthetic_srcip=synthetic_srcip,
                )
                
                # add synthetic alerts to local list and rebuild ts_data
                alerts.extend(synthetic_alerts)
                ts_data = fb.build_timeseries(alerts)

            else:
                logger.info("Use --fill-with-synthetic to auto-generate synthetic alerts.")
                return 0

        if ts_data.empty:
            logger.warning("No valid time series data after attempted fill; skipping training.")
            return 0

        logger.info(f"Training on {len(ts_data)} time points...")
        print(ts_data.describe())
        engine = MVADModelEngine(cfg)
        engine.train(ts_data)

        logger.info(f"Saving model to {cfg.model_path}...")
        ensure_model_directory(cfg.model_path)
        engine.save()

        # If shipping is enabled, create the data stream template for future anomaly indexing
        if _should_ship(cfg, args):
            _create_scenario_stream(cfg, ts_data)

        logger.info("✓ Training complete.")
        return 0

    except Exception as e:
        logger.exception("Training failed.")
        return 1


def cmd_detect(args: argparse.Namespace) -> int:
    """
    Run anomaly detection on recent Wazuh data.

    Args:
        args: Parsed CLI arguments with config, lookback_minutes.

    Returns:
        0 on success, 1 on failure.
    """
    try:
        # Check if scenario mode
        if hasattr(args, 'scenario') and args.scenario:
            logger.info("Loading configuration from scenario file: %s", args.scenario)
            cfg, detection = load_scenario_for_phase(args.scenario, 'detection', args.config)
            
            # Use scenario values as defaults, CLI arguments override if explicitly set
            if args.lookback_minutes != 10:
                lookback_minutes = args.lookback_minutes
            else:
                lookback_minutes = detection.lookback_minutes
                
            fill_synthetic = args.fill_with_synthetic or detection.fill_with_synthetic
            synthetic_count = args.synthetic_count if args.synthetic_count is not None else detection.synthetic_count
            synthetic_mode = args.synthetic_mode if args.synthetic_mode != "constant" else "constant"
            synthetic_level = args.synthetic_level
            synthetic_srcip = args.synthetic_srcip
            
            logger.info("Scenario: %s", detection)
        else:
            # Standard config loading
            logger.info("Loading configuration...")
            cfg = load_config(args.config)
            
            lookback_minutes = args.lookback_minutes
            fill_synthetic = args.fill_with_synthetic
            synthetic_count = args.synthetic_count
            synthetic_mode = args.synthetic_mode
            synthetic_level = args.synthetic_level
            synthetic_srcip = args.synthetic_srcip

        logger.info("Loading trained model...")
        engine = MVADModelEngine(cfg)
        engine.load()

        # Check if debug mode is enabled
        if args.debug:
            logger.info("🔧 DEBUG MODE ENABLED - Using local test data")
            try:
                data_file = cfg.debug.detection_data_file
                logger.info(f"Using detection data file: {data_file}")
                client = LocalDataProvider(cfg.debug.data_dir, data_file=data_file)
                logger.info(f"✓ Loaded local data from {cfg.debug.data_dir}/{data_file}")
                stats = client.get_stats()
                logger.info(f"  Data statistics: {stats}")
            except (FileNotFoundError, ValueError) as e:
                logger.error(f"Failed to load local data: {e}")
                return 1
        else:
            logger.info("Connecting to Wazuh Indexer...")
            try:
                client = WazuhIndexerClient(
                    cfg.wazuh,
                    print_payloads=getattr(args, "print_payloads", False),
                    dry_run=getattr(args, "dry_run", False),
                    payload_dir=getattr(args, "payload_dir", None),
                )
            except TypeError:
                # Backwards-compatible for stubs/mocks that accept only (cfg,)
                client = WazuhIndexerClient(cfg.wazuh)
            if not client.check_connection():
                logger.error("Failed to connect to Wazuh Indexer.")
                return 1

        logger.info("Fetching recent alerts...")
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=args.lookback_minutes)
        # In debug mode, ignore time range filter (use all test data)
        if args.debug:
            alerts = client.search_alerts(start, end, ignore_time_range=True)
        else:
            alerts = client.search_alerts(start, end)
        logger.info(f"Retrieved {len(alerts)} alerts.")

        logger.info("Building feature time series...")
        fb = WazuhFeatureBuilder(cfg.features)
        ts_data = fb.build_timeseries(alerts)

        # If there are not enough time points for reliable detection, optionally fill with synthetic alerts
        params = cfg.mvad.to_params()
        sliding_window = params.get("sliding_window", 0)
        required_points = sliding_window + 1 if sliding_window > 0 else 2

        if len(ts_data) < required_points:
            logger.warning(
                "Insufficient time points for detection (have=%d, need=%d).",
                len(ts_data),
                required_points,
            )
            if args.fill_with_synthetic:
                logger.info("Filling with synthetic alerts to reach required sample count...")
                to_add = required_points - len(ts_data)
                
                target_count = args.synthetic_count if args.synthetic_count is not None else to_add
                target_count = max(target_count, to_add)
                
                # Generate and index synthetic alerts using consolidated function
                synthetic_alerts = _generate_and_index_synthetic_alerts(
                    cfg=cfg,
                    fb=fb,
                    client=client,
                    alerts=alerts,
                    ts_data=ts_data,
                    target_count=target_count,
                    synthetic_mode=synthetic_mode,
                    synthetic_level=synthetic_level,
                    synthetic_srcip=synthetic_srcip,
                )
                
                alerts.extend(synthetic_alerts)
                ts_data = fb.build_timeseries(alerts)

                if len(ts_data) < required_points:
                    logger.warning("Not enough data after attempted fill; skipping detection.")
                    return 0
            else:
                logger.info("Use --fill-with-synthetic to auto-generate synthetic alerts.")
                return 0

        if ts_data.empty:
            logger.info("No valid time series data after attempted fill; nothing to detect.")
            return 0

        logger.info(f"Running detection on {len(ts_data)} time points...")
        results = engine.predict(ts_data)

        logger.info("Post-processing results...")
        post = MVADPostProcessor(cfg.features)
        anomaly_docs = post.build_wazuh_anomaly_docs(
            timestamps=ts_data.index.to_list(),
            results=results,
            context={
                "lookback_minutes": args.lookback_minutes,
                "alert_count": len(alerts),
            },
        )

        if anomaly_docs:
            logger.info(f"Found {len(anomaly_docs)} anomalies.")

            # Ship to data stream or use standard indexing
            if _should_ship(cfg, args):
                _ship_anomalies(cfg, client, anomaly_docs)
            else:
                # Standard anomaly indexing
                logger.info(f"Indexing {len(anomaly_docs)} anomalies to Wazuh...")
                for doc in anomaly_docs:
                    try:
                        doc_id = client.index_anomaly(doc)
                        logger.info(f"  Indexed anomaly: {doc_id}")
                    except Exception as e:
                        logger.warning(f"  Failed to index anomaly: {e}")
        else:
            logger.info("No anomalies detected.")

        logger.info("✓ Detection complete.")
        return 0

    except Exception as e:
        logger.exception("Detection failed.")
        return 1


def cmd_scenario(args: argparse.Namespace) -> int:
    """
    Execute a use-case scenario from a YAML file.

    Automatically executes training and/or detection based on what sections
    are present in the YAML file:
    - If both training and detection sections exist: execute both phases
    - If only training section exists: execute training only
    - If only detection section exists: execute detection only

    Detection mode (historical/realtime/batch) is only used if training is skipped.

    Args:
        args: Parsed CLI arguments with use_case path and mode override.

    Returns:
        0 on success, 1 on failure.
    """
    try:
        if not args.use_case:
            logger.error("--use-case argument required for scenario command")
            return 1

        logger.info("Loading use-case scenario from %s...", args.use_case)
        uc = UseCase.from_yaml(args.use_case)

        if not uc.enabled:
            logger.info("Use case '%s' is disabled; skipping.", uc.name)
            return 0

        logger.info("Use case: %s", uc.name)
        if uc.description:
            logger.info("  Description: %s", uc.description)

        # Load base config
        cfg = load_config(args.config)
        
        # Load scenario YAML again to extract debug/shipping sections
        # (These aren't part of UseCase dataclass yet)
        with open(args.use_case, 'r') as f:
            scenario_yaml = yaml.safe_load(f)
        
        # Apply debug configuration from scenario if present
        if "debug" in scenario_yaml:
            cfg.debug.__dict__.update(scenario_yaml["debug"])
            logger.debug(f"Applied debug config from scenario: {scenario_yaml['debug']}")
        
        # Apply shipping configuration from scenario if present
        if "shipping" in scenario_yaml:
            cfg.shipping.__dict__.update(scenario_yaml["shipping"])
            logger.debug(f"Applied shipping config from scenario: {scenario_yaml['shipping']}")

        # Set model path based on model_name
        if uc.model_name:
            # Use provided model name
            cfg.model_path = f"./sonar/models/{uc.model_name}.pkl"
            logger.info(f"Using model name from scenario: {uc.model_name}")
        else:
            # Generate unique model name from scenario name
            model_name = generate_model_name(uc.name)
            cfg.model_path = f"./sonar/models/{model_name}.pkl"
            logger.info(f"Generated model name: {model_name}")

        # Apply training scenario parameters (safe to do even if training is skipped)
        cfg.features.numeric_fields = uc.training.numeric_fields
        cfg.features.categorical_fields = uc.training.categorical_fields
        cfg.features.categorical_top_k = uc.training.categorical_top_k
        cfg.features.bucket_minutes = uc.training.bucket_minutes
        cfg.features.derived_features = uc.training.derived_features
        cfg.features.alert_filter = uc.training.alert_filter
        cfg.features.max_numeric_fields = uc.training.max_numeric_fields
        cfg.mvad.sliding_window = uc.training.sliding_window
        cfg.mvad.device = uc.training.device
        cfg.mvad.extra_params.update(uc.training.extra_params)

        # Determine what phases to execute based on YAML sections
        engine = None
        
        if uc.has_training:
            logger.info("Training section found in scenario; executing training phase...")
            logger.info("Phase 1: Training...")
            result = _execute_training_phase(cfg, uc.training, args)
            if result != 0:
                return result
            
            # Load the trained model for detection phase if needed
            if uc.has_detection:
                engine = MVADModelEngine(cfg)
                try:
                    engine.load()
                    logger.info("Trained model loaded for detection phase.")
                except FileNotFoundError:
                    logger.error("Failed to load trained model from %s", cfg.model_path)
                    return 1
        
        if uc.has_detection:
            logger.info("Detection section found in scenario; executing detection phase...")
            
            # Determine detection mode: CLI override > YAML config
            detection_mode = args.mode if args.mode else uc.detection.mode
            logger.info("Detection mode: %s", detection_mode)
            
            # If we didn't train in this run, load the pre-trained model
            if engine is None:
                logger.info("Phase 1: Loading trained model...")
                engine = MVADModelEngine(cfg)
                try:
                    engine.load()
                    logger.info("Model loaded successfully.")
                except FileNotFoundError:
                    logger.error("Model not found at %s. Please train first or add training section to YAML.", cfg.model_path)
                    return 1
            
            # Run detection
            if uc.has_training:
                # If we just trained, skip to detection (already loaded model)
                logger.info("Phase 2: Detection...")
            else:
                # If we only have detection, this is the only phase
                logger.info("Phase 1: Detection...")
            
            # Pass threshold/min_consecutive from detection scenario to args
            if not hasattr(args, 'threshold'):
                args.threshold = uc.detection.threshold
            if not hasattr(args, 'min_consecutive'):
                args.min_consecutive = uc.detection.min_consecutive
            
            result = _execute_detection_phase(
                cfg,
                uc.detection,
                args,
                engine=engine,
                mode=detection_mode,
            )
            return result
        
        # If only training was executed, success
        logger.info("Scenario execution completed successfully.")
        return 0

    except Exception as e:
        logger.exception("Scenario execution failed.")
        return 1


def _execute_training_phase(
    cfg: PipelineConfig, training: TrainingScenario, args: argparse.Namespace
) -> int:
    """Execute the training phase of a scenario."""
    try:
        # Check if debug mode is enabled
        if getattr(args, "debug", False):
            logger.info("🔧 DEBUG MODE ENABLED - Using local test data")
            try:
                data_file = cfg.debug.training_data_file
                logger.info(f"Using training data file: {data_file}")
                client = LocalDataProvider(cfg.debug.data_dir, data_file=data_file)
                logger.info(f"✓ Loaded local data from {cfg.debug.data_dir}/{data_file}")
                stats = client.get_stats()
                logger.info(f"  Data statistics: {stats}")
            except (FileNotFoundError, ValueError) as e:
                logger.error(f"Failed to load local data: {e}")
                return 1
        else:
            logger.info("Connecting to Wazuh Indexer...")
            try:
                client = WazuhIndexerClient(
                    cfg.wazuh,
                    print_payloads=getattr(args, "print_payloads", False),
                    dry_run=getattr(args, "dry_run", False),
                    payload_dir=getattr(args, "payload_dir", None),
                )
            except TypeError:
                client = WazuhIndexerClient(cfg.wazuh)

            if not client.check_connection():
                logger.error("Failed to connect to Wazuh Indexer.")
                return 1

        logger.info("Fetching %d hours of historical alerts...", training.lookback_hours)
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=training.lookback_hours)
        # In debug mode, ignore time range filter (use all test data)
        if isinstance(client, LocalDataProvider):
            alerts = client.search_alerts(start, end, ignore_time_range=True)
        else:
            alerts = client.search_alerts(start, end, query=cfg.features.alert_filter)
        logger.info("Retrieved %d alerts.", len(alerts))

        logger.info("Building feature time series...")
        fb = WazuhFeatureBuilder(cfg.features)
        ts_data = fb.build_timeseries(alerts)

        # Handle synthetic fill if needed
        params = cfg.mvad.to_params()
        sliding_window = params.get("sliding_window", 0)
        required_points = sliding_window + 1 if sliding_window > 0 else 2

        if len(ts_data) < required_points and training.fill_with_synthetic:
            logger.warning("Insufficient time points; filling with synthetic alerts...")
            to_add = required_points - len(ts_data)
            target_count = max(to_add, training.synthetic_count)
            
            # Generate and index synthetic alerts using consolidated function
            synthetic_alerts = _generate_and_index_synthetic_alerts(
                cfg=cfg,
                fb=fb,
                client=client,
                alerts=alerts,
                ts_data=ts_data,
                target_count=target_count,
                synthetic_mode=training.synthetic_mode,
                synthetic_level=training.synthetic_level,
                synthetic_srcip=training.synthetic_srcip,
            )
            
            alerts.extend(synthetic_alerts)
            ts_data = fb.build_timeseries(alerts)

        if ts_data.empty or len(ts_data) < required_points:
            logger.error("Insufficient training data even after synthetic fill.")
            return 1

        logger.info("Training MVAD model on %d time points...", len(ts_data))
        engine = MVADModelEngine(cfg)
        engine.train(ts_data)
        engine.save()
        logger.info("✓ Model trained and saved to %s", cfg.model_path)

        # If shipping is enabled, create the data stream template for future anomaly indexing
        if _should_ship(cfg, args):
            _create_scenario_stream(cfg, ts_data)

        return 0

    except Exception as e:
        logger.exception("Training phase failed.")
        return 1


def _execute_detection_phase(
    cfg: PipelineConfig,
    detection: DetectionScenario,
    args: argparse.Namespace,
    engine: MVADModelEngine = None,
    mode: str = None,
) -> int:
    """Execute the detection phase of a scenario."""
    try:
        if engine is None:
            engine = MVADModelEngine(cfg)
            engine.load()

        # Check if debug mode is enabled
        if getattr(args, "debug", False):
            logger.info("🔧 DEBUG MODE ENABLED - Using local test data")
            try:
                data_file = cfg.debug.detection_data_file
                logger.info(f"Using detection data file: {data_file}")
                client = LocalDataProvider(cfg.debug.data_dir, data_file=data_file)
                logger.info(f"✓ Loaded local data from {cfg.debug.data_dir}/{data_file}")
                stats = client.get_stats()
                logger.info(f"  Data statistics: {stats}")
            except (FileNotFoundError, ValueError) as e:
                logger.error(f"Failed to load local data: {e}")
                return 1
        else:
            try:
                client = WazuhIndexerClient(
                    cfg.wazuh,
                    print_payloads=detection.print_payloads or getattr(args, "print_payloads", False),
                    dry_run=detection.dry_run or getattr(args, "dry_run", False),
                    payload_dir=detection.payload_dir or getattr(args, "payload_dir", None),
                )
            except TypeError:
                client = WazuhIndexerClient(cfg.wazuh)

            if not client.check_connection():
                logger.error("Failed to connect to Wazuh Indexer.")
                return 1

        # Determine polling mode
        actual_mode = mode if mode else detection.mode
        logger.debug(f"Detection mode from parameter: {mode}, from scenario: {detection.mode}, actual: {actual_mode}")
        logger.debug(f"Detection lookback_minutes: {detection.lookback_minutes}")
        if actual_mode == "realtime":
            logger.info("Starting real-time detection loop. Press Ctrl+C to stop.")
            polling_interval = detection.polling_interval_seconds or (cfg.features.bucket_minutes * 60)
            try:
                while True:
                    if _run_single_detection(cfg, client, engine, detection.lookback_minutes, args):
                        logger.info("Sleeping for %d seconds...", polling_interval)
                        time.sleep(polling_interval)
                    else:
                        logger.error("Detection iteration failed; stopping.")
                        return 1
            except KeyboardInterrupt:
                logger.info("Real-time detection stopped by user.")
                return 0
        else:
            # 'historical' or 'batch' mode: single detection run
            logger.info("Running detection (mode: %s)...", actual_mode)
            return 0 if _run_single_detection(cfg, client, engine, detection.lookback_minutes, args) else 1

    except Exception as e:
        logger.exception("Detection phase failed.")
        return 1


def _run_single_detection(
    cfg: PipelineConfig,
    client: WazuhIndexerClient,
    engine: MVADModelEngine,
    lookback_minutes: int,
    args: argparse.Namespace,
) -> bool:
    """
    Execute a single detection iteration.

    Args:
        cfg: Pipeline configuration.
        client: Wazuh client or LocalDataProvider.
        engine: Trained MVAD model engine.
        lookback_minutes: Minutes of data to fetch.
        args: CLI arguments (for shipping config).

    Returns:
        True on success, False on failure.
    """
    try:
        logger.info("Fetching recent %d minutes of alerts...", lookback_minutes)
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=lookback_minutes)
        # In debug mode, ignore time range filter (use all test data)
        if isinstance(client, LocalDataProvider):
            alerts = client.search_alerts(start, end, ignore_time_range=True)
        else:
            alerts = client.search_alerts(start, end, query=cfg.features.alert_filter)
        logger.info("Retrieved %d alerts.", len(alerts))

        if not alerts:
            logger.info("No alerts to process.")
            return True

        logger.info("Building feature time series...")
        fb = WazuhFeatureBuilder(cfg.features)
        ts_data = fb.build_timeseries(alerts)

        if ts_data.empty:
            logger.info("No valid time series data.")
            return True

        logger.info(
            "Built time series: shape=%s, columns=%s, dtypes=%s",
            ts_data.shape,
            ts_data.columns.tolist(),
            ts_data.dtypes.to_dict()
        )

        # Check if we have enough data points for the model
        min_required = 200  # MVAD sliding window minimum
        if len(ts_data) < min_required:
            logger.warning(
                "Insufficient data for detection: %d time points (minimum: %d required).",
                len(ts_data),
                min_required
            )
            logger.warning(
                "Recommendations: (1) Increase lookback_minutes to %d+ minutes, " 
                "(2) Decrease bucket_minutes, or (3) Wait for more alerts to accumulate.",
                min_required * cfg.features.bucket_minutes
            )
            logger.info("Skipping detection for this iteration.")
            return True

        logger.info("Running detection on %d time points...", len(ts_data))
        results = engine.predict(ts_data)

        logger.info("Post-processing results...")
        post = MVADPostProcessor(cfg.features)
        anomaly_docs = post.build_wazuh_anomaly_docs(
            timestamps=ts_data.index.to_list(),
            results=results,
            context={
                "lookback_minutes": lookback_minutes,
                "alert_count": len(alerts),
                "scenario_id": _get_scenario_id(cfg),
                "model_path": cfg.model_path,
                "training_samples": getattr(engine, '_training_samples', 0),
                "sliding_window": cfg.mvad.sliding_window,
                "bucket_minutes": cfg.features.bucket_minutes,
            },
            threshold=getattr(args, 'threshold', 0.85),
        )

        if anomaly_docs:
            logger.info("Found %d anomalies.", len(anomaly_docs))

            # Ship to data stream or use standard indexing
            if _should_ship(cfg, args):
                _ship_anomalies(cfg, client, anomaly_docs)
            else:
                # Standard anomaly indexing
                logger.info("Indexing %d anomalies...", len(anomaly_docs))
                for doc in anomaly_docs:
                    try:
                        doc_id = client.index_anomaly(doc)
                        logger.info("  Indexed anomaly: %s", doc_id)
                    except Exception as e:
                        logger.warning("  Failed to index anomaly: %s", e)
        else:
            logger.info("No anomalies detected.")

        return True

    except ValueError as e:
        logger.error("Validation error during detection: %s", e)
        logger.error("This may indicate incompatible data between training and detection.")
        return False
    except RuntimeError as e:
        logger.error("Runtime error during detection: %s", e)
        return False
    except Exception as e:
        logger.exception("Single detection iteration failed with unexpected error.")
        return False


def cmd_check(args: argparse.Namespace) -> int:
    """
    Check connection to Wazuh Indexer.

    Args:
        args: Parsed CLI arguments.

    Returns:
        0 if connected, 1 otherwise.
    """
    try:
        logger.info("Loading configuration...")
        cfg = load_config(args.config if hasattr(args, "config") else None)

        logger.info("Checking connection to Wazuh Indexer...")
        client = WazuhIndexerClient(cfg.wazuh)
        if client.check_connection():
            logger.info("✓ Connection successful.")
            return 0
        else:
            logger.error("✗ Connection failed.")
            return 1

    except Exception as e:
        logger.exception("Check failed.")
        return 1


def main():
    """Parse arguments and dispatch to subcommands."""
    parser = argparse.ArgumentParser(
        description="SONAR: SIEM-Oriented Neural Anomaly Recognition for Wazuh."
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand")

    # Train subcommand
    train_parser = subparsers.add_parser("train", help="Train multivariate anomaly detection model")
    train_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config YAML (optional; uses defaults if omitted)",
    )
    train_parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Path to scenario YAML file (alternative to --config; training section will be used)",
    )
    train_parser.add_argument(
        "--model-name",
        type=str,
        default=None,
        help="Model name for saving trained model (auto-generated if not provided)",
    )
    train_parser.add_argument(
        "--lookback-hours",
        type=int,
        default=24,
        help="Hours of historical data to train on (default: 24)",
    )
    train_parser.add_argument(
        "--fill-with-synthetic",
        action="store_true",
        help=(
            "If training data is insufficient, generate synthetic alerts and "
            "index them into Wazuh to pad the dataset (uses timezone UTC)."
        ),
    )
    train_parser.add_argument(
        "--synthetic-count",
        type=int,
        default=None,
        help=(
            "Number of synthetic alerts to create when filling (default: minimal required)"
        ),
    )
    train_parser.add_argument(
        "--synthetic-mode",
        type=str,
        default="constant",
        choices=["constant", "random", "copy"],
        help=("Mode for synthetic alert content: constant, random, or copy"),
    )
    train_parser.add_argument(
        "--synthetic-level",
        type=float,
        default=None,
        help="Numeric level to use for synthetic alerts when mode=constant",
    )
    train_parser.add_argument(
        "--synthetic-srcip",
        type=str,
        default=None,
        help="Source IP to use for synthetic alerts when mode=constant",
    )
    train_parser.add_argument(
        "--print-payloads",
        action="store_true",
        help="Print JSON payloads (and save) for synthetic alerts/anomalies instead of or before sending",
    )
    train_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not send requests to Wazuh/OpenSearch; save payloads to disk instead",
    )
    train_parser.add_argument(
        "--payload-dir",
        type=str,
        default="./payloads",
        help="Directory to save payloads when --dry-run or --print-payloads is used",
    )
    train_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode: use local test data from test_data/synthetic_alerts/ folder instead of connecting to Wazuh",
    )
    train_parser.add_argument(
        "--ship",
        action="store_true",
        help="Enable data shipping: create scenario data stream in Wazuh for future anomaly results",
    )
    train_parser.set_defaults(func=cmd_train)

    # Detect subcommand
    detect_parser = subparsers.add_parser("detect", help="Run anomaly detection")
    detect_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config YAML (optional; uses defaults if omitted)",
    )
    detect_parser.add_argument(
        "--scenario",
        type=str,
        default=None,
        help="Path to scenario YAML file (alternative to --config; detection section will be used)",
    )
    detect_parser.add_argument(
        "--lookback-minutes",
        type=int,
        default=10,
        help="Minutes of recent data to detect on (default: 10)",
    )
    detect_parser.add_argument(
        "--fill-with-synthetic",
        action="store_true",
        help=(
            "If recent data is insufficient for detection, generate synthetic alerts and "
            "index them into Wazuh to pad the dataset (uses timezone UTC)."
        ),
    )
    detect_parser.add_argument(
        "--synthetic-count",
        type=int,
        default=None,
        help=(
            "Number of synthetic alerts to create when filling (default: minimal required)"
        ),
    )
    detect_parser.add_argument(
        "--synthetic-mode",
        type=str,
        default="constant",
        choices=["constant", "random", "copy"],
        help=("Mode for synthetic alert content: constant, random, or copy"),
    )
    detect_parser.add_argument(
        "--synthetic-level",
        type=float,
        default=None,
        help="Numeric level to use for synthetic alerts when mode=constant",
    )
    detect_parser.add_argument(
        "--synthetic-srcip",
        type=str,
        default=None,
        help="Source IP to use for synthetic alerts when mode=constant",
    )
    detect_parser.add_argument(
        "--print-payloads",
        action="store_true",
        help="Print JSON payloads (and save) for synthetic alerts/anomalies instead of or before sending",
    )
    detect_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not send requests to Wazuh/OpenSearch; save payloads to disk instead",
    )
    detect_parser.add_argument(
        "--payload-dir",
        type=str,
        default="./payloads",
        help="Directory to save payloads when --dry-run or --print-payloads is used",
    )
    detect_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode: use local test data from test_data/synthetic_alerts/ folder instead of connecting to Wazuh",
    )
    detect_parser.add_argument(
        "--ship",
        action="store_true",
        help="Enable data shipping: ship detected anomalies to Wazuh data stream",
    )
    detect_parser.set_defaults(func=cmd_detect)

    # Scenario subcommand (new)
    scenario_parser = subparsers.add_parser(
        "scenario",
        help="Execute a use-case scenario from a YAML file",
    )
    scenario_parser.add_argument(
        "--use-case",
        type=str,
        required=True,
        help="Path to use-case YAML file defining training and detection config",
    )
    scenario_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to base config YAML (optional; use-case overrides)",
    )
    scenario_parser.add_argument(
        "--mode",
        type=str,
        choices=["historical", "realtime", "batch"],
        default=None,
        help="Override detection mode from use-case YAML (historical|realtime|batch)",
    )
    scenario_parser.add_argument(
        "--print-payloads",
        action="store_true",
        help="Print JSON payloads before sending",
    )
    scenario_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not send to Wazuh; save payloads instead",
    )
    scenario_parser.add_argument(
        "--payload-dir",
        type=str,
        default="./payloads",
        help="Directory for saved payloads",
    )
    scenario_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode: use local test data from test_data/synthetic_alerts/ folder instead of connecting to Wazuh",
    )
    scenario_parser.add_argument(
        "--ship",
        action="store_true",
        help="Enable data shipping: ship anomaly results to Wazuh data stream when detection is run",
    )
    scenario_parser.set_defaults(func=cmd_scenario)

    # Check subcommand
    check_parser = subparsers.add_parser(
        "check", help="Check Wazuh Indexer connection"
    )
    check_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config YAML (optional)",
    )
    check_parser.set_defaults(func=cmd_check)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
