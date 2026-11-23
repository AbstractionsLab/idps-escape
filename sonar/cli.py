"""
CLI entry point for SONAR (SIEM-Oriented Neural Anomaly Recognition).

Usage:
    sonar train [--config CONFIG_YAML] [--lookback-hours HOURS]
    sonar detect [--config CONFIG_YAML] [--lookback-minutes MINUTES] [--mode MODE]
    sonar scenario [--use-case YAML_FILE]
    sonar evaluate --scenario YAML --train-file F --test-file F --test-labels F
    sonar export --scenario YAML --start T --end T --output-dir DIR [--radar-results INDEX] [--event TYPE,START,END]
    sonar check                     # Check Wazuh connection
"""

import argparse
import dataclasses
import getpass
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pandas as pd
import yaml

from sonar import __version__ as SONAR_VERSION
from sonar.config import FeatureConfig, OutputConfig, PipelineConfig
from sonar.engine import IncompatibleModelError, MVADModelEngine
from sonar.evaluation import LABELS_FORMAT, REPORT_FORMAT, Labels, calibrate, detections_from_points, load_external_detections, render_markdown, score
from sonar.features import WazuhFeatureBuilder
from sonar.local_data_provider import LocalDataProvider
from sonar.paths import file_dir, packaged_scenario, resolve, slug, sonar_home
from sonar.pipeline import MVADPostProcessor
from sonar.scenario import DetectionScenario, UseCase
from sonar.sinks import FALLBACK_NAMES, SINK_NAMES, deliver
from sonar.sinks.events import DEFAULT_ANOMALY_CONFIDENCE
from sonar.sinks.indexer import DataStreamSink, IndexSink
from sonar.sinks.local import JsonlSink, StdoutSink
from sonar.sinks.wazuh import ADMIN_PASSWORD_ENV, PASSWORD_ENV, RULES_FILE, WazuhApi, WazuhApiError, WazuhSink
from sonar.training_plan import InsufficientTrainingDataError
from sonar.watermark import Watermark
from sonar.wazuh_client import WazuhIndexerClient

# Default lookbacks when neither a scenario nor the command line sets one.
DEFAULT_TRAIN_LOOKBACK_HOURS = 168  # the default config needs about 3.5 days of 5-minute buckets
DEFAULT_DETECT_LOOKBACK_MINUTES = 10

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# --- Shipping Helper Functions ---


def _get_scenario_id(cfg: PipelineConfig) -> str:
    """
    The scenario ID: names the data stream, the watermark file and each anomaly's ``anomaly_id``.

    ``shipping.scenario_id`` if set, otherwise the model name (lower case, safe for index names).
    """
    if cfg.shipping.scenario_id:
        return cfg.shipping.scenario_id
    return slug(cfg.model_name)


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


def _create_scenario_stream(cfg: PipelineConfig, scenario_name: str = None) -> None:
    """
    Prepare the scenario's data stream after training: index templates and the ISM policy.

    Args:
        cfg: Pipeline configuration.
        scenario_name: Optional custom scenario name.
    """
    try:
        from sonar.shipper.wazuh_data_shipper import WazuhDataShipper

        logger.info("Initializing data shipper for stream creation...")
        shipper = WazuhDataShipper(
            cfg.wazuh,
            install=cfg.shipping.install_templates,
            rollover_days=cfg.shipping.rollover_days,
            retention_days=cfg.shipping.retention_days,
        )
        scenario_id = _get_scenario_id(cfg)
        stream_name = shipper.create_scenario_stream(scenario_id, scenario_name or f"sonar_scenario_{scenario_id}")
        logger.info("✓ Data stream ready: %s", stream_name)
    except Exception as e:
        logger.error("Failed to set up the anomaly data stream: %s", e)
        logger.warning("Training completed but the data stream setup failed")


# --- Paths ---


def _scenario_file(path: str) -> str:
    """``path`` if it exists, else the packaged example scenario of that name (e.g. ``linux_resource_monitoring``)."""
    if path and not Path(path).exists():
        packaged_path = packaged_scenario(path)
        if packaged_path is not None:
            logger.info("Using the packaged example scenario %s", packaged_path)
            return str(packaged_path)
    return path


def _resolve_file_paths(cfg: PipelineConfig, raw: Dict[str, Any], source: str) -> None:
    """
    Make the paths set in a configuration or scenario file absolute, relative to that file.

    Args:
        cfg: Configuration the file's values were already copied into.
        raw: The file's YAML.
        source: The file.
    """
    base = file_dir(source)
    if raw.get("models_dir"):
        cfg.models_dir = resolve(raw["models_dir"], base)
    if raw.get("model_path"):
        logger.warning("%s: model_path is deprecated; use models_dir and model_name.", source)
        cfg.model_path = resolve(raw["model_path"], base)
    if (raw.get("debug") or {}).get("data_dir"):
        cfg.debug.data_dir = resolve(raw["debug"]["data_dir"], base)
    output = raw.get("output") or {}
    for key in ("state_dir", "jsonl_path"):
        if output.get(key):
            setattr(cfg.output, key, resolve(output[key], base))
    if (output.get("wazuh") or {}).get("file_path"):
        cfg.output.wazuh.file_path = resolve(output["wazuh"]["file_path"], base)


# --- Configuration Loading ---


def _update_section(target: Any, values: Dict[str, Any], source: str, section: str) -> None:
    """
    Copy YAML values onto a config dataclass, warning about keys it does not define.

    Args:
        target: Config dataclass instance (e.g. ``cfg.wazuh``).
        values: Mapping read from YAML.
        source: File the values come from (for the warning).
        section: Section name (for the warning).
    """
    known = set(getattr(target, "__dataclass_fields__", {}))
    for key, value in (values or {}).items():
        if key not in known:
            logger.warning("%s: unknown key '%s' in %s section is ignored", source, key, section)
        elif dataclasses.is_dataclass(getattr(target, key)) and isinstance(value, dict):
            _update_section(getattr(target, key), value, source, f"{section}.{key}")
        else:
            setattr(target, key, value)


def apply_scenario_to_config(cfg: PipelineConfig, uc: UseCase, scenario_yaml: dict, source: Optional[str] = None) -> None:
    """
    Apply a use-case scenario on top of a base configuration, in place.

    Single place where scenario keys reach the PipelineConfig, so that
    ``sonar scenario``, ``sonar train --scenario`` and ``sonar detect --scenario``
    all honour the same keys.

    Args:
        cfg: Base configuration (from ``load_config``), modified in place.
        uc: Parsed use case.
        scenario_yaml: Raw scenario YAML (for the wazuh/debug/shipping/output sections).
        source: The scenario file; relative paths in it are relative to it.
    """
    for section in ("wazuh", "debug", "shipping", "output"):
        if scenario_yaml.get(section):
            _update_section(getattr(cfg, section), scenario_yaml[section], "scenario", section)

    if source:
        _resolve_file_paths(cfg, scenario_yaml, source)
        if uc.detection.payload_dir:
            uc.detection.payload_dir = resolve(uc.detection.payload_dir, file_dir(source))
    # Without model_name, the scenario's name: train and detect find the same model.
    cfg.model_name = uc.model_name or slug(uc.name)
    logger.info("Model: %s", cfg.model_path)

    # Feature and window settings live under training: and are reused for detection,
    # so that detection builds the same columns the model was trained on.
    cfg.features.numeric_fields = uc.training.numeric_fields
    cfg.features.categorical_fields = uc.training.categorical_fields
    cfg.features.categorical_top_k = uc.training.categorical_top_k
    cfg.features.bucket_minutes = uc.training.bucket_minutes
    cfg.features.derived_features = uc.training.derived_features
    cfg.features.alert_filter = uc.training.alert_filter
    cfg.features.max_numeric_fields = uc.training.max_numeric_fields
    cfg.features.numeric_fill = uc.training.numeric_fill
    cfg.features.count_transform = uc.training.count_transform
    cfg.mvad.sliding_window = uc.training.sliding_window
    cfg.mvad.device = uc.training.device
    cfg.mvad.extra_params.update(uc.training.extra_params)
    cfg.mvad.min_gradient_steps = uc.training.min_gradient_steps
    if uc.training.backend:
        cfg.backend = uc.training.backend
    _update_section(cfg.ewma, uc.training.ewma, "scenario", "training.ewma")
    _update_section(cfg.pca, uc.training.pca, "scenario", "training.pca")


# The field that names a host in Wazuh alerts and archived events (RADAR's category_field).
AGENT_FIELD = "agent.name"


def apply_agent(cfg: PipelineConfig, agent: Optional[str]) -> None:
    """
    Restrict a configuration to one agent (``--agent``), in place: one model per host.

    The ``agent.name`` term joins ``alert_filter``, so the model stores it and detection with the
    same model reads the same host. The model name and an explicit ``shipping.scenario_id`` get
    the agent as suffix, so each host has its own model, watermarks, data stream and anomaly IDs.
    Call it after the scenario and any ``--model-name`` are applied, the same way in every command.
    """
    if not agent:
        return
    cfg.agent = agent
    term = {"term": {AGENT_FIELD: agent}}
    current = cfg.features.alert_filter
    cfg.features.alert_filter = {"bool": {"filter": [current, term]}} if current else term
    cfg.model_name = f"{cfg.model_name}-{slug(agent)}"
    if cfg.shipping.scenario_id:
        cfg.shipping.scenario_id = f"{cfg.shipping.scenario_id}-{slug(agent)}"
    logger.info("Agent %s only: model %s", agent, cfg.model_path)


def _of_agent(alerts: list, agent: Optional[str]) -> list:
    """The alerts of ``agent`` (all of them without one): local files are not filtered by ``alert_filter``."""
    if not agent:
        return alerts
    return [a for a in alerts if (a.get("agent") or {}).get("name") == agent]


def _normalised(value: Any) -> Any:
    """Tuples become lists recursively, so configs from YAML and from a model compare equal."""
    if isinstance(value, dict):
        return {k: _normalised(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalised(v) for v in value]
    return value


def _adopt_model_features(cfg: PipelineConfig, engine: MVADModelEngine) -> None:
    """
    Make detection use the feature settings the model was trained with.

    The model stores its FeatureConfig and categorical vocabulary; building detection
    features from anything else would give different columns. If the scenario's training:
    section has changed since, warn and keep the model's settings.
    """
    stored = engine.feature_config
    if not isinstance(stored, FeatureConfig):
        return
    current, trained = _normalised(dataclasses.asdict(cfg.features)), _normalised(dataclasses.asdict(stored))
    changed = sorted(k for k in trained if current.get(k) != trained.get(k))
    if changed:
        logger.warning(
            "Feature settings %s differ from those model %s was trained with; detection uses the model's. Retrain to apply the new settings.",
            changed,
            cfg.model_path,
        )
    cfg.features = stored


def _detection_features(cfg: PipelineConfig, engine: MVADModelEngine, alerts: list, start: datetime, end: datetime, debug: bool):
    """Feature matrix for detection: the model's vocabulary, on the full requested window."""
    fb = WazuhFeatureBuilder(cfg.features, vocabulary=engine.vocabulary)
    if debug:  # local data ignores the time range
        return fb, fb.build_timeseries(alerts)
    return fb, fb.build_timeseries(alerts, start=start, end=end)


def _search_alerts(client, start: datetime, end: datetime, cfg: PipelineConfig, debug: bool) -> list:
    """
    Fetch alerts, applying the configured alert_filter (ignored by local debug data).

    From the indexer, only the fields the features read are requested.
    """
    if debug:
        return _of_agent(client.search_alerts(start, end, ignore_time_range=True), cfg.agent)
    source_fields = WazuhFeatureBuilder(cfg.features).required_source_fields()
    return client.search_alerts(start, end, query=getattr(cfg.features, "alert_filter", None) or None, source_fields=source_fields)


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
    if phase not in ("training", "detection"):
        raise ValueError(f"Unknown phase: {phase}")

    scenario_path = _scenario_file(scenario_path)
    uc = UseCase.from_yaml(scenario_path)
    cfg = load_config(base_config_path)
    with open(scenario_path, "r") as f:
        scenario_yaml = yaml.safe_load(f) or {}
    apply_scenario_to_config(cfg, uc, scenario_yaml, source=scenario_path)

    return (cfg, uc.training) if phase == "training" else (cfg, uc.detection)


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
        raw = yaml.safe_load(f) or {}

    # Create base config
    cfg = PipelineConfig()

    # Update each section if present in YAML
    if "wazuh" in raw:
        _update_section(cfg.wazuh, raw["wazuh"], config_path, "wazuh")
    if "mvad" in raw:
        _update_section(cfg.mvad, raw["mvad"], config_path, "mvad")
    if "features" in raw:
        # Handle both lists and tuples for sequence fields
        features_data = raw["features"]
        if features_data.get("numeric_fields") is not None:
            cfg.features.numeric_fields = tuple(features_data["numeric_fields"])
        if "categorical_fields" in features_data:
            cfg.features.categorical_fields = tuple(features_data["categorical_fields"] or ())
        if "categorical_top_k" in features_data:
            cfg.features.categorical_top_k = features_data["categorical_top_k"]
        if "bucket_minutes" in features_data:
            cfg.features.bucket_minutes = features_data["bucket_minutes"]
        if "derived_features" in features_data:
            cfg.features.derived_features = features_data["derived_features"]
        if "alert_filter" in features_data:
            cfg.features.alert_filter = features_data["alert_filter"]
        if "max_numeric_fields" in features_data:
            cfg.features.max_numeric_fields = tuple(features_data["max_numeric_fields"] or ())
        for key in ("numeric_fill", "count_transform"):
            if features_data.get(key) is not None:
                setattr(cfg.features, key, features_data[key])
        known = getattr(cfg.features, "__dataclass_fields__", None)
        for key in sorted(set(features_data) - set(known or features_data)):
            logger.warning("%s: unknown key '%s' in features section is ignored", config_path, key)
    if "debug" in raw:
        _update_section(cfg.debug, raw["debug"], config_path, "debug")
    if "shipping" in raw:
        _update_section(cfg.shipping, raw["shipping"], config_path, "shipping")
    if "output" in raw:
        _update_section(cfg.output, raw["output"], config_path, "output")
    if "ewma" in raw:
        _update_section(cfg.ewma, raw["ewma"], config_path, "ewma")
    if "pca" in raw:
        _update_section(cfg.pca, raw["pca"], config_path, "pca")
    if raw.get("backend"):
        cfg.backend = raw["backend"]
    if raw.get("model_name"):
        cfg.model_name = raw["model_name"]
    _resolve_file_paths(cfg, raw, config_path)

    return cfg


# --- Exit codes ---

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_ENOUGH_DATA = 2  # one-shot detection: too little data, nothing was scored

# First wait after a failed realtime poll; it doubles per failure, up to one bucket.
RETRY_BASE_SECONDS = 10


# --- Shared steps ---


def _open_data_source(cfg: PipelineConfig, args: argparse.Namespace, data_file: str, detection: Optional[DetectionScenario] = None):
    """
    Open the alert source: local test data with --debug, else a connected Wazuh Indexer client.

    Args:
        cfg: Pipeline configuration.
        args: CLI arguments (debug, print_payloads, dry_run, payload_dir).
        data_file: Local data file to load in debug mode.
        detection: Detection settings, whose payload options add to the CLI flags.

    Returns:
        LocalDataProvider or WazuhIndexerClient, or None if it could not be opened.
    """
    if getattr(args, "debug", False):
        logger.info("🔧 DEBUG MODE ENABLED - Using local test data")
        try:
            client = LocalDataProvider(cfg.debug.data_dir, data_file=data_file)
        except (FileNotFoundError, ValueError) as e:
            logger.error("Failed to load local data: %s", e)
            return None
        logger.info("✓ Loaded local data from %s/%s: %s", cfg.debug.data_dir, data_file, client.get_stats())
        return client

    logger.info("Connecting to Wazuh Indexer...")
    client = WazuhIndexerClient(
        cfg.wazuh,
        print_payloads=bool(getattr(args, "print_payloads", False) or (detection and detection.print_payloads)),
        dry_run=bool(getattr(args, "dry_run", False) or (detection and detection.dry_run)),
        payload_dir=getattr(args, "payload_dir", None) or (detection.payload_dir if detection else None),
    )
    if not client.check_connection():
        logger.error("Failed to connect to Wazuh Indexer.")
        return None
    return client


def _load_engine(cfg: PipelineConfig) -> Optional[MVADModelEngine]:
    """Load the trained model; None (with the reason logged) if it is missing or incompatible."""
    engine = MVADModelEngine(cfg)
    try:
        engine.load()
    except FileNotFoundError:
        logger.error("Model not found at %s. Train first, or add a training section to the scenario.", cfg.model_path)
        return None
    except IncompatibleModelError as e:
        logger.error("%s", e)
        return None
    return engine


def _floor_time(value: datetime, step: timedelta) -> datetime:
    """Round down to a multiple of `step` since the Unix epoch (the feature builder's bucket boundaries)."""
    seconds = step.total_seconds()
    return datetime.fromtimestamp((value.timestamp() // seconds) * seconds, tz=timezone.utc)


def _scoring_window(
    cfg: PipelineConfig,
    engine: MVADModelEngine,
    lookback_minutes: int,
    now: Optional[datetime] = None,
    ingest_delay_seconds: int = 0,
) -> Tuple[datetime, datetime, datetime]:
    """
    Time range for one detection run.

    The scored window holds the complete buckets of the last ``lookback_minutes``: it ends at
    the start of the bucket that is still filling, or that ended less than
    ``ingest_delay_seconds`` ago (alerts reach the indexer with a delay). MVAD needs
    ``engine.context_buckets`` buckets before the first bucket it scores, so they are
    fetched as well.

    Returns:
        ``(fetch_start, score_start, end)``.
    """
    bucket = timedelta(minutes=int(cfg.features.bucket_minutes))
    end = _floor_time((now or datetime.now(timezone.utc)) - timedelta(seconds=ingest_delay_seconds), bucket)
    score_start = _floor_time(end - timedelta(minutes=lookback_minutes), bucket)
    if score_start >= end:
        score_start = end - bucket
    return score_start - engine.context_buckets * bucket, score_start, end


def _state_dir(cfg: PipelineConfig) -> str:
    """Directory of the delivery watermarks: output.state_dir, else state/ next to the model."""
    return cfg.output.state_dir or str(Path(cfg.model_path).parent / "state")


@dataclasses.dataclass
class _Delivery:
    """Where a detection phase delivers its anomalies; built once, reused by every poll."""

    sinks: list
    fallback: Any = None
    watermark: Optional[Watermark] = None


def _make_sink(name: str, cfg: PipelineConfig, client, jsonl_path: Optional[str] = None):
    """One sink by its configuration name."""
    bands = (cfg.output.wazuh.severity_medium, cfg.output.wazuh.severity_high)
    if name == "wazuh":
        return WazuhSink(cfg.output.wazuh)
    if name == "datastream":
        return DataStreamSink(cfg.wazuh, cfg.shipping, _get_scenario_id(cfg))
    if name == "index":
        if not hasattr(client, "index_anomaly"):
            raise ValueError("the 'index' sink needs the Wazuh Indexer; it is not available with --debug")
        return IndexSink(client)
    if name == "jsonl":
        return JsonlSink(jsonl_path or cfg.output.jsonl_path or str(sonar_home() / "anomalies.jsonl"), *bands)
    if name == "stdout":
        return StdoutSink(*bands)
    raise ValueError(f"unknown sink '{name}'; choose from {', '.join(SINK_NAMES)}")


def _build_delivery(cfg: PipelineConfig, client, args: argparse.Namespace, detection: Optional[DetectionScenario] = None) -> _Delivery:
    """
    The sinks of this detection phase.

    - ``--debug`` (or ``debug.enabled``): ``output.debug_sinks`` (stdout by default), no watermark.
    - ``--dry-run``: a JSON-lines file in the payload directory instead of the sinks, no watermark.
    - Otherwise ``output.sinks`` (plus ``datastream`` with ``--ship`` or ``shipping.enabled``),
      ``output.fallback``, and the scenario's watermarks.

    ``--print-payloads`` adds stdout.

    Raises:
        ValueError: On an unknown sink, fallback or transport.
    """
    out = cfg.output
    debug = isinstance(client, LocalDataProvider) or cfg.debug.enabled
    dry_run = bool(getattr(args, "dry_run", False) or (detection and detection.dry_run))
    print_payloads = bool(getattr(args, "print_payloads", False) or (detection and detection.print_payloads))
    jsonl_path = None
    if debug:
        names = list(out.debug_sinks)
    elif dry_run:
        # The command line wins over the scenario, as for every other option.
        payload_dir = getattr(args, "payload_dir", None) or (detection.payload_dir if detection else None) or str(sonar_home() / "payloads")
        jsonl_path = str(Path(payload_dir) / "anomalies.jsonl")
        names = ["jsonl"]
        logger.info("Dry run: anomalies go to %s only; the delivery watermark is not used.", jsonl_path)
    else:
        names = list(out.sinks)
        if _should_ship(cfg, args) and "datastream" not in names:
            names.append("datastream")
    if print_payloads and "stdout" not in names:
        names.append("stdout")
    sinks = [_make_sink(n, cfg, client, jsonl_path) for n in dict.fromkeys(names)]

    if out.fallback not in FALLBACK_NAMES:
        raise ValueError(f"output.fallback must be one of {', '.join(FALLBACK_NAMES)}; got '{out.fallback}'")
    real = not (debug or dry_run)
    fallback = _make_sink(out.fallback, cfg, client) if real and out.fallback != "none" else None
    watermark = Watermark(_state_dir(cfg), _get_scenario_id(cfg)) if real else None
    if any(sink.name == "wazuh" for sink in sinks) and (detection is None or detection.anomaly_confidence is None):
        logger.warning(
            "detection.anomaly_confidence is not set: Wazuh events carry anomaly_confidence %.1f, which is not a measured value. Set it to the scenario's precision.",
            DEFAULT_ANOMALY_CONFIDENCE,
        )
    logger.info("Anomaly sinks: %s%s", ", ".join(sink.name for sink in sinks) or "none", f" (fallback {fallback.name})" if fallback else "")
    return _Delivery(sinks, fallback, watermark)


def _validate_output(cfg: PipelineConfig) -> None:
    """
    Check sink, fallback and transport names before any work, so a typo does not surface after training.

    Raises:
        ValueError: On an unknown name.
    """
    out = cfg.output
    if not isinstance(out, OutputConfig):
        return
    for name in [*out.sinks, *out.debug_sinks]:
        if name not in SINK_NAMES:
            raise ValueError(f"unknown sink '{name}' in output; choose from {', '.join(SINK_NAMES)}")
    if out.fallback not in FALLBACK_NAMES:
        raise ValueError(f"output.fallback must be one of {', '.join(FALLBACK_NAMES)}; got '{out.fallback}'")
    if out.wazuh.transport not in ("file", "api"):
        raise ValueError(f"output.wazuh.transport must be 'file' or 'api'; got '{out.wazuh.transport}'")


# --- Training ---


def cmd_train(args: argparse.Namespace) -> int:
    """
    Train MVAD model on historical Wazuh data.

    Args:
        args: Parsed CLI arguments with config, scenario, model_name, lookback_hours.

    Returns:
        0 on success, 1 on failure.
    """
    try:
        if getattr(args, "scenario", None):
            logger.info("Loading configuration from scenario file: %s", args.scenario)
            cfg, training = load_scenario_for_phase(args.scenario, "training", args.config)
            default_lookback = training.lookback_hours
        else:
            logger.info("Loading configuration...")
            cfg = load_config(args.config)
            default_lookback = DEFAULT_TRAIN_LOOKBACK_HOURS

        if getattr(args, "model_name", None):
            cfg.model_name = args.model_name
            logger.info("Using model name from the command line: %s", args.model_name)
        apply_agent(cfg, getattr(args, "agent", None))

        lookback_hours = args.lookback_hours if args.lookback_hours is not None else default_lookback
        return _execute_training_phase(cfg, lookback_hours, args)
    except Exception:
        logger.exception("Training failed.")
        return EXIT_ERROR


def _execute_training_phase(cfg: PipelineConfig, lookback_hours: int, args: argparse.Namespace) -> int:
    """
    Fetch history, build features, train and save the model (every training path).

    Returns:
        0 on success, 1 on failure (including too little data).
    """
    try:
        client = _open_data_source(cfg, args, cfg.debug.training_data_file)
        if client is None:
            return EXIT_ERROR
        debug = isinstance(client, LocalDataProvider)

        logger.info("Fetching %d hours of historical alerts...", lookback_hours)
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=lookback_hours)
        alerts = _search_alerts(client, start, end, cfg, debug=debug)
        logger.info("Retrieved %d alerts.", len(alerts))

        logger.info("Building feature time series...")
        fb = WazuhFeatureBuilder(cfg.features)
        # The grid starts at the first alert (history before it is not learned as silence)
        # and ends at the end of the training window (trailing silence is real data).
        ts_data = fb.build_timeseries(alerts, end=None if debug else end)
        if ts_data.empty:
            logger.error("No alerts with a valid timestamp in the training window; nothing to train on.")
            return EXIT_ERROR

        logger.debug("Training data summary:\n%s", ts_data.describe())
        engine = MVADModelEngine(cfg)
        try:
            engine.train(ts_data, vocabulary=fb.vocabulary)
        except InsufficientTrainingDataError as e:
            logger.error("%s", e)
            return EXIT_ERROR
        engine.save()
        logger.info("✓ Model trained and saved to %s", cfg.model_path)

        # If shipping is enabled, create the data stream template for future anomaly indexing
        if not (debug or cfg.debug.enabled) and (_should_ship(cfg, args) or "datastream" in cfg.output.sinks):
            _create_scenario_stream(cfg)
        return EXIT_OK
    except Exception:
        logger.exception("Training phase failed.")
        return EXIT_ERROR


# --- Detection ---


def cmd_detect(args: argparse.Namespace) -> int:
    """
    Run anomaly detection once on recent Wazuh data.

    Args:
        args: Parsed CLI arguments with config, scenario, lookback_minutes.

    Returns:
        0 if the window was scored, 2 if there was too little data to score it, 1 on error.
    """
    try:
        if getattr(args, "scenario", None):
            logger.info("Loading configuration from scenario file: %s", args.scenario)
            cfg, detection = load_scenario_for_phase(args.scenario, "detection", args.config)
        else:
            logger.info("Loading configuration...")
            cfg = load_config(args.config)
            detection = DetectionScenario(lookback_minutes=DEFAULT_DETECT_LOOKBACK_MINUTES)
        apply_agent(cfg, getattr(args, "agent", None))
        if args.lookback_minutes is not None:
            detection.lookback_minutes = args.lookback_minutes
        logger.info("Detection settings: %s", detection)

        engine = _load_engine(cfg)
        if engine is None:
            return EXIT_ERROR
        client = _open_data_source(cfg, args, cfg.debug.detection_data_file, detection)
        if client is None:
            return EXIT_ERROR
        return _run_single_detection(cfg, client, engine, detection, args, delivery=_build_delivery(cfg, client, args, detection))
    except Exception:
        logger.exception("Detection failed.")
        return EXIT_ERROR


def cmd_scenario(args: argparse.Namespace) -> int:
    """
    Execute a use-case scenario from a YAML file.

    Runs training if the YAML has a training section, then detection if it has a
    detection section (in the YAML's mode, or --mode).

    Args:
        args: Parsed CLI arguments with use_case path and mode override.

    Returns:
        The exit code of the last phase run (see cmd_train and cmd_detect).
    """
    try:
        if not args.use_case:
            logger.error("--use-case argument required for scenario command")
            return EXIT_ERROR

        use_case = _scenario_file(args.use_case)
        logger.info("Loading use-case scenario from %s...", use_case)
        uc = UseCase.from_yaml(use_case)

        if not uc.enabled:
            logger.info("Use case '%s' is disabled; skipping.", uc.name)
            return EXIT_OK

        logger.info("Use case: %s", uc.name)
        if uc.description:
            logger.info("  Description: %s", uc.description)

        # Load base config, then apply the scenario on top of it
        cfg = load_config(args.config)
        with open(use_case, "r") as f:
            scenario_yaml = yaml.safe_load(f) or {}
        apply_scenario_to_config(cfg, uc, scenario_yaml, source=use_case)
        apply_agent(cfg, getattr(args, "agent", None))
        if uc.has_detection:
            _validate_output(cfg)

        if uc.has_training:
            logger.info("Phase: training")
            result = _execute_training_phase(cfg, uc.training.lookback_hours, args)
            if result != EXIT_OK:
                return result

        if uc.has_detection:
            mode = args.mode if args.mode else uc.detection.mode
            logger.info("Phase: detection (mode: %s)", mode)
            return _execute_detection_phase(cfg, uc.detection, args, mode)

        logger.info("Scenario execution completed successfully.")
        return EXIT_OK

    except Exception:
        logger.exception("Scenario execution failed.")
        return EXIT_ERROR


def _execute_detection_phase(cfg: PipelineConfig, detection: DetectionScenario, args: argparse.Namespace, mode: str) -> int:
    """Load the model and run detection once, or repeatedly in realtime mode."""
    try:
        engine = _load_engine(cfg)
        if engine is None:
            return EXIT_ERROR
        client = _open_data_source(cfg, args, cfg.debug.detection_data_file, detection)
        if client is None:
            return EXIT_ERROR

        delivery = _build_delivery(cfg, client, args, detection)
        if mode != "realtime":
            # 'historical' or 'batch' mode: single detection run
            return _run_single_detection(cfg, client, engine, detection, args, delivery=delivery)

        return _realtime_loop(cfg, client, engine, detection, args, delivery=delivery)

    except Exception:
        logger.exception("Detection phase failed.")
        return EXIT_ERROR


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _seconds_until_next_poll(cfg: PipelineConfig, detection: DetectionScenario, now: datetime) -> float:
    """
    Wait before the next poll: until the next bucket has ended and its ingest delay has passed.

    ``detection.polling_interval_seconds``, when set, overrides this with a fixed interval.
    """
    if detection.polling_interval_seconds:
        return float(detection.polling_interval_seconds)
    bucket = timedelta(minutes=int(cfg.features.bucket_minutes))
    delay = timedelta(seconds=detection.ingest_delay_seconds)
    next_poll = _floor_time(now - delay, bucket) + bucket + delay
    return max(0.0, (next_poll - now).total_seconds())


def _realtime_loop(
    cfg: PipelineConfig,
    client,
    engine: MVADModelEngine,
    detection: DetectionScenario,
    args: argparse.Namespace,
    now=_utcnow,
    sleep=time.sleep,
    delivery: Optional[_Delivery] = None,
) -> int:
    """
    Poll until stopped: one detection run per bucket.

    A failed poll is retried after an exponential backoff of at most one bucket.
    "Not enough data" is not a failure. After ``detection.max_consecutive_failures``
    failed polls in a row the loop gives up with exit code 1.

    Args:
        now: Clock (injectable for tests).
        sleep: Sleep function (injectable for tests).

    Returns:
        0 when stopped with Ctrl+C, 1 after too many consecutive failures.
    """
    bucket_seconds = int(cfg.features.bucket_minutes) * 60
    max_failures = max(1, int(detection.max_consecutive_failures))
    failures = 0
    logger.info("Starting real-time detection loop. Press Ctrl+C to stop.")
    try:
        while True:
            code = _run_single_detection(cfg, client, engine, detection, args, now=now(), delivery=delivery)
            if code == EXIT_ERROR:
                failures += 1
                if failures >= max_failures:
                    logger.error("Detection failed %d times in a row; stopping.", failures)
                    return EXIT_ERROR
                wait = min(bucket_seconds, RETRY_BASE_SECONDS * 2 ** (failures - 1))
                logger.warning("Detection poll failed (%d of %d allowed in a row); retrying in %d seconds.", failures, max_failures, wait)
            else:
                failures = 0
                wait = _seconds_until_next_poll(cfg, detection, now())
                logger.info("Next poll in %d seconds.", wait)
            sleep(wait)
    except KeyboardInterrupt:
        logger.info("Real-time detection stopped by user.")
        return EXIT_OK


def _detection_context(cfg: PipelineConfig, engine: MVADModelEngine, detection: DetectionScenario, alert_count: int) -> Dict[str, Any]:
    """Fields of the anomaly documents that describe the model and the run."""
    return {
        "lookback_minutes": detection.lookback_minutes,
        "alert_count": alert_count,
        "scenario_id": _get_scenario_id(cfg),
        "model_name": cfg.model_name,
        "model_path": cfg.model_path,
        "feature_names": list(engine.training_columns or []),
        "training_samples": getattr(engine, "_training_samples", 0),
        "sliding_window": engine.sliding_window,
        "bucket_minutes": cfg.features.bucket_minutes,
        "anomaly_confidence": detection.anomaly_confidence if detection.anomaly_confidence is not None else DEFAULT_ANOMALY_CONFIDENCE,
    }


def _run_single_detection(
    cfg: PipelineConfig,
    client,
    engine: MVADModelEngine,
    detection: DetectionScenario,
    args: argparse.Namespace,
    now: Optional[datetime] = None,
    delivery: Optional[_Delivery] = None,
) -> int:
    """
    Execute a single detection iteration (every detection path).

    Args:
        cfg: Pipeline configuration.
        client: Wazuh client or LocalDataProvider.
        engine: Trained MVAD model engine.
        detection: Detection settings (lookback_minutes, ingest_delay_seconds, threshold, min_consecutive).
        args: CLI arguments (for shipping config).
        now: Current time (default: the clock).
        delivery: Sinks to deliver to (default: built from the configuration).

    Returns:
        0 if the window was scored and its new anomalies delivered, 2 if there was too little
        data to score it, 1 on error (including anomalies that could not be delivered).
    """
    try:
        # Before the search: the model's alert_filter selects the alerts.
        _adopt_model_features(cfg, engine)
        debug = isinstance(client, LocalDataProvider)
        fetch_start, score_start, end = _scoring_window(cfg, engine, detection.lookback_minutes, now=now, ingest_delay_seconds=detection.ingest_delay_seconds)
        if debug:
            logger.info("Scoring the local detection data (debug mode ignores the time range).")
        else:
            logger.info(
                "Scoring %d minutes of complete buckets, %s to %s (plus %d buckets of context from %s)",
                detection.lookback_minutes,
                score_start.isoformat(),
                end.isoformat(),
                engine.context_buckets,
                fetch_start.isoformat(),
            )
        alerts = _search_alerts(client, fetch_start, end, cfg, debug=debug)
        logger.info("Retrieved %d alerts.", len(alerts))
        if not alerts:
            logger.warning("No alerts in the detection window; nothing to score.")
            return EXIT_NOT_ENOUGH_DATA

        logger.info("Building feature time series...")
        _, ts_data = _detection_features(cfg, engine, alerts, fetch_start, end, debug=debug)
        if len(ts_data) < engine.min_detection_points:
            logger.warning(
                "Insufficient data for detection: %d time buckets, the model needs at least %d (sliding_window %d). %s",
                len(ts_data),
                engine.min_detection_points,
                engine.sliding_window,
                "The local data file is too short." if debug else "The alerts start too late in the window.",
            )
            return EXIT_NOT_ENOUGH_DATA

        logger.info("Running detection on %d time buckets...", len(ts_data))
        results = engine.predict(ts_data)
        if not debug:
            results = [r for r in results if r.timestamp >= pd.Timestamp(score_start)]
        logger.info("Scored %d buckets.", len(results))

        post = MVADPostProcessor(cfg.features)
        anomaly_docs = post.build_wazuh_anomaly_docs(
            results=results,
            context=_detection_context(cfg, engine, detection, len(alerts)),
            threshold=detection.threshold,
            min_consecutive=detection.min_consecutive,
            feature_values=ts_data,
        )

        if not anomaly_docs:
            logger.info("No anomalies detected.")
            return EXIT_OK
        logger.info("Found %d anomalies.", len(anomaly_docs))
        delivery = delivery or _build_delivery(cfg, client, args, detection)
        report = deliver(anomaly_docs, delivery.sinks, delivery.watermark, delivery.fallback)
        if report.all_failed:
            logger.error("No sink accepted the anomalies (%s).", ", ".join(report.failed))
            return EXIT_ERROR
        if report.failed:
            logger.warning("Sinks %s failed; the others accepted the anomalies.", ", ".join(report.failed))
        return EXIT_OK

    except ValueError as e:
        logger.error("Validation error during detection: %s", e)
        return EXIT_ERROR
    except RuntimeError as e:
        logger.error("Runtime error during detection: %s", e)
        return EXIT_ERROR
    except Exception:
        logger.exception("Single detection iteration failed with unexpected error.")
        return EXIT_ERROR


# --- Evaluation ---


def _alerts_from_file(path: str) -> list:
    """All alerts of a local JSON file (array, JSON lines or OpenSearch response)."""
    path = Path(path)
    return LocalDataProvider(str(path.parent), data_file=path.name).get_all_alerts()


def _last_hours(alerts: list, hours: Optional[int]) -> list:
    """The alerts of the last ``hours`` before the newest alert (all of them if ``hours`` is not set)."""
    if not hours or not alerts:
        return alerts
    stamps = [LocalDataProvider._parse_timestamp(a["timestamp"]) for a in alerts]
    cutoff = max(stamps) - timedelta(hours=int(hours))
    return [a for a, ts in zip(alerts, stamps) if ts >= cutoff]


def _sonar_detections(args: argparse.Namespace, report: Dict[str, Any]) -> Tuple[DetectionScenario, Dict[str, list]]:
    """Train the scenario's backend on the training file and score each split; returns the scenario's detection settings and the detections per split."""
    cfg, training = load_scenario_for_phase(args.scenario, "training", args.config)
    _, detection = load_scenario_for_phase(args.scenario, "detection", args.config)
    if args.backend:
        cfg.backend = args.backend
    agent = getattr(args, "agent", None)
    apply_agent(cfg, agent)
    train_alerts = _last_hours(_of_agent(_alerts_from_file(args.train_file), agent), training.lookback_hours if training else None)
    fb = WazuhFeatureBuilder(cfg.features)
    ts_train = fb.build_timeseries(train_alerts)
    engine = MVADModelEngine(cfg)
    started = time.monotonic()
    engine.train(ts_train, vocabulary=fb.vocabulary)
    report.update(
        scenario=_get_scenario_id(cfg),
        backend=engine.backend_name,
        train_file=args.train_file,
        training_buckets=len(ts_train),
        training_seconds=round(time.monotonic() - started, 1),
        context_buckets=engine.context_buckets,
    )
    detections = {}
    for split, path in (("validation", args.validation_file), ("test", args.test_file)):
        if not path:
            continue
        ts = WazuhFeatureBuilder(cfg.features, vocabulary=engine.vocabulary).build_timeseries(_of_agent(_alerts_from_file(path), agent))
        if len(ts) < engine.min_detection_points:
            raise ValueError(f"{path}: {len(ts)} buckets, the model needs at least {engine.min_detection_points}")
        detections[split] = detections_from_points(engine.predict(ts), cfg.features.bucket_minutes)
        report[f"{split}_file"] = path
    return detection, detections


def cmd_evaluate(args: argparse.Namespace) -> int:
    """
    Measure detection quality against labelled data, optionally calibrating the decision rule.

    Writes ``<name>.json`` (the record) and ``<name>.md`` (a summary) to ``--output-dir``.

    Returns:
        0 on success, 1 on failure.
    """
    try:
        if bool(args.scenario) == bool(args.detections):
            logger.error("Give either --scenario (with --train-file) or --detections.")
            return EXIT_ERROR
        if args.scenario and not (args.train_file and args.test_file):
            logger.error("--scenario needs --train-file and --test-file.")
            return EXIT_ERROR
        if bool(args.validation_labels) != bool(args.validation_file or args.validation_detections):
            logger.error("Calibration needs both validation data (--validation-file or --validation-detections) and --validation-labels.")
            return EXIT_ERROR

        event_types = [t.strip() for t in (args.event_types or "").split(",") if t.strip()] or None
        test_labels = Labels.from_file(args.test_labels)
        report: Dict[str, Any] = {
            "format": REPORT_FORMAT,
            "sonar_version": SONAR_VERSION,
            "test_labels": args.test_labels,
            "validation_labels": args.validation_labels,
            "tolerance_minutes": args.tolerance_minutes,
            "event_types": event_types,
            "max_false_alarms_per_day": args.max_false_alarms_per_day,
        }

        if args.detections:
            report["detector"] = args.detector_name
            detections = {"test": load_external_detections(args.detections)}
            report["test_file"] = args.detections
            if args.validation_detections:
                detections["validation"] = load_external_detections(args.validation_detections)
                report["validation_file"] = args.validation_detections
            configured = (None, 1)
        else:
            detection, detections = _sonar_detections(args, report)
            report["detector"] = f"sonar/{report['backend']}"
            configured = (detection.threshold, detection.min_consecutive)

        runs = [{"name": "test (configured)", "threshold": configured[0], "min_consecutive": configured[1]}]
        if args.validation_labels:
            cal = calibrate(detections["validation"], Labels.from_file(args.validation_labels), args.tolerance_minutes, event_types, args.max_false_alarms_per_day)
            report["calibration"] = cal.to_dict()
            runs.append({"name": "validation (calibrated)", "threshold": cal.threshold, "min_consecutive": cal.min_consecutive, "metrics": cal.validation.to_dict()})
            runs.append({"name": "test (calibrated)", "threshold": cal.threshold, "min_consecutive": cal.min_consecutive})
        for run in runs:
            if "metrics" not in run:
                run["metrics"] = score(detections["test"], test_labels, run["threshold"], run["min_consecutive"], args.tolerance_minutes, event_types).to_dict()
        report["runs"] = runs
        if args.validation_labels:
            report["anomaly_confidence"] = runs[-1]["metrics"]["precision"]

        name = args.name or (f"{report['scenario']}-{report['backend']}" if args.scenario else slug(args.detector_name))
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{name}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        summary = render_markdown(report)
        (out / f"{name}.md").write_text(summary, encoding="utf-8")
        logger.info("Evaluation report written to %s/%s.{json,md}", out, name)
        print(summary)
        return EXIT_OK
    except InsufficientTrainingDataError as e:
        logger.error("%s", e)
        return EXIT_ERROR
    except (OSError, ValueError, KeyError) as e:
        logger.error("Evaluation failed: %s", e)
        return EXIT_ERROR


# --- Export (live data for sonar evaluate) ---

EXPORT_EVENTS_FILE = "events.json"
EXPORT_LABELS_FILE = "labels.json"
EXPORT_RADAR_FILE = "radar_results.json"


def _utc_datetime(value: str) -> datetime:
    """A command-line time (ISO 8601) as an aware UTC datetime; without an offset it is UTC."""
    ts = pd.Timestamp(value)
    ts = ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")
    return ts.to_pydatetime()


def _export_labels(specs: Optional[list], start: datetime, end: datetime, dataset: str) -> Labels:
    """
    The label file of an exported window: its span and one event per ``--event TYPE,START,END``.

    Raises:
        ValueError: On a malformed event or one outside the window.
    """
    events, counts = [], {}
    for spec in specs or []:
        parts = [p.strip() for p in spec.split(",")]
        if len(parts) != 3 or not all(parts):
            raise ValueError(f"--event {spec!r}: expected TYPE,START,END")
        kind, ev_start, ev_end = parts[0], _utc_datetime(parts[1]), _utc_datetime(parts[2])
        if ev_end <= start or ev_start >= end:
            raise ValueError(f"--event {spec!r} lies outside the exported window {start.isoformat()} to {end.isoformat()}")
        counts[kind] = counts.get(kind, 0) + 1
        events.append({"id": f"{kind}_{counts[kind]}", "type": kind, "start": ev_start.isoformat(), "end": ev_end.isoformat()})
    return Labels.from_dict({"format": LABELS_FORMAT, "dataset": dataset, "span": {"start": start.isoformat(), "end": end.isoformat()}, "events": events})


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")


def cmd_export(args: argparse.Namespace) -> int:
    """
    Export a time window from the indexer for ``sonar evaluate``.

    Writes to ``--output-dir``:

    - ``events.json``: the scenario's alerts or events (its index, ``alert_filter`` and ``--agent``)
      from ``context`` before ``--start`` to ``--end``. The context is what the scenario's
      backend needs before it scores the first bucket, so SONAR scores the whole window.
    - ``labels.json``: the window as the label span, and each ``--event`` as a labelled event.
    - ``radar_results.json`` (with ``--radar-results``): the OpenSearch anomaly detection results
      of RADAR's detector for the window (and ``--agent``), for ``sonar evaluate --detections``.

    Returns:
        0 on success, 2 if the window holds no alerts, 1 on failure.
    """
    try:
        cfg, _ = load_scenario_for_phase(args.scenario, "training", args.config)
        apply_agent(cfg, args.agent)
        bucket = timedelta(minutes=int(cfg.features.bucket_minutes))
        start, end = _floor_time(_utc_datetime(args.start), bucket), _floor_time(_utc_datetime(args.end), bucket)
        if end <= start:
            logger.error("--end must be at least one bucket (%s) after --start.", bucket)
            return EXIT_ERROR
        if args.context_minutes is not None:
            context = timedelta(minutes=args.context_minutes)
        else:
            context = MVADModelEngine(cfg).context_buckets * bucket
        labels = _export_labels(args.event, start, end, f"{_get_scenario_id(cfg)} {start.isoformat()} to {end.isoformat()}")

        client = WazuhIndexerClient(cfg.wazuh)
        if not client.check_connection():
            logger.error("Failed to connect to Wazuh Indexer.")
            return EXIT_ERROR
        logger.info("Exporting %s from %s to %s (%s of context before %s).", cfg.wazuh.alerts_index_pattern, (start - context).isoformat(), end.isoformat(), context, start.isoformat())
        alerts = client.search_alerts(start - context, end, query=cfg.features.alert_filter or None)
        radar = client.search_detector_results(args.radar_results, start, end, entity=args.agent, entity_field=AGENT_FIELD) if args.radar_results else None

        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        _write_json(out / EXPORT_EVENTS_FILE, alerts)
        labels.write(str(out / EXPORT_LABELS_FILE))
        written = [EXPORT_EVENTS_FILE, EXPORT_LABELS_FILE]
        if radar is not None:
            _write_json(out / EXPORT_RADAR_FILE, radar)
            written.append(EXPORT_RADAR_FILE)
        logger.info("Wrote %s to %s: %d alerts, %d labelled events%s.", ", ".join(written), out, len(alerts), len(labels.events), f", {len(radar)} RADAR results" if radar is not None else "")
        if not alerts:
            logger.warning("The window holds no alerts: check the scenario's index (wazuh.alerts_index_pattern), alert_filter and --agent.")
            return EXIT_NOT_ENOUGH_DATA
        return EXIT_OK
    except ValueError as e:
        logger.error("Export failed: %s", e)
        return EXIT_ERROR
    except Exception:
        logger.exception("Export failed.")
        return EXIT_ERROR


def cmd_wazuh_install_rules(args: argparse.Namespace) -> int:
    """
    Upload ``sonar/wazuh/rules/sonar_rules.xml`` to the manager (``PUT /rules/files``), optionally restarting it.

    Returns:
        0 on success, 1 on failure.
    """
    try:
        cfg = load_config(args.config)
        sink_cfg = cfg.output.wazuh
        user = args.user or sink_cfg.api_username
        # With --user, the configured password and $SONAR_WAZUH_API_PASSWORD belong to another user
        # (the event:ingest one): only $SONAR_WAZUH_ADMIN_PASSWORD or the prompt apply.
        password = os.environ.get(ADMIN_PASSWORD_ENV) or ("" if args.user else (sink_cfg.api_password or os.environ.get(PASSWORD_ENV, "")))
        if not password and sys.stdin.isatty():
            password = getpass.getpass(f"Wazuh API password for {user}: ")
        api = WazuhApi(args.api_url or sink_cfg.api_url, user, password, verify=sink_cfg.verify_ssl, timeout=sink_cfg.timeout_seconds)
        api.request(
            "PUT",
            f"/rules/files/{RULES_FILE.name}",
            params={"overwrite": "true"},
            data=RULES_FILE.read_bytes(),
            headers={"Content-Type": "application/octet-stream"},
        )
        logger.info("✓ Uploaded %s to the Wazuh manager at %s.", RULES_FILE.name, api.url)
        if args.restart:
            api.request("PUT", "/manager/restart")
            logger.info("✓ Manager restart requested; the rules are active once it is back.")
        else:
            logger.info("Restart the manager to load the rules (or rerun with --restart).")
        return EXIT_OK
    except (WazuhApiError, OSError) as e:
        logger.error("Installing the rules failed: %s", e)
        return EXIT_ERROR


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
    parser = argparse.ArgumentParser(description="SONAR: SIEM-Oriented Neural Anomaly Recognition for Wazuh.")
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
        help="Model name: the model is <models_dir>/<name>/ (default: the scenario's model_name or name, else the config's model_name)",
    )
    train_parser.add_argument(
        "--lookback-hours",
        type=int,
        default=None,
        help="Hours of historical data to train on (default: the scenario's lookback_hours, else 168)",
    )
    train_parser.add_argument(
        "--print-payloads",
        action="store_true",
        help="Print JSON payloads (and save) for anomalies instead of or before sending",
    )
    train_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not send requests to Wazuh/OpenSearch; save payloads to disk instead",
    )
    train_parser.add_argument(
        "--payload-dir",
        type=str,
        default=None,
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
    train_parser.add_argument("--agent", type=str, default=None, help="Only this agent (agent.name): its own model <model_name>-<agent>, like RADAR's per-host detectors")
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
        default=None,
        help="Minutes of complete buckets to score; earlier context is fetched automatically (default: the scenario's lookback_minutes, else 10)",
    )
    detect_parser.add_argument(
        "--print-payloads",
        action="store_true",
        help="Print JSON payloads (and save) for anomalies instead of or before sending",
    )
    detect_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not send requests to Wazuh/OpenSearch; save payloads to disk instead",
    )
    detect_parser.add_argument(
        "--payload-dir",
        type=str,
        default=None,
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
    detect_parser.add_argument("--agent", type=str, default=None, help="Only this agent (agent.name): its own model <model_name>-<agent>, like RADAR's per-host detectors")
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
        default=None,
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
    scenario_parser.add_argument("--agent", type=str, default=None, help="Only this agent (agent.name): its own model <model_name>-<agent>, like RADAR's per-host detectors")
    scenario_parser.set_defaults(func=cmd_scenario)

    # Evaluation against labelled data
    eval_parser = subparsers.add_parser("evaluate", help="Measure detection quality on labelled data (precision, recall, F1, delay, false alarms) and calibrate the decision rule")
    eval_parser.add_argument("--scenario", type=str, default=None, help="Scenario to evaluate: its features, backend and detection settings (path or packaged name)")
    eval_parser.add_argument("--config", type=str, default=None, help="Base config YAML (optional)")
    eval_parser.add_argument("--backend", type=str, default=None, help="Override the scenario's backend (mvad, pca, ewma)")
    eval_parser.add_argument("--train-file", type=str, default=None, help="Alert file to train on (the last training.lookback_hours of it)")
    eval_parser.add_argument("--validation-file", type=str, default=None, help="Alert file of the validation split; with --validation-labels, calibrates threshold and min_consecutive")
    eval_parser.add_argument("--validation-labels", type=str, default=None, help="Label file of the validation split")
    eval_parser.add_argument("--test-file", type=str, default=None, help="Alert file of the test split")
    eval_parser.add_argument("--test-labels", type=str, required=True, help="Label file of the test split")
    eval_parser.add_argument("--detections", type=str, default=None, help="Evaluate another detector's results instead of SONAR (OpenSearch anomaly detection results or start/end/severity records)")
    eval_parser.add_argument("--validation-detections", type=str, default=None, help="That detector's results on the validation split")
    eval_parser.add_argument("--detector-name", type=str, default="external", help="Name of that detector in the report")
    eval_parser.add_argument("--event-types", type=str, default=None, help="Comma-separated label types the scenario is meant to detect (default: all); other labelled events are ignored")
    eval_parser.add_argument("--tolerance-minutes", type=float, default=0.0, help="An alarm this close to an event still detects it (default: 0)")
    eval_parser.add_argument("--max-false-alarms-per-day", type=float, default=5.0, help="False-alarm budget for calibration (default: 5)")
    eval_parser.add_argument("--output-dir", type=str, default=".", help="Directory for the JSON report and Markdown summary (default: current directory)")
    eval_parser.add_argument("--name", type=str, default=None, help="Report file name without extension (default: <scenario_id>-<backend>)")
    eval_parser.add_argument("--agent", type=str, default=None, help="Only this agent's alerts in the files, with the model and report named after it")
    eval_parser.set_defaults(func=cmd_evaluate)

    # Export of a live window for evaluation
    export_parser = subparsers.add_parser("export", help="Export a window of the scenario's alerts, RADAR's detector results and labels from the indexer, for sonar evaluate")
    export_parser.add_argument("--scenario", type=str, required=True, help="Scenario whose index, alert_filter and window settings select the alerts (path or packaged name)")
    export_parser.add_argument("--config", type=str, default=None, help="Base config YAML (optional): the indexer connection")
    export_parser.add_argument("--start", type=str, required=True, help="Start of the window (ISO 8601; UTC without an offset), rounded down to a bucket")
    export_parser.add_argument("--end", type=str, required=True, help="End of the window, exclusive (ISO 8601), rounded down to a bucket")
    export_parser.add_argument("--output-dir", type=str, required=True, help="Directory for events.json, labels.json and radar_results.json")
    export_parser.add_argument("--agent", type=str, default=None, help="Only this agent's alerts and RADAR results")
    export_parser.add_argument(
        "--context-minutes",
        type=int,
        default=None,
        help="Alerts exported before --start, so that SONAR scores the whole window (default: the context the scenario's backend needs)",
    )
    export_parser.add_argument("--radar-results", type=str, default=None, help="Result index (or pattern) of RADAR's detector, e.g. opensearch-ad-plugin-result-linux-resource-utilization*")
    export_parser.add_argument("--event", type=str, action="append", default=None, help="A labelled event TYPE,START,END in the window (repeatable), e.g. the run of a RADAR simulation")
    export_parser.set_defaults(func=cmd_export)

    # Check subcommand
    check_parser = subparsers.add_parser("check", help="Check Wazuh Indexer connection")
    check_parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config YAML (optional)",
    )
    check_parser.set_defaults(func=cmd_check)

    # Wazuh manager integration
    wazuh_parser = subparsers.add_parser("wazuh", help="Wazuh manager integration (rules)")
    wazuh_sub = wazuh_parser.add_subparsers(dest="wazuh_command")
    install_parser = wazuh_sub.add_parser("install-rules", help="Upload SONAR's rules (100500-100519) to the Wazuh manager through its API")
    install_parser.add_argument("--config", type=str, default=None, help="Config YAML whose output.wazuh section gives the API URL and TLS settings")
    install_parser.add_argument("--api-url", type=str, default=None, help="Wazuh server API URL (default: output.wazuh.api_url)")
    install_parser.add_argument(
        "--user",
        type=str,
        default=None,
        help=f"API user allowed to update rules (default: output.wazuh.api_username); its password comes from ${ADMIN_PASSWORD_ENV} or a prompt",
    )
    install_parser.add_argument("--restart", action="store_true", help="Restart the manager afterwards so the rules take effect")
    install_parser.set_defaults(func=cmd_wazuh_install_rules)

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1
    if args.command == "wazuh" and getattr(args, "wazuh_command", None) is None:
        wazuh_parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
