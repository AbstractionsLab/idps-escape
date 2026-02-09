"""
SONAR Wazuh Indexer templates for anomaly data streams.

Defines the index template structure for SONAR (MVAD-based) anomaly detection results.
"""

# Template structure keys
TYPE = "type"
MAPPINGS = "mappings"
PROPERTIES = "properties"
COMPOSED_OF = "composed_of"
TEMPLATE = "template"
PRIORITY = "priority"
INDEX_PATTERNS = "index_patterns"
DATA_STREAM = "data_stream"
NAME = "name"
PATTERN = "pattern"

# Field type values
TIMESTAMP = "timestamp"
BOOLEAN = "boolean"
FLOAT = "float"
KEYWORD = "keyword"
TEXT = "text"
OBJECT = "object"

# SONAR template naming
SONAR_BASE_TEMPLATE_NAME = "sonar_stream_template"
SONAR_ANOMALY_PATTERN = "sonar_anomalies"
SONAR_INDEX_PATTERNS = [
    SONAR_ANOMALY_PATTERN + "_*",
]

BASE_TEMPLATE_KEYS = [INDEX_PATTERNS, TEMPLATE, COMPOSED_OF, PRIORITY, "_meta", DATA_STREAM]

# Base template for SONAR anomaly data streams
SONAR_BASE_TEMPLATE = {
    INDEX_PATTERNS: SONAR_INDEX_PATTERNS,
    TEMPLATE: {
        "settings": {
            "index.refresh_interval": "30s",
            "index.number_of_replicas": 0,
            "index.number_of_shards": 1,
        },
        MAPPINGS: {
            PROPERTIES: {
                "is_anomaly": {TYPE: BOOLEAN},
                "anomaly_score": {TYPE: FLOAT},
                "threshold": {TYPE: FLOAT},
                "scenario_name": {TYPE: KEYWORD},
                "detection_timestamp": {TYPE: "date"},
                "alert_count": {TYPE: "integer"},
                "feature_count": {TYPE: "integer"},
            }
        },
        "aliases": {},
    },
    COMPOSED_OF: [],
    PRIORITY: 1,
    "_meta": {"flow": "sonar_mvad", "version": "2.0"},
    DATA_STREAM: {"timestamp_field": {"name": TIMESTAMP}},
}

# MVAD-specific component template
MVAD_COMPONENT_NAME = "component_template_sonar_mvad"
MVAD_COMPONENT = {
    TEMPLATE: {
        MAPPINGS: {
            PROPERTIES: {
                "mvad_score": {TYPE: FLOAT},
                "mvad_severity": {TYPE: FLOAT},
                "mvad_threshold": {TYPE: FLOAT},
                "sliding_window": {TYPE: "integer"},
                "bucket_minutes": {TYPE: "integer"},
                "lookback_minutes": {TYPE: "integer"},
                "top_contributors": {
                    TYPE: OBJECT,
                    PROPERTIES: {
                        "variable": {TYPE: KEYWORD},
                        "contribution": {TYPE: FLOAT},
                    },
                },
                "context": {
                    TYPE: OBJECT,
                    PROPERTIES: {
                        "model_path": {TYPE: KEYWORD},
                        "feature_names": {TYPE: KEYWORD},
                        "training_samples": {TYPE: "integer"},
                    },
                },
            }
        }
    }
}

# Scenario-specific feature component template name pattern
SCENARIO_COMPONENT_NAME = "component_template_sonar_{scenario_id}"


def get_scenario_component(scenario_name: str, features: dict) -> dict:
    """
    Generate scenario-specific template component with dynamic feature fields.

    Args:
        scenario_name: Name of the scenario (e.g., 'brute_force', 'lateral_movement').
        features: Dict mapping feature names to their types (e.g., {'rule.level': 'float'}).

    Returns:
        Template component definition for the scenario.
    """
    properties = {}
    for feature_name, feature_type in features.items():
        safe_name = feature_name.replace(".", "_")
        properties[f"feature_{safe_name}"] = {TYPE: feature_type}

    return {
        TEMPLATE: {
            MAPPINGS: {
                PROPERTIES: {
                    "scenario_features": {TYPE: OBJECT, PROPERTIES: properties},
                    "scenario_metadata": {
                        TYPE: OBJECT,
                        PROPERTIES: {
                            "scenario_name": {TYPE: KEYWORD},
                            "scenario_version": {TYPE: KEYWORD},
                        },
                    },
                }
            }
        }
    }
