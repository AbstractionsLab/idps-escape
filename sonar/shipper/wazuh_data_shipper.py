"""
SONAR Wazuh Data Shipper - Ship MVAD anomaly results to Wazuh Indexer.

This module implements data stream creation and document shipping for SONAR
anomaly detection results to be indexed in Wazuh (OpenSearch).
"""

import json
import logging
import math
from pathlib import Path
from typing import Any, Dict, List, Optional

from opensearchpy import OpenSearch
from opensearchpy.exceptions import OpenSearchException

from sonar.config import WazuhIndexerConfig
from sonar.shipper import DataShipper
from sonar.shipper.wazuh_base_template import (
    BASE_TEMPLATE_KEYS,
    COMPOSED_OF,
    INDEX_PATTERNS,
    MAPPINGS,
    MVAD_COMPONENT,
    MVAD_COMPONENT_NAME,
    PATTERN,
    PRIORITY,
    PROPERTIES,
    SCENARIO_COMPONENT_NAME,
    SONAR_ANOMALY_PATTERN,
    SONAR_BASE_TEMPLATE,
    SONAR_BASE_TEMPLATE_NAME,
    TEMPLATE,
    TYPE,
    get_scenario_component,
)

logger = logging.getLogger(__name__)

# Bulk actions
CREATE = "create"
DELETE = "delete"
INDEX = "index"
UPDATE = "update"


def clean_nan_values(obj: Any) -> Any:
    """
    Recursively clean NaN values from a data structure.
    
    Converts NaN/Infinity values to None (null in JSON) to prevent
    OpenSearch rejection of invalid JSON.
    
    Args:
        obj: Object to clean (dict, list, or primitive).
        
    Returns:
        Cleaned object with NaN values replaced by None.
    """
    if isinstance(obj, dict):
        return {k: clean_nan_values(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [clean_nan_values(item) for item in obj]
    elif isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    else:
        return obj

CONNECTION_MESSAGE = "SONAR shipper connected to Wazuh Indexer"
ERROR_INSTALL_MESSAGE = "SONAR shipper not installed!"


def get_template_name_and_pattern(scenario_id: Optional[str] = None) -> tuple[str, str]:
    """
    Get template name and index pattern for a scenario.

    Args:
        scenario_id: Optional scenario identifier (e.g., 'brute_force_abc123').

    Returns:
        Tuple of (template_name, pattern).
    """
    if scenario_id:
        template_name = f"{SONAR_BASE_TEMPLATE_NAME}_mvad_{scenario_id}"
        pattern = f"{SONAR_ANOMALY_PATTERN}_mvad_{scenario_id}"
    else:
        template_name = f"{SONAR_BASE_TEMPLATE_NAME}_mvad"
        pattern = f"{SONAR_ANOMALY_PATTERN}_mvad"
    return template_name, pattern


class TemplateHandler:
    """Handles index template construction and manipulation."""

    def __init__(self, pattern: str = SONAR_ANOMALY_PATTERN, name: str = SONAR_BASE_TEMPLATE_NAME):
        """
        Initialize template handler.

        Args:
            pattern: Index pattern for the template.
            name: Name of the template.
        """
        self.pattern = pattern
        self.name = name
        # Deep copy of base template
        self.body = {k: v for k, v in SONAR_BASE_TEMPLATE.items()}

        if not all(x in self.body for x in BASE_TEMPLATE_KEYS):
            raise ValueError("Missing keys in selected base template")

        self.body[INDEX_PATTERNS] = [pattern + "_*"]

    @staticmethod
    def get_base_template() -> dict:
        """Get the base SONAR template."""
        return SONAR_BASE_TEMPLATE

    @staticmethod
    def get_scenario_template_component(features: Dict[str, str]) -> dict:
        """
        Generate scenario-specific template component.

        Args:
            features: Dict mapping feature names to types (e.g., {'rule.level': 'float'}).

        Returns:
            Template component body.
        """
        properties = {}
        for feature_name, feature_type in features.items():
            safe_name = feature_name.replace(".", "_")
            properties[safe_name] = {TYPE: feature_type}
        return {TEMPLATE: {MAPPINGS: {PROPERTIES: properties}}}

    def get_stream_name(self, scenario_id: str) -> str:
        """
        Get data stream name for a scenario.

        Args:
            scenario_id: Scenario identifier.

        Returns:
            Data stream name.
        """
        return f"{self.pattern}_{scenario_id}"

    def add_component(self, component_name: str):
        """
        Add a component to the template.

        Args:
            component_name: Name of the component to add.
        """
        self.body[COMPOSED_OF] = self.body[COMPOSED_OF] + [component_name]
        self.body[PRIORITY] += 1

    def set_pattern_as_scenario_name(self, scenario_id: str) -> str:
        """
        Set the index pattern to match a specific scenario.

        Args:
            scenario_id: Scenario identifier.

        Returns:
            The specific pattern name.
        """
        name = f"{self.pattern}_{scenario_id}"
        self.body[INDEX_PATTERNS] = [name]
        return name


class WazuhDataShipper(DataShipper):
    """Wazuh Indexer data shipper for SONAR anomaly results."""

    def __init__(self, config: WazuhIndexerConfig, install: bool = False):
        """
        Initialize Wazuh data shipper.

        Args:
            config: WazuhIndexerConfig instance with connection details.
            install: If True, install base templates on initialization.
        """
        super().__init__(config)
        self.base_template_pattern = SONAR_ANOMALY_PATTERN
        self.map_scenario_templates = {}

        logger.info("SONAR Shipper establishing connection to Wazuh Indexer...")

        # Parse base URL to get host and port
        # Expected format: https://localhost:9200 or http://localhost:9200
        base_url = config.base_url.rstrip("/")
        if "://" in base_url:
            protocol, rest = base_url.split("://", 1)
            use_ssl = protocol == "https"
        else:
            rest = base_url
            use_ssl = config.verify_ssl

        # Split host:port
        if ":" in rest:
            host, port_str = rest.rsplit(":", 1)
            port = int(port_str)
        else:
            host = rest
            port = 9200  # default OpenSearch port

        auth = (config.username, config.password)

        self.client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=use_ssl,
            verify_certs=config.verify_ssl if isinstance(config.verify_ssl, bool) else True,
            ssl_assert_hostname=False,
            ssl_show_warn=False,
        )

        if install:
            self.install()

    def test_connection(self) -> bool:
        """
        Test connection to Wazuh Indexer.

        Returns:
            True if connection is healthy, False otherwise.
        """
        try:
            response = self.client.cluster.health()
            cluster_status = response.get("status")
            if cluster_status in ["green", "yellow"]:
                logger.info("SONAR Shipper: Connection to Wazuh Indexer successful (status: %s)", cluster_status)
                return True
            else:
                logger.warning("SONAR Shipper: Cluster status is %s", cluster_status)
                return False
        except Exception as e:
            logger.error("SONAR Shipper: Error checking connection: %s", e)
            return False

    def index_template_exists(self, name: str) -> bool:
        """
        Check if an index template exists.

        Args:
            name: Template name.

        Returns:
            True if template exists.
        """
        try:
            return self.client.indices.exists_index_template(name=name)
        except Exception as e:
            logger.error("Error checking template existence: %s", e)
            return False

    def install(self):
        """Install base SONAR templates and components in Wazuh Indexer."""
        connection = self.test_connection()
        if not connection:
            raise ConnectionError("Connection to Wazuh Indexer not available: shipping impossible")

        base_template_exists = self.index_template_exists(SONAR_BASE_TEMPLATE_NAME)
        if base_template_exists:
            logger.info(CONNECTION_MESSAGE)
        else:
            logger.info("Installing SONAR base template...")
            base_template = TemplateHandler()
            response = self.client.indices.put_index_template(name=base_template.name, body=base_template.body)
            logger.info("Base template installed: %s", response)

        # Install MVAD component template
        self.add_mvad_template()

    def ship_single(self, stream_name: str, document: dict) -> dict:
        """
        Ship a single document to a data stream.

        Args:
            stream_name: Name of the data stream.
            document: Document to index.

        Returns:
            Response from OpenSearch.
        """
        try:
            # Clean NaN values to prevent JSON parsing errors
            cleaned_document = clean_nan_values(document)
            response = self.client.index(index=stream_name, body=cleaned_document)
            logger.debug("Shipped document to %s: %s", stream_name, response)
            return response
        except OpenSearchException as e:
            logger.error("Error shipping document to %s: %s", stream_name, e)
            raise

    def ship_bulk(self, request: str) -> dict:
        """
        Ship multiple documents in bulk.

        Args:
            request: Bulk request body (newline-delimited JSON).

        Returns:
            Response from OpenSearch.
        """
        try:
            response = self.client.bulk(body=request)
            logger.debug("Shipped bulk request: %s", response)
            return response
        except OpenSearchException as e:
            logger.error("Error shipping bulk request: %s", e)
            raise

    def get_single_request(self, data: dict, stream_name: str):
        """Build single document request (not implemented for direct use)."""
        pass

    def get_bulk_request(self, data: List[dict], stream_name: str, actions: List[str]) -> str:
        """
        Build a bulk request body.

        Args:
            data: List of documents.
            stream_name: Target stream name.
            actions: List of actions (one per document).

        Returns:
            Newline-delimited JSON bulk request body.
        """
        lines = []
        for action, doc in zip(actions, data):
            action_meta = {action: {"_index": stream_name}}
            lines.append(json.dumps(action_meta))
            # Clean NaN values before serializing
            cleaned_doc = clean_nan_values(doc)
            lines.append(json.dumps(cleaned_doc))
        return "\n".join(lines) + "\n"

    def add_mvad_template(self):
        """Add MVAD component template if it doesn't exist."""
        try:
            # Check if component template exists
            exists = self.client.cluster.exists_component_template(name=MVAD_COMPONENT_NAME)
            if not exists:
                logger.info("Installing MVAD component template...")
                response = self.client.cluster.put_component_template(name=MVAD_COMPONENT_NAME, body=MVAD_COMPONENT)
                logger.info("MVAD component template installed: %s", response)

            # Create MVAD-specific index template
            template_name, pattern = get_template_name_and_pattern()
            if not self.index_template_exists(template_name):
                logger.info("Installing MVAD index template...")
                template_handler = self.create_template_handler_from_base([MVAD_COMPONENT_NAME])
                response = self.client.indices.put_index_template(name=template_name, body=template_handler.body)
                logger.info("MVAD index template installed: %s", response)
                self.map_scenario_templates["mvad"] = (template_name, pattern)
        except Exception as e:
            logger.error("Error adding MVAD template: %s", e)
            raise

    def create_template_handler_from_base(self, components: List[str]) -> TemplateHandler:
        """
        Create a template handler from base with specified components.

        Args:
            components: List of component template names to include.

        Returns:
            Configured TemplateHandler instance.
        """
        template_handler = TemplateHandler(pattern=SONAR_ANOMALY_PATTERN, name=SONAR_BASE_TEMPLATE_NAME)
        for component in components:
            template_handler.add_component(component)
        return template_handler

    def create_scenario_stream(
        self, scenario_id: str, scenario_name: str, features: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Create a data stream for a specific scenario.

        Args:
            scenario_id: Unique scenario identifier.
            scenario_name: Human-readable scenario name.
            features: Optional dict of feature names to types.

        Returns:
            Name of the created data stream.
        """
        template_name, pattern = get_template_name_and_pattern(scenario_id)

        # Create scenario-specific component if features provided
        component_name = SCENARIO_COMPONENT_NAME.format(scenario_id=scenario_id)
        components = [MVAD_COMPONENT_NAME]

        if features:
            logger.info("Creating scenario component template: %s", component_name)
            scenario_component = self.get_scenario_template_component(features)
            try:
                self.client.cluster.put_component_template(name=component_name, body=scenario_component)
                components.append(component_name)
            except Exception as e:
                logger.warning("Could not create scenario component: %s", e)

        # Create scenario-specific index template
        template_handler = self.create_template_handler_from_base(components)
        stream_name = template_handler.set_pattern_as_scenario_name(scenario_id)

        try:
            logger.info("Creating scenario index template: %s", template_name)
            self.client.indices.put_index_template(name=template_name, body=template_handler.body)
            self.map_scenario_templates[scenario_id] = (template_name, stream_name)
            logger.info("Scenario stream ready: %s", stream_name)
            return stream_name
        except Exception as e:
            logger.error("Error creating scenario stream: %s", e)
            raise

    def get_scenario_template_component(self, features: Dict[str, str]) -> dict:
        """
        Generate scenario-specific template component.

        Args:
            features: Dict mapping feature names to types.

        Returns:
            Component template body.
        """
        return TemplateHandler.get_scenario_template_component(features)

    def delete_data_stream(self, stream_name: str):
        """
        Delete a data stream.

        Args:
            stream_name: Name of the data stream to delete.
        """
        try:
            if self.client.indices.exists(index=stream_name):
                response = self.client.indices.delete(index=stream_name)
                logger.info("Deleted data stream: %s", stream_name)
                return response
            else:
                logger.warning("Data stream does not exist: %s", stream_name)
        except Exception as e:
            logger.error("Error deleting data stream %s: %s", stream_name, e)
            raise

    def add_rollover_policy(self, policy_name: str = "sonar_rollover_policy"):
        """
        Add ISM rollover policy for SONAR data streams.

        Args:
            policy_name: Name of the policy to create.
        """
        policy_body = {
            "policy": {
                "description": "SONAR anomaly data stream rollover policy",
                "default_state": "active",
                "states": [
                    {
                        "name": "active",
                        "actions": [],
                        "transitions": [
                            {
                                "state_name": "rollover",
                                "conditions": {"min_index_age": "7d", "min_doc_count": 100000},
                            }
                        ],
                    },
                    {
                        "name": "rollover",
                        "actions": [{"rollover": {}}],
                        "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "30d"}}],
                    },
                    {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
                ],
            }
        }

        try:
            response = self.client.transport.perform_request("PUT", f"/_plugins/_ism/policies/{policy_name}", body=policy_body)
            logger.info("Rollover policy created: %s", policy_name)
            return response
        except Exception as e:
            logger.error("Error creating rollover policy: %s", e)
            raise

    def check_install(self) -> bool:
        """
        Check if SONAR shipper is properly installed.

        Returns:
            True if base templates exist.
        """
        try:
            base_exists = self.index_template_exists(SONAR_BASE_TEMPLATE_NAME)
            if base_exists:
                logger.info("SONAR shipper is installed")
                return True
            else:
                logger.warning(ERROR_INSTALL_MESSAGE)
                return False
        except Exception as e:
            logger.error("Error checking installation: %s", e)
            return False
