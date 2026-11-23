"""
SONAR Wazuh Data Shipper - Ship MVAD anomaly results to Wazuh Indexer.

This module implements data stream creation and document shipping for SONAR
anomaly detection results to be indexed in Wazuh (OpenSearch).
"""

import json
import logging
from typing import List, Optional, Tuple

from opensearchpy.exceptions import ConflictError, OpenSearchException

from sonar.config import WazuhIndexerConfig
from sonar.indexer import build_opensearch_client, json_safe
from sonar.shipper import DataShipper
from sonar.shipper.wazuh_base_template import (
    BASE_TEMPLATE_KEYS,
    COMPOSED_OF,
    INDEX_PATTERNS,
    MVAD_COMPONENT,
    MVAD_COMPONENT_NAME,
    PRIORITY,
    SCENARIO_TEMPLATE_PRIORITY,
    SONAR_ANOMALY_PATTERN,
    SONAR_BASE_TEMPLATE,
    SONAR_BASE_TEMPLATE_NAME,
)

logger = logging.getLogger(__name__)

# Bulk actions
CREATE = "create"
DELETE = "delete"
INDEX = "index"
UPDATE = "update"


ISM_POLICY_NAME = "sonar_anomalies_policy"


def ism_policy(rollover_days: int = 7, retention_days: int = 30) -> dict:
    """ISM policy body for SONAR data streams: roll over, then delete after the retention period."""
    return {
        "policy": {
            "description": "SONAR anomaly data streams: rollover and retention",
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [{"rollover": {"min_index_age": f"{int(rollover_days)}d"}}],
                    "transitions": [{"state_name": "delete", "conditions": {"min_index_age": f"{int(retention_days)}d"}}],
                },
                {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
            ],
            "ism_template": [{"index_patterns": [f".ds-{SONAR_ANOMALY_PATTERN}_*"], "priority": 100}],
        }
    }


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

    def add_component(self, component_name: str):
        """
        Add a component to the template.

        Args:
            component_name: Name of the component to add.
        """
        self.body[COMPOSED_OF] = self.body[COMPOSED_OF] + [component_name]
        self.body[PRIORITY] += 1


class WazuhDataShipper(DataShipper):
    """Wazuh Indexer data shipper for SONAR anomaly results."""

    def __init__(self, config: WazuhIndexerConfig, install: bool = False, rollover_days: int = 7, retention_days: int = 30):
        """
        Initialize Wazuh data shipper.

        Args:
            config: WazuhIndexerConfig instance with connection details.
            install: If True, install the templates and the ISM policy on initialization.
            rollover_days, retention_days: Settings of the ISM policy installed with the templates.
        """
        super().__init__(config)
        self.rollover_days = int(rollover_days)
        self.retention_days = int(retention_days)
        self.base_template_pattern = SONAR_ANOMALY_PATTERN
        self.map_scenario_templates = {}

        logger.info("SONAR Shipper establishing connection to Wazuh Indexer...")
        self.client = build_opensearch_client(config)

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
        self.add_rollover_policy(rollover_days=self.rollover_days, retention_days=self.retention_days)

    def ship_single(self, stream_name: str, document: dict) -> dict:
        """
        Ship a single document to a data stream.

        A document with an ``anomaly_id`` is created under that id (data streams only accept
        creates); if the stream already holds it (HTTP 409), it was shipped before, which counts
        as success.

        Args:
            stream_name: Name of the data stream.
            document: Document to index.

        Returns:
            Response from OpenSearch.
        """
        doc_id = document.get("anomaly_id")
        try:
            # Clean NaN values to prevent JSON parsing errors
            cleaned_document = json_safe(document)
            if doc_id:
                response = self.client.create(index=stream_name, id=doc_id, body=cleaned_document)
            else:
                response = self.client.index(index=stream_name, body=cleaned_document)
            logger.debug("Shipped document to %s: %s", stream_name, response)
            return response
        except ConflictError:
            logger.debug("Anomaly %s is already in %s; not shipping it again.", doc_id, stream_name)
            return {"_id": doc_id, "result": "exists"}
        except OpenSearchException as e:
            logger.error("Error shipping document to %s: %s", stream_name, e)
            raise

    def create_documents(self, stream_name: str, documents: List[dict]) -> Tuple[int, Optional[str]]:
        """
        Create documents in a data stream with one bulk request, each under its ``anomaly_id``.

        A document the stream already holds (HTTP 409) was shipped before and counts as accepted.

        Returns:
            ``(accepted, error)``: how many documents, from the first one on, were accepted
            before the first failure, and that failure (None if all were accepted).
        """
        response = self.ship_bulk(self.get_bulk_request(documents, stream_name, [CREATE] * len(documents)))
        for i, item in enumerate(response.get("items", [])):
            result = item.get(CREATE) or next(iter(item.values()), {})
            if result.get("status") not in (200, 201, 409):
                return i, f"{result.get('status')}: {result.get('error')}"
        return len(documents), None

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
            if doc.get("anomaly_id"):
                action_meta[action]["_id"] = doc["anomaly_id"]
            lines.append(json.dumps(action_meta))
            # Clean NaN values before serializing
            cleaned_doc = json_safe(doc)
            lines.append(json.dumps(cleaned_doc))
        return "\n".join(lines) + "\n"

    def add_mvad_template(self):
        """Add MVAD component template if it doesn't exist."""
        try:
            # Check if component template exists
            # Always (re)install the component: put is idempotent, and it updates clusters that
            # still carry an older mapping. New mappings apply to the next backing index.
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

    def create_scenario_stream(self, scenario_id: str, scenario_name: str) -> str:
        """
        Create the index template of a scenario's data stream.

        The stream itself is created by the first document shipped to it.

        Args:
            scenario_id: Unique scenario identifier.
            scenario_name: Human-readable scenario name.

        Returns:
            Name of the data stream.
        """
        template_name, pattern = get_template_name_and_pattern(scenario_id)
        # Its pattern is the exact stream name that detection ships to (sonar_anomalies_mvad_<id>),
        # and its priority must stay above the generic sonar_anomalies_* templates (1 and 2) that
        # the pattern overlaps. The documents are the same for every scenario, so the MVAD
        # component maps all their fields.
        template_handler = self.create_template_handler_from_base([MVAD_COMPONENT_NAME])
        template_handler.body[INDEX_PATTERNS] = [pattern]
        template_handler.body[PRIORITY] = max(template_handler.body[PRIORITY], SCENARIO_TEMPLATE_PRIORITY)
        template_handler.body["_meta"] = {**template_handler.body.get("_meta", {}), "scenario_name": scenario_name}

        try:
            logger.info("Creating scenario index template: %s", template_name)
            self.client.indices.put_index_template(name=template_name, body=template_handler.body)
            self.map_scenario_templates[scenario_id] = (template_name, pattern)
            logger.info("Scenario stream ready: %s", pattern)
            return pattern
        except Exception as e:
            logger.error("Error creating scenario stream: %s", e)
            raise

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

    def add_rollover_policy(self, policy_name: str = ISM_POLICY_NAME, rollover_days: int = 7, retention_days: int = 30):
        """
        Install the ISM policy for SONAR data streams, unless it exists.

        Its ``ism_template`` attaches it to every new backing index of a ``sonar_anomalies_*``
        stream (``.ds-sonar_anomalies_*``), so no index needs to be configured by hand. The write
        index rolls over after ``rollover_days``; backing indices are deleted after
        ``retention_days``. An existing policy is left unchanged (edit or delete it to change it).

        Args:
            policy_name: Name of the policy.
            rollover_days: Age at which the write index rolls over.
            retention_days: Age at which a backing index is deleted.
        """
        policy_body = ism_policy(rollover_days, retention_days)
        try:
            response = self.client.transport.perform_request("PUT", f"/_plugins/_ism/policies/{policy_name}", body=policy_body)
            logger.info("ISM policy %s installed (rollover %dd, retention %dd)", policy_name, rollover_days, retention_days)
            return response
        except ConflictError:
            logger.info("ISM policy %s already exists; left unchanged.", policy_name)
            return None

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
