"""
Sinks that write anomaly documents to the Wazuh Indexer directly, bypassing the manager.

``datastream`` writes to the scenario's data stream (``sonar_anomalies_mvad_<scenario_id>``),
for dashboards and history. ``index`` writes to the plain ``wazuh.anomalies_index``, the
legacy destination. Both store each document under its ``anomaly_id``, create-only, so a
document delivered twice is stored once.
"""

import logging
from typing import Any, Dict, List

from sonar.config import ShippingConfig, WazuhIndexerConfig
from sonar.sinks.base import DeliveryResult

logger = logging.getLogger(__name__)


class DataStreamSink:
    """The scenario's data stream, through one bulk create per batch."""

    name = "datastream"

    def __init__(self, cfg: WazuhIndexerConfig, shipping: ShippingConfig, scenario_id: str):
        self.cfg = cfg
        self.shipping = shipping
        self.scenario_id = scenario_id
        self._shipper = None

    def _stream(self):
        from sonar.shipper.wazuh_data_shipper import WazuhDataShipper, get_template_name_and_pattern

        if self._shipper is None:
            self._shipper = WazuhDataShipper(self.cfg, install=False)
        return get_template_name_and_pattern(self.scenario_id)[1]

    def emit(self, docs: List[Dict[str, Any]]) -> DeliveryResult:
        try:
            stream = self._stream()
            accepted, error = self._shipper.create_documents(stream, docs)
        except Exception as e:  # connection, TLS, authentication: nothing was accepted
            return DeliveryResult(0, len(docs), f"data stream unavailable: {e}")
        if accepted:
            logger.info("Shipped %d anomalies to data stream %s", accepted, stream)
        return DeliveryResult(accepted, len(docs), error)


class IndexSink:
    """The plain anomalies index, one create per document, stopping at the first failure."""

    name = "index"

    def __init__(self, client: Any):
        self.client = client

    def emit(self, docs: List[Dict[str, Any]]) -> DeliveryResult:
        for i, doc in enumerate(docs):
            try:
                self.client.index_anomaly(doc)
            except Exception as e:
                return DeliveryResult(i, len(docs), f"anomalies index: {e}")
        logger.info("Indexed %d anomalies in %s", len(docs), getattr(getattr(self.client, "cfg", None), "anomalies_index", "the anomalies index"))
        return DeliveryResult(len(docs), len(docs))
