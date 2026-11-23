"""
Wazuh Indexer client: reads alerts and indexes anomalies.

Alert search pages through the whole result with a point-in-time and ``search_after``, so
long training lookbacks are read completely instead of being cut at one page.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence
from uuid import uuid4

from opensearchpy.exceptions import ConflictError

from sonar.config import WazuhIndexerConfig
from sonar.indexer import build_opensearch_client, json_safe
from sonar.paths import sonar_home

logger = logging.getLogger(__name__)

# Hits per page; OpenSearch's default index.max_result_window is 10000.
PAGE_SIZE = 10_000
# How long the indexer keeps the point-in-time between two pages.
PIT_KEEP_ALIVE = "2m"
# Newest first, so that a search cut off at max_alerts keeps the most recent alerts. The
# alert's keyword `id` ("<epoch>.<offset>", unique per manager) breaks ties between alerts
# with the same timestamp, so search_after never skips or repeats one.
ALERT_SORT = [
    {"timestamp": {"order": "desc"}},
    {"id": {"order": "desc", "unmapped_type": "keyword"}},
]


class WazuhIndexerClient:
    """Client for Wazuh Indexer (OpenSearch) API operations."""

    def __init__(self, cfg: WazuhIndexerConfig, *, print_payloads: bool = False, dry_run: bool = False, payload_dir: Optional[str] = None):
        """
        Initialize Wazuh Indexer client.

        Args:
            cfg: WazuhIndexerConfig instance with connection details.
            print_payloads: Print and save every anomaly payload before sending it.
            dry_run: Save anomaly payloads instead of sending them.
            payload_dir: Directory for saved payloads (default ``./payloads``).
        """
        self.cfg = cfg
        self.client = build_opensearch_client(cfg)
        self.max_alerts = int(getattr(cfg, "max_alerts", 2_000_000))
        # Debug / integration options
        self.print_payloads = bool(print_payloads)
        self.dry_run = bool(dry_run)
        self.payload_dir = payload_dir or str(sonar_home() / "payloads")
        if self.dry_run or self.print_payloads:
            try:
                os.makedirs(self.payload_dir, exist_ok=True)
            except OSError as e:
                logger.warning("Could not create payload_dir '%s': %s", self.payload_dir, e)

    def search_alerts(
        self,
        start: datetime,
        end: datetime,
        query: Optional[Dict[str, Any]] = None,
        source_fields: Optional[Sequence[str]] = None,
        page_size: int = PAGE_SIZE,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve every alert in ``[start, end)`` from ``alerts_index_pattern``, oldest first.

        Pages through a point-in-time with ``search_after``, which is closed afterwards even
        on error. Stops at ``max_alerts``, keeping the most recent alerts, with a warning.

        Args:
            start: Start datetime (UTC), inclusive.
            end: End datetime (UTC), exclusive.
            query: Optional additional query, added to ``bool.must`` (e.g. ``alert_filter``).
                Alerts in ``exclude_rule_groups`` are always left out (``bool.must_not``).
            source_fields: Alert fields to return; None returns whole alerts.
            page_size: Hits per page.

        Returns:
            Alert documents (``_source``), in ascending ``timestamp`` order.

        Raises:
            opensearchpy.exceptions.OpenSearchException: If a request fails.
        """
        bool_block: Dict[str, Any] = {
            "filter": [
                {
                    "range": {
                        "timestamp": {
                            "gte": start.isoformat(),
                            # end is exclusive: it is the start of the first bucket not analysed
                            "lt": end.isoformat(),
                        }
                    }
                }
            ]
        }
        if query:
            bool_block["must"] = [query]
        excluded = list(getattr(self.cfg, "exclude_rule_groups", None) or [])
        if excluded:
            # SONAR's own alerts (rule group "sonar") must never become training or detection input.
            bool_block["must_not"] = [{"terms": {"rule.groups": excluded}}]

        pit_id = self.client.create_pit(index=self.cfg.alerts_index_pattern, params={"keep_alive": PIT_KEEP_ALIVE})["pit_id"]
        alerts: List[Dict[str, Any]] = []
        total = None
        try:
            search_after = None
            while len(alerts) < self.max_alerts:
                body: Dict[str, Any] = {
                    "size": min(page_size, self.max_alerts - len(alerts)),
                    "query": {"bool": bool_block},
                    "sort": ALERT_SORT,
                    "pit": {"id": pit_id, "keep_alive": PIT_KEEP_ALIVE},
                    # Count the matches once, on the first page.
                    "track_total_hits": total is None,
                }
                if source_fields is not None:
                    body["_source"] = list(source_fields)
                if search_after is not None:
                    body["search_after"] = search_after
                resp = self.client.search(body=body)
                pit_id = resp.get("pit_id", pit_id)
                hits = resp.get("hits", {})
                if total is None:
                    total = _total_hits(hits)
                page = hits.get("hits", [])
                alerts.extend(h.get("_source", {}) for h in page)
                if len(page) < body["size"]:
                    break
                search_after = page[-1]["sort"]
        finally:
            try:
                self.client.delete_pit(body={"pit_id": [pit_id]})
            except Exception as e:  # the point-in-time expires on its own after PIT_KEEP_ALIVE
                logger.warning("Could not close the alert search point-in-time: %s", e)

        if total is not None and total > len(alerts) and len(alerts) >= self.max_alerts:
            logger.warning(
                "The alert search matched %d alerts; only the %d most recent were fetched (wazuh.max_alerts). Shorten the lookback or raise max_alerts.",
                total,
                len(alerts),
            )
        else:
            logger.info("Fetched %d of %s matching alerts.", len(alerts), total if total is not None else "?")
        alerts.reverse()
        return alerts

    def search_detector_results(
        self,
        index: str,
        start: datetime,
        end: datetime,
        entity: Optional[str] = None,
        entity_field: str = "agent.name",
        page_size: int = PAGE_SIZE,
    ) -> List[Dict[str, Any]]:
        """
        Results of the OpenSearch anomaly detection plugin (RADAR's detectors) whose interval starts in ``[start, end)``.

        Reads through a scroll, which needs no sort tiebreaker: results of several entities share
        a ``data_start_time``. The caller orders them (``sonar.evaluation.load_external_detections`` does).

        Args:
            index: Result index or pattern, e.g. ``opensearch-ad-plugin-result-linux-resource-utilization*``.
            start: Start datetime (UTC), inclusive.
            end: End datetime (UTC), exclusive.
            entity: Keep only the results of this entity (a high-cardinality detector's category value).
            entity_field: The detector's category field.
            page_size: Hits per scroll page.

        Returns:
            Result documents (``_source``), at most ``max_alerts``.

        Raises:
            opensearchpy.exceptions.OpenSearchException: If a request fails.
        """
        filters: List[Dict[str, Any]] = [{"range": {"data_start_time": {"gte": start.isoformat(), "lt": end.isoformat()}}}]
        if entity is not None:
            # The plugin stores the category values as a nested list of {name, value}.
            entity_match = {"bool": {"filter": [{"term": {"entity.name": entity_field}}, {"term": {"entity.value": entity}}]}}
            filters.append({"nested": {"path": "entity", "query": entity_match}})
        body = {"size": page_size, "query": {"bool": {"filter": filters}}}
        resp = self.client.search(index=index, body=body, params={"scroll": PIT_KEEP_ALIVE, "ignore_unavailable": "true"})
        results: List[Dict[str, Any]] = []
        scroll_id = resp.get("_scroll_id")
        try:
            while True:
                page = resp.get("hits", {}).get("hits", [])
                results.extend(h.get("_source", {}) for h in page)
                if not page or not scroll_id or len(results) >= self.max_alerts:
                    break
                resp = self.client.scroll(body={"scroll_id": scroll_id, "scroll": PIT_KEEP_ALIVE})
                scroll_id = resp.get("_scroll_id", scroll_id)
        finally:
            if scroll_id:
                try:
                    self.client.clear_scroll(body={"scroll_id": scroll_id})
                except Exception as e:  # the scroll expires on its own; a failed clear must not hide the results
                    logger.debug("Could not clear the scroll: %s", e)
        if len(results) >= self.max_alerts:
            logger.warning("Kept the first %d detector results (wazuh.max_alerts); shorten the window.", self.max_alerts)
            results = results[: self.max_alerts]
        logger.info("Fetched %d detector results from %s.", len(results), index)
        return results

    def index_anomaly(self, doc: Dict[str, Any]) -> str:
        """
        Index an anomaly document in a dedicated index.

        A document with an ``anomaly_id`` is created under that id and never overwritten:
        if the index already holds it (HTTP 409), it was delivered before, which counts as
        success.

        Args:
            doc: Anomaly document to index.

        Returns:
            Document ID of the indexed anomaly.

        Raises:
            opensearchpy.exceptions.OpenSearchException: If the request fails.
        """
        doc_id = doc.get("anomaly_id")
        body = json_safe(doc)
        if self.print_payloads or self.dry_run:
            self._save_payload(doc_id, body)
        if self.dry_run:
            return f"dryrun-{doc_id or int(datetime.now().timestamp())}"

        index = self.cfg.anomalies_index
        if not doc_id:
            return self.client.index(index=index, body=body).get("_id", "")
        try:
            return self.client.create(index=index, id=doc_id, body=body).get("_id", doc_id)
        except ConflictError:
            logger.debug("Anomaly %s is already indexed; not writing it again.", doc_id)
            return doc_id

    def _save_payload(self, doc_id: Optional[str], body: Dict[str, Any]) -> None:
        """Write (and with print_payloads, print) an anomaly payload for inspection."""
        payload = json.dumps(body)
        fname = f"anomaly_{doc_id}.json" if doc_id else f"anomaly_{int(datetime.now().timestamp())}_{uuid4().hex}.json"
        path = os.path.join(self.payload_dir, fname)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(payload)
            logger.info("Wrote anomaly payload to %s", path)
        except OSError as e:
            logger.warning("Failed to write anomaly payload: %s", e)
        if self.print_payloads:
            print(payload)

    def check_connection(self) -> bool:
        """
        Check if connection to Wazuh Indexer is active.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            return bool(self.client.ping())
        except Exception as e:
            logger.debug("Indexer ping failed: %s", e)
            return False


def _total_hits(hits: Dict[str, Any]) -> Optional[int]:
    """``hits.total`` as a number (OpenSearch returns ``{"value": n, "relation": ...}``)."""
    total = hits.get("total")
    if isinstance(total, dict):
        return int(total.get("value", 0))
    return int(total) if total is not None else None
