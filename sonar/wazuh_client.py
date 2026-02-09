"""
Wazuh Indexer client for ingesting alerts and indexing anomalies.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
import json

import requests

from sonar.config import WazuhIndexerConfig
import logging

logger = logging.getLogger(__name__)


class WazuhIndexerClient:
    """Client for Wazuh Indexer (OpenSearch) API operations."""
    def __init__(self, cfg: WazuhIndexerConfig, *, print_payloads: bool = False, dry_run: bool = False, payload_dir: Optional[str] = None):
        """
        Initialize Wazuh Indexer client.

        Args:
            cfg: WazuhIndexerConfig instance with connection details.
        """
        self.cfg = cfg
        self.session = requests.Session()
        self.session.auth = (cfg.username, cfg.password)
        self.session.verify = cfg.verify_ssl
        # Debug / integration options
        self.print_payloads = bool(print_payloads)
        self.dry_run = bool(dry_run)
        self.payload_dir = payload_dir or "./payloads"
        if self.dry_run or self.print_payloads:
            try:
                import os

                os.makedirs(self.payload_dir, exist_ok=True)
            except Exception as e:
                logger.warning("Could not create payload_dir '%s': %s", self.payload_dir, e)

    def search_alerts(
        self,
        start: datetime,
        end: datetime,
        query: Optional[Dict[str, Any]] = None,
        size: int = 10_000,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve alerts from wazuh-alerts-* indices via Wazuh indexer (OpenSearch) API.

        Args:
            start: Start datetime (UTC).
            end: End datetime (UTC).
            query: Optional additional query filter.
            size: Maximum number of documents to retrieve.

        Returns:
            List of alert documents (source only).

        Raises:
            requests.HTTPError: If the API request fails.
        """
        base_query: Dict[str, Any] = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": start.isoformat(),
                                    "lte": end.isoformat(),
                                }
                            }
                        }
                    ]
                }
            },
            "size": size,
        }

        if query:
            # Merge user query into bool.must
            bool_block = base_query["query"]["bool"]
            bool_block.setdefault("must", [])
            bool_block["must"].append(query)

        url = f"{self.cfg.base_url}/{self.cfg.alerts_index_pattern}/_search"
        resp = self.session.post(url, json=base_query)
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        return [h["_source"] for h in hits]

    def index_anomaly(self, doc: Dict[str, Any]) -> str:
        """
        Index an anomaly document in a dedicated index.

        Args:
            doc: Anomaly document to index.

        Returns:
            Document ID of the indexed anomaly.

        Raises:
            requests.HTTPError: If the API request fails.
        """
        url = f"{self.cfg.base_url}/{self.cfg.anomalies_index}/_doc"
        # Ensure all datetime-like objects are serialized (pandas.Timestamp, numpy types, etc.)
        try:
            payload = json.dumps(doc, default=str)
        except Exception:
            # Fallback: convert to strings aggressively
            payload = json.dumps(doc, default=lambda o: str(o))
        # If configured to print/save payloads, do so before sending
        if self.print_payloads or self.dry_run:
            try:
                import os
                from uuid import uuid4
                fname = f"anomaly_{int(datetime.now().timestamp())}_{uuid4().hex}.json"
                path = os.path.join(self.payload_dir, fname)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(payload)
                logger.info("Wrote anomaly payload to %s", path)
                if self.print_payloads:
                    print(payload)
            except Exception as e:
                logger.warning("Failed to write anomaly payload: %s", e)

        if self.dry_run:
            return f"dryrun-{int(datetime.now().timestamp())}"

        resp = self.session.post(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            # Log response body for easier debugging (caller will catch/log)
            logger.warning("Failed to index anomaly: %s", getattr(resp, "text", ""))
            raise
        return resp.json().get("_id", "")

    def index_alert(self, doc: Dict[str, Any]) -> str:
        """
        Index a synthetic alert into the alerts indices pattern.

        Useful for populating test or synthetic data when not enough historical
        data is available for training.

        Args:
            doc: Alert document to index.

        Returns:
            Document ID of the indexed alert.

        Raises:
            requests.HTTPError: If the API request fails.
        """
        # If the configured alerts index pattern contains a wildcard, try to
        # resolve it to a concrete index via the cluster's aliases API or _cat/indices.
        index_name = self.cfg.alerts_index_pattern
        if "*" in index_name:
            try:
                # Prefer resolving via aliases API which can indicate a write index
                alias_url = f"{self.cfg.base_url}/_alias/{self.cfg.alerts_index_pattern}"
                r = self.session.get(alias_url)
                r.raise_for_status()
                aliases_info = r.json()
                if isinstance(aliases_info, dict) and len(aliases_info) > 0:
                    # Choose an index that has an alias matching the pattern; prefer write index metadata
                    chosen = None
                    for idx_name, meta in aliases_info.items():
                        # meta.get('aliases') is a dict of alias names -> props
                        aliases = meta.get("aliases", {})
                        if aliases:
                            # If any alias has 'is_write_index' True, prefer this index
                            for a_name, a_props in aliases.items():
                                if isinstance(a_props, dict) and a_props.get("is_write_index"):
                                    chosen = idx_name
                                    break
                            if chosen:
                                break
                    if not chosen:
                        # fallback to first index name
                        chosen = next(iter(aliases_info.keys()))
                    index_name = chosen
                    logger.info("Resolved alerts index pattern (aliases) '%s' -> '%s'", self.cfg.alerts_index_pattern, index_name)
                else:
                    # Fallback to _cat/indices
                    cat_url = f"{self.cfg.base_url}/_cat/indices/{self.cfg.alerts_index_pattern}?format=json"
                    r2 = self.session.get(cat_url)
                    r2.raise_for_status()
                    indices = r2.json()
                    if isinstance(indices, list) and len(indices) > 0 and "index" in indices[0]:
                        index_name = indices[0]["index"]
                        logger.info("Resolved alerts index pattern '%s' -> '%s' via _cat/indices", self.cfg.alerts_index_pattern, index_name)
                    else:
                        index_name = index_name.replace("*", "") or self.cfg.alerts_index_pattern
                        logger.warning("Could not resolve concrete index for pattern '%s'; falling back to '%s'", self.cfg.alerts_index_pattern, index_name)
            except Exception as e:
                logger.warning("Failed to resolve index pattern '%s': %s", self.cfg.alerts_index_pattern, e)
                index_name = index_name.replace("*", "") or self.cfg.alerts_index_pattern

        url = f"{self.cfg.base_url}/{index_name}/_doc"
        try:
            payload = json.dumps(doc, default=str)
        except Exception:
            payload = json.dumps(doc, default=lambda o: str(o))

        # If configured to print/save payloads, do so before sending
        if self.print_payloads or self.dry_run:
            try:
                import os
                from uuid import uuid4
                fname = f"alert_{int(datetime.now().timestamp())}_{uuid4().hex}.json"
                path = os.path.join(self.payload_dir, fname)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(payload)
                logger.info("Wrote alert payload to %s", path)
                if self.print_payloads:
                    print(payload)
            except Exception as e:
                logger.warning("Failed to write alert payload: %s", e)

        if self.dry_run:
            return f"dryrun-{int(datetime.now().timestamp())}"

        resp = self.session.post(url, data=payload, headers={"Content-Type": "application/json"})
        try:
            resp.raise_for_status()
        except requests.HTTPError as e:
            body = getattr(resp, "text", "")
            logger.warning("Indexing alert failed (status=%s): %s", getattr(resp, "status_code", "?"), body)
            e.response_text = body
            raise
        return resp.json().get("_id", "")

    def check_connection(self) -> bool:
        """
        Check if connection to Wazuh Indexer is active.

        Returns:
            True if connection successful, False otherwise.
        """
        try:
            url = f"{self.cfg.base_url}/"
            resp = self.session.get(url, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
