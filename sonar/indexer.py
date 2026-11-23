"""
The single way SONAR connects to the Wazuh Indexer (OpenSearch).

Alert search (``sonar/wazuh_client.py``) and anomaly shipping (``sonar/shipper/``) both get
their client here, so TLS, credentials and timeouts behave the same for both.
"""

import json
import math
from typing import Any

from opensearchpy import OpenSearch

from sonar.config import WazuhIndexerConfig


def tls_options(verify_ssl: Any) -> dict:
    """
    Client TLS arguments for ``wazuh.verify_ssl``.

    ``False`` disables certificate checks (the default, for the self-signed lab indexer);
    ``True`` checks against the system trust store; a string is a CA bundle path that
    checks against that CA (for example the Wazuh root CA, ``root-ca.pem``).
    """
    if isinstance(verify_ssl, str) and verify_ssl.strip():
        return {"verify_certs": True, "ca_certs": verify_ssl}
    if verify_ssl is True:
        return {"verify_certs": True}
    return {"verify_certs": False, "ssl_show_warn": False}


def build_opensearch_client(cfg: WazuhIndexerConfig) -> OpenSearch:
    """
    An OpenSearch client for ``cfg``: URL (scheme, host and port), basic auth, TLS and timeout.

    Args:
        cfg: Indexer connection settings.

    Returns:
        A client; no request is made until it is used.
    """
    return OpenSearch(
        hosts=[cfg.base_url.rstrip("/")],
        http_auth=(cfg.username, cfg.password),
        http_compress=True,
        timeout=float(getattr(cfg, "timeout_seconds", 30.0)),
        **tls_options(cfg.verify_ssl),
    )


def json_safe(obj: Any) -> Any:
    """
    A copy of ``obj`` the indexer accepts as JSON.

    Values JSON cannot represent (timestamps, numpy numbers, ...) become strings or plain
    numbers, and NaN or infinity become null: OpenSearch rejects them.
    """
    return _clean_nan(json.loads(json.dumps(obj, default=_default)))


def _default(value: Any) -> Any:
    if hasattr(value, "item") and callable(value.item):  # numpy scalars
        try:
            return value.item()
        except (TypeError, ValueError):
            pass
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _clean_nan(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _clean_nan(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_clean_nan(v) for v in obj]
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        return None
    return obj
