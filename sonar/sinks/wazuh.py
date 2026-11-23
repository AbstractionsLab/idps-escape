"""
The ``wazuh`` sink: anomalies as events for the Wazuh manager, which decodes them, matches
SONAR's rules (``sonar/wazuh/rules/sonar_rules.xml``) and raises alerts that rules, active
responses and integrations (RADAR) can act on.

SONAR never runs on monitored endpoints, so no Wazuh agent is involved. Two transports:

- ``file``: SONAR runs on the manager host (or in a container sharing a volume with it) and
  appends one JSON line per anomaly to a file the manager reads with
  ``<localfile><log_format>json</log_format>``.
- ``api``: SONAR runs on a dedicated machine and posts the events to the Wazuh server API
  (``POST /events``, Wazuh 4.6 and later).

Self-contained on purpose: SONAR must not import RADAR's Wazuh API client.
"""

import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import requests

from sonar.config import WazuhSinkConfig
from sonar.sinks.base import DeliveryResult
from sonar.sinks.events import event_line, wazuh_event

logger = logging.getLogger(__name__)

PASSWORD_ENV = "SONAR_WAZUH_API_PASSWORD"
# Password of the administrator `sonar wazuh install-rules --user` logs in as.
ADMIN_PASSWORD_ENV = "SONAR_WAZUH_ADMIN_PASSWORD"
# SONAR's Wazuh rules (IDs 100500-100519), installed with `sonar wazuh install-rules`.
RULES_FILE = Path(__file__).resolve().parents[1] / "wazuh" / "rules" / "sonar_rules.xml"
# Wazuh server API reference (4.x), POST /events: at most 100 events per request, and the
# endpoint is rate-limited (HTTP 429 when exceeded). SONAR sends one event per anomalous
# bucket, far below either limit in normal operation.
MAX_EVENTS_PER_REQUEST = 100
# API tokens expire after 900 s by default (auth_token_exp_timeout); renew a little earlier.
TOKEN_TTL_SECONDS = 850


class FileTransport:
    """Append event lines to the file the manager's logcollector reads, rotating it by size."""

    def __init__(self, path: str, max_bytes: int = 10 * 1024 * 1024, backup_count: int = 5):
        self.path = Path(path)
        self.max_bytes = int(max_bytes)
        self.backup_count = int(backup_count)

    def send(self, lines: Sequence[str]) -> Tuple[int, Optional[str]]:
        """Write all lines in one append and flush them; all or nothing."""
        data = "".join(f"{line}\n" for line in lines).encode("utf-8")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                size = self.path.stat().st_size
                if size > 0 and size + len(data) > self.max_bytes:
                    self._rotate()
            with open(self.path, "ab") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as e:
            return 0, f"cannot write {self.path}: {e}"
        return len(lines), None

    def _rotate(self) -> None:
        """anomalies.json -> anomalies.json.1 -> ... -> anomalies.json.<backup_count> (dropped beyond)."""
        if self.backup_count <= 0:
            self.path.unlink()
            return
        for i in range(self.backup_count - 1, 0, -1):
            src = self.path.with_name(f"{self.path.name}.{i}")
            if src.exists():
                os.replace(src, self.path.with_name(f"{self.path.name}.{i + 1}"))
        os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))
        logger.info("Rotated %s", self.path)


class WazuhApiError(Exception):
    """A Wazuh server API request failed."""

    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(f"Wazuh API error (HTTP {status}): {message}")


class WazuhApi:
    """
    Minimal Wazuh server API client: JWT authentication, renewal on 401, backoff on 429.

    Args:
        url: API base URL, e.g. ``https://wazuh.manager:55000``.
        username, password: API user.
        verify: False, True or a CA bundle path (passed to requests).
        timeout: Seconds per request.
        session: requests session (injectable for tests).
        sleep: Sleep function (injectable for tests).
        max_retries: Retries after HTTP 429 before giving up.
    """

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify: Any = False,
        timeout: float = 30.0,
        session: Optional[requests.Session] = None,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = 3,
    ):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = float(timeout)
        self.session = session or requests.Session()
        self.session.verify = verify
        self.sleep = sleep
        self.max_retries = int(max_retries)
        self._token: Optional[str] = None
        self._token_at = 0.0

    def _authenticate(self) -> str:
        try:
            resp = self.session.post(f"{self.url}/security/user/authenticate", auth=(self.username, self.password), timeout=self.timeout)
        except requests.RequestException as e:
            raise WazuhApiError(0, f"cannot reach {self.url}: {e}") from e
        if resp.status_code != 200:
            raise WazuhApiError(resp.status_code, f"authentication of user '{self.username}' failed")
        self._token = resp.json()["data"]["token"]
        self._token_at = time.monotonic()
        return self._token

    def _bearer(self) -> str:
        if self._token is None or time.monotonic() - self._token_at > TOKEN_TTL_SECONDS:
            return self._authenticate()
        return self._token

    def request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Send an authenticated request; raise WazuhApiError unless it ends with a 2xx."""
        extra_headers = kwargs.pop("headers", None) or {}
        reauthenticated = False
        attempt = 0
        while True:
            headers = {**extra_headers, "Authorization": f"Bearer {self._bearer()}"}
            try:
                resp = self.session.request(method, f"{self.url}{path}", headers=headers, timeout=self.timeout, **kwargs)
            except requests.RequestException as e:
                raise WazuhApiError(0, f"cannot reach {self.url}: {e}") from e
            if resp.status_code == 401 and not reauthenticated:
                # The token was revoked or expired early: get a new one, once.
                self._token = None
                reauthenticated = True
                continue
            if resp.status_code == 429 and attempt < self.max_retries:
                attempt += 1
                wait = _retry_after(resp) or min(60.0, 2.0**attempt)
                logger.warning("Wazuh API rate limit reached; retrying in %.0f s.", wait)
                self.sleep(wait)
                continue
            if 200 <= resp.status_code < 300:
                return resp
            raise WazuhApiError(resp.status_code, _error_detail(resp))


def _retry_after(resp: requests.Response) -> Optional[float]:
    try:
        return float(resp.headers.get("Retry-After"))
    except (TypeError, ValueError):
        return None


def _error_detail(resp: requests.Response) -> str:
    try:
        body = resp.json()
        return str(body.get("detail") or body.get("title") or resp.text)
    except ValueError:
        return resp.text


class ApiTransport:
    """Post event lines to ``POST /events`` in batches of at most MAX_EVENTS_PER_REQUEST."""

    def __init__(self, api: WazuhApi):
        self.api = api

    def send(self, lines: Sequence[str]) -> Tuple[int, Optional[str]]:
        accepted = 0
        for i in range(0, len(lines), MAX_EVENTS_PER_REQUEST):
            chunk = list(lines[i : i + MAX_EVENTS_PER_REQUEST])
            try:
                resp = self.api.request("POST", "/events", json={"events": chunk})
            except WazuhApiError as e:
                return accepted, str(e)
            data = (resp.json() or {}).get("data") or {}
            failed = int(data.get("total_failed_items") or 0)
            if failed:
                return accepted, f"the manager rejected {failed} of {len(chunk)} events: {data.get('failed_items')}"
            accepted += len(chunk)
        return accepted, None


def api_from_config(cfg: WazuhSinkConfig, **kwargs: Any) -> WazuhApi:
    """A WazuhApi for the sink settings; the password falls back to $SONAR_WAZUH_API_PASSWORD."""
    password = cfg.api_password or os.environ.get(PASSWORD_ENV, "")
    if not password:
        logger.warning("No Wazuh API password: set output.wazuh.api_password or %s.", PASSWORD_ENV)
    return WazuhApi(cfg.api_url, cfg.api_username, password, verify=cfg.verify_ssl, timeout=cfg.timeout_seconds, **kwargs)


class WazuhSink:
    """Deliver anomalies to the Wazuh manager as SONAR events."""

    name = "wazuh"

    def __init__(self, cfg: WazuhSinkConfig, transport: Any = None):
        self.cfg = cfg
        if transport is None:
            if cfg.transport == "file":
                transport = FileTransport(cfg.file_path, cfg.max_file_bytes, cfg.backup_count)
            elif cfg.transport == "api":
                transport = ApiTransport(api_from_config(cfg))
            else:
                raise ValueError(f"output.wazuh.transport must be 'file' or 'api'; got '{cfg.transport}'")
        self.transport = transport

    def emit(self, docs: List[Dict[str, Any]]) -> DeliveryResult:
        lines = [event_line(wazuh_event(d, self.cfg.severity_medium, self.cfg.severity_high)) for d in docs]
        accepted, error = self.transport.send(lines)
        return DeliveryResult(accepted, len(docs), error)
