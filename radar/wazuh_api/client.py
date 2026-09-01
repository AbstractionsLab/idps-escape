"""
Wazuh API client.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhAPIError(Exception):
    def __init__(self, status_code: int, error_code: Optional[int], message: str,
                 raw_body: Optional[str] = None):
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.raw_body = raw_body
        super().__init__(f"Wazuh API error (HTTP {status_code}, code {error_code}): {message}")


class WazuhAPIClient:
    def __init__(self, base_url: str, user: str, password: str,
                 verify_ssl: bool = False, timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._token: Optional[str] = None
        self._token_obtained_at: float = 0.0
        # Token expires after 900s by default (auth_token_exp_timeout);
        # refresh a little early to be safe rather than racing the expiry.
        self._token_ttl_seconds = 850

    def _authenticate(self) -> None:
        try:
            resp = self._session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.user, self.password),
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as e:
            raise WazuhAPIError(
                0, None, f"Could not reach the Wazuh API at {self.base_url} ({e.__class__.__name__}): {e}"
            ) from e
        if resp.status_code != 200:
            raise WazuhAPIError(resp.status_code, None, "Authentication failed", resp.text)
        self._token = resp.json()["data"]["token"]
        self._token_obtained_at = time.monotonic()

    def _ensure_token(self) -> str:
        token_age = time.monotonic() - self._token_obtained_at
        if self._token is None or token_age > self._token_ttl_seconds:
            self._authenticate()
        return self._token  # type: ignore[return-value]

    def _request(self, method: str, path: str, *,
                 tolerate_error_codes: Optional[List[int]] = None,
                 _retries_left: int = 2, **kwargs) -> requests.Response:
        tolerate_error_codes = tolerate_error_codes or []
        url = f"{self.base_url}{path}"
        extra_headers = kwargs.pop("headers", None) or {}
        headers = {"Authorization": f"Bearer {self._ensure_token()}", **extra_headers}

        try:
            resp = self._session.request(method, url, headers=headers, timeout=self.timeout, **kwargs)
        except requests.exceptions.RequestException as e:
            raise WazuhAPIError(
                0, None, f"Could not reach the Wazuh API at {self.base_url} ({e.__class__.__name__}): {e}"
            ) from e

        if resp.status_code == 401 and _retries_left > 0:
            # Token may have been invalidated server-side; force a fresh one and retry once.
            self._token = None
            return self._request(method, path, tolerate_error_codes=tolerate_error_codes,
                                  _retries_left=_retries_left - 1, headers=extra_headers, **kwargs)

        if resp.status_code == 429 and _retries_left > 0:
            time.sleep(2)
            return self._request(method, path, tolerate_error_codes=tolerate_error_codes,
                                  _retries_left=_retries_left - 1, headers=extra_headers, **kwargs)

        if 200 <= resp.status_code < 300:
            return resp

        error_code: Optional[int] = None
        message = resp.text
        try:
            body = resp.json()
            error_code = body.get("error")
            message = body.get("detail") or body.get("title") or resp.text
        except ValueError:
            pass  # non-JSON error body -- fall back to raw text

        if error_code in tolerate_error_codes:
            return resp

        raise WazuhAPIError(resp.status_code, error_code, message, resp.text)

    def get(self, path: str, **kwargs) -> requests.Response:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self._request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> requests.Response:
        return self._request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs) -> requests.Response:
        return self._request("DELETE", path, **kwargs)