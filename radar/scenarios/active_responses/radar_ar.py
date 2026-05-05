#!/usr/bin/env python3

import sys
import json
import os
import re
import yaml
import smtplib
import ssl
import hashlib
import traceback
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _parse_bool(v, default=False):
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")

def _safe_str(v):
    return "" if v is None else str(v)


def _utc_now():
    return datetime.now(timezone.utc)


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()

def _to_float(v, default=0.0) -> float:
    try:
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str) and v.strip():
            return float(v.strip())
    except Exception:
        return default
    return default


def _parse_iso(ts: str):
    ts = _safe_str(ts).strip()
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        match = re.match(r"^(.*)([+-])(\d{2})(\d{2})$", ts)
        if match:
            ts = f"{match.group(1)}{match.group(2)}{match.group(3)}:{match.group(4)}"
        return datetime.fromisoformat(ts)
    except Exception:
        return None

def _get_tier_boundaries(cfg: dict):
    tiers = cfg.get("tiers") or {}
    t1_min = _to_float(tiers.get("tier1_min"), 0.0)
    t1_max = _to_float(tiers.get("tier1_max"), 0.33)
    t2_max = _to_float(tiers.get("tier2_max"), 0.66)
    if t1_min < 0.0:
        t1_min = 0.0
    if t1_max < t1_min:
        t1_max = t1_min
    if t2_max < t1_max:
        t2_max = t1_max
    if t2_max > 1.0:
        t2_max = 1.0
    if t1_max > 1.0:
        t1_max = 1.0
    return t1_min, t1_max, t2_max


class EnvLoader:
    @staticmethod
    def _strip_inline_comment(s: str) -> str:
        in_single = in_double = False
        for i, ch in enumerate(s):
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "#" and not in_single and not in_double:
                return s[:i].rstrip()
        return s.rstrip()

    @staticmethod
    def load():
        candidates = [
            Path("/var/ossec/active-response/bin/active_responses.env"),
            Path(__file__).with_name("active_responses.env"),
        ]
        env_file = next((p for p in candidates if p.exists()), None)
        if not env_file:
            return
        with env_file.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = EnvLoader._strip_inline_comment(value.strip())
                value = value.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, value)


class Logger:
    def __init__(self, logfile: str):
        self.logfile = logfile

    def log(self, level: str, msg: str, **ctx) -> None:
        ts = _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
        ctx_str = " " + json.dumps(ctx, separators=(",", ":"), ensure_ascii=False) if ctx else ""
        line = f"{ts} [{level}] {msg}{ctx_str}\n"
        try:
            with open(self.logfile, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception:
            sys.stderr.write(line)


class ConfigLoader:
    def __init__(self, logger: Logger, config_path: Path):
        self.logger = logger
        self.config_path = config_path

    def load(self) -> dict:
        if not self.config_path.exists():
            self.logger.log("WARNING", "Config not found", file=str(self.config_path))
            return {"scenarios": {}}
        try:
            with self.config_path.open(encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
            self.logger.log("INFO", "Config loaded", scenarios=list((cfg.get("scenarios") or {}).keys()))
            return cfg
        except Exception as e:
            self.logger.log("ERROR", "Config load failed", error=str(e))
            return {"scenarios": {}}


class WazuhInputHandler:
    def __init__(self, logger: Logger):
        self.logger = logger

    def read_alert(self):
        input_str = ""
        line = sys.stdin.readline()
        if line:
            input_str += line.strip()

        if not input_str.strip():
            self.logger.log("WARNING", "No input received")
            return None

        try:
            dec = json.JSONDecoder()
            wrapper, _ = dec.raw_decode(input_str.lstrip())
            if not isinstance(wrapper, dict):
                self.logger.log("ERROR", "Invalid wrapper format")
                return None

            alert = wrapper.get("parameters", {}).get("alert", {})
            if not alert:
                self.logger.log("ERROR", "No alert in wrapper")
                return None

            self.logger.log("INFO", "Alert parsed", rule_id=(alert.get("rule") or {}).get("id"))
            return alert
        except Exception as e:
            self.logger.log("ERROR", "Failed to parse input", error=str(e))
            return None


class ScenarioIdentifier:
    def __init__(self, logger: Logger, cfg: dict):
        self.logger = logger
        self.scenarios = cfg.get("scenarios") or {}

    def identify(self, alert: dict):
        rule_id = _safe_str((alert.get("rule") or {}).get("id"))
        for scenario_name, scfg in self.scenarios.items():
            ad_rules = [str(x) for x in (((scfg.get("ad") or {}).get("rule_ids")) or [])]
            sig_rules = [str(x) for x in (((scfg.get("signature") or {}).get("rule_ids")) or [])]
            is_ad = rule_id in ad_rules
            is_sig = rule_id in sig_rules
            if not (is_ad or is_sig):
                continue
            detection = "ad" if is_ad and not is_sig else "signature" if is_sig and not is_ad else "hybrid"
            self.logger.log("INFO", "Scenario identified", scenario=scenario_name, detection=detection, rule_id=rule_id)
            return {"name": scenario_name, "detection": detection, "config": scfg, "alert": alert}
        self.logger.log("WARNING", "No scenario matched", rule_id=rule_id)
        return None


class OpenSearchClient:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.url = os.environ.get("OS_URL", "https://localhost:9200").rstrip("/")
        self.user = os.environ.get("OS_USER", "admin")
        self.password = os.environ.get("OS_PASS", "")
        self.verify = _parse_bool(os.environ.get("OS_VERIFY_SSL", "false"), False)
        self.indices = os.environ.get("OS_INDEXES", "wazuh-alerts-*,wazuh-archives-*")

        try:
            import requests
            self._requests = requests
            self._ready = True
            self.logger.log("INFO", "OpenSearch requests client ready", url=self.url, indices=self.indices)
        except Exception as e:
            self._requests = None
            self._ready = False
            self.logger.log("WARNING", "OpenSearch unavailable", error=str(e))

    def search(self, indices: str, body: dict):
        try:
            url = f"{self.url}/{indices}/_search"
            headers = {"Content-Type": "application/json"}
            auth = (self.user, self.password) if self.user else None
            r = self._requests.post(url, headers=headers, data=json.dumps(body), auth=auth, verify=self.verify, timeout=30)
            r.raise_for_status()
            hits = (((r.json() or {}).get("hits") or {}).get("hits") or [])
            return [h.get("_source") or {} for h in hits]
        except Exception as e:
            self.logger.log("ERROR", "OpenSearch query failed", error=str(e))
            return []


class IOCExtractor:
    def __init__(self):
        self.ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self.domain_re = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
        self._file_ext_blocklist = {
            "pid", "py", "pyc", "log", "json", "temp", "sh", "xml",
            "conf", "yaml", "yml", "gz", "tar", "zip", "state", "task",
            "legacy", "cpython-310",
        }
        self.md5_re = re.compile(r"\b[a-fA-F0-9]{32}\b")
        self.sha1_re = re.compile(r"\b[a-fA-F0-9]{40}\b")
        self.sha256_re = re.compile(r"\b[a-fA-F0-9]{64}\b")

    def extract(self, alert: dict, events: list) -> dict:
        out = {
            "ip": set(), "user": set(), "domain": set(),
            "hash": set(), "service": set(),
            "country": set(), "asn": set(), "agent": set(),
        }
        self._extract_from_object(alert, out)
        agent_name = _safe_str((alert.get("agent") or {}).get("name")).strip()
        if agent_name:
            out["agent"].add(agent_name)
        for ev in events:
            self._extract_from_object(ev, out)
        return {k: sorted([x for x in v if _safe_str(x).strip()]) for k, v in out.items()}

    def _extract_from_object(self, obj: dict, out: dict):
        data = obj.get("data") or {}

        for k in ("srcip", "dstip"):
            v = data.get(k) or obj.get(k)
            if v:
                out["ip"].add(_safe_str(v))

        for k in ("dstuser", "srcuser", "user", "username"):
            v = data.get(k) or obj.get(k)
            if v:
                out["user"].add(_safe_str(v))

        for k in ("service", "app", "program", "program_name", "process", "proc", "command"):
            v = data.get(k) or obj.get(k)
            if v:
                out["service"].add(_safe_str(v))

        country = _safe_str(data.get("radar_country")).strip()
        if country:
            out["country"].add(country)
        asn = _safe_str(data.get("radar_asn")).strip()
        if asn:
            out["asn"].add(asn)

        for k in ("md5", "sha1", "sha256", "hash", "file_hash"):
            v = _safe_str(data.get(k)).strip()
            if v:
                out["hash"].add(v)

        full_log = _safe_str(obj.get("full_log"))
        if full_log:
            for ip in self.ip_re.findall(full_log):
                out["ip"].add(ip)
            for dom in self.domain_re.findall(full_log):
                if not self.ip_re.fullmatch(dom):
                    tld = dom.rsplit(".", 1)[-1].lower()
                    if tld not in self._file_ext_blocklist and "/" not in dom:
                        out["domain"].add(dom)


class BaseScenario:
    def __init__(self, logger: Logger, os_client: OpenSearchClient):
        self.logger = logger
        self.os = os_client
        self.iocs = IOCExtractor()

    def resolve_time_window(self, scenario: dict):
        alert = scenario["alert"]
        scfg = scenario["config"] or {}
        detection = scenario["detection"] or "signature"

        delta_ad = int(scfg.get("delta_ad_minutes", "10"))
        delta_sig = int(scfg.get("delta_signature_minutes", "1"))

        t_end = _parse_iso(alert.get("timestamp"))
        if not t_end:
            return None, None

        if detection == "ad":
            t_start = t_end - timedelta(minutes=delta_ad)
        else:
            t_start = t_end - timedelta(minutes=delta_sig)

        return t_start, t_end

    def resolve_effective_agent_name(self, scenario: dict, context_events: list):
        detection = _safe_str(scenario.get("detection")).strip()
        if detection != "ad":
            alert_agent = _safe_str((scenario["alert"].get("agent")).get("name")).strip()
            return alert_agent
        return None

    def build_filters(self, t_start: datetime, t_end: datetime, effective_agent_name: str):
        filters = [{"range": {"@timestamp": {"gte": t_start.isoformat(), "lte": t_end.isoformat()}}}]
        if effective_agent_name:
            filters.append({"term": {"agent.name": effective_agent_name}})
        return filters

    def build_query(self, filters: list):
        return {
            "size": 1000,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}},
        }

    def collect_context(self, scenario: dict):
        alert = scenario["alert"]
        t_start, t_end = self.resolve_time_window(scenario)
        if not t_start or not t_end:
            raise ValueError("Missing/invalid alert timestamp; cannot build context window")

        effective_agent = self.resolve_effective_agent_name(scenario, [])
        events = []
        q = self.build_query(self.build_filters(t_start, t_end, effective_agent))
        events = self.os.search(self.os.indices, q)

        if not events and effective_agent:
            filters_kw = [{"range": {"@timestamp": {"gte": t_start.isoformat(), "lte": t_end.isoformat()}}}, {"term": {"agent.name.keyword": effective_agent}}]
            q2 = self.build_query(filters_kw)
            events = self.os.search(self.os.indices, q2)

        iocs = self.iocs.extract(alert, events)
        resolved_effective_agent = self.resolve_effective_agent_name(scenario, events)
        window = {"start": t_start.isoformat(), "end": t_end.isoformat()}
        self.logger.log("INFO", "Events", events=events, iocs=iocs)
        return {"events": events, "event_count": len(events), "iocs": iocs, "window": window, "effective_agent": resolved_effective_agent}

    def resolve_ad_scores(self, scenario: dict):
        data = scenario["alert"].get("data") or {}
        grade = data.get("anomaly_grade")
        confidence = data.get("anomaly_confidence")

        if grade is None or confidence is None:
            raise ValueError("Missing anomaly_grade/anomaly_confidence for AD detection")

        grade_float = _to_float(grade, None)
        confidence_float = _to_float(confidence, None)

        if grade_float is None or confidence_float is None:
            raise ValueError("Invalid anomaly_grade/anomaly_confidence (not numeric)")

        return grade_float, confidence_float


class GeoipDetection(BaseScenario):
    pass


class SuspiciousLogin(BaseScenario):
    pass


class LogVolume(BaseScenario):
    def resolve_time_window(self, scenario: dict):
        data = scenario["alert"].get("data") or {}
        ps = _parse_iso(data.get("period_start"))
        pe = _parse_iso(data.get("period_end"))
        if ps and pe:
            return ps, pe
        return super().resolve_time_window(scenario)

    def resolve_effective_agent_name(self, scenario: dict, context_events: list) -> str:
        data = scenario["alert"].get("data") or {}
        entity = _safe_str(data.get("entity_keyword")).strip()
        if entity:
            return entity
        return super().resolve_effective_agent_name(scenario, context_events)


class Registry:
    def __init__(self, logger: Logger, os_client: OpenSearchClient):
        self._default = BaseScenario(logger, os_client)
        self._map = {
            "geoip_detection": GeoipDetection(logger, os_client),
            "suspicious_login": SuspiciousLogin(logger, os_client),
            "log_volume": LogVolume(logger, os_client),
            "default": BaseScenario(logger, os_client),
        }

    def get(self, scenario_name: str):
        return self._map.get(scenario_name, self._default)


class DecipherClient:

    ANALYZE_ENDPOINTS = {
        "suspicious_login": "/api/v0.1/analyze/suspicious_login",
    }
    HEALTH_ENDPOINT = "/health"
    INCIDENT_ENDPOINT = "/api/v0.1/incident"
    TIER_PRIORITY = {
        1: "priority-level:low",
        2: "priority-level:medium",
        3: "priority-level:high",
    }

    def __init__(self, logger: Logger):
        self.logger = logger
        self.base_url = os.environ.get("DECIPHER_BASE_URL", "").strip().rstrip("/")
        self.verify_ssl = _parse_bool(os.environ.get("DECIPHER_VERIFY_SSL", "false"), False)
        self.timeout = int(os.environ.get("DECIPHER_TIMEOUT_SEC", "30"))
        self._available: Optional[bool] = None  # None = not yet checked

        try:
            import requests
            self._requests = requests
        except ImportError as e:
            self._requests = None
            self.logger.log("ERROR", "requests library unavailable for DecipherClient", error=str(e))

    def _request(self, method: str, path: str, json_data: dict = None) -> dict:
        if not self._requests:
            raise RuntimeError("requests library not available")
        if not self.base_url:
            raise RuntimeError("DECIPHER_BASE_URL not configured")
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        resp = self._requests.request(
            method=method, url=url, json=json_data,
            headers=headers, timeout=self.timeout, verify=self.verify_ssl,
        )
        resp.raise_for_status()
        return resp.json()

    def health_check(self) -> bool:
        if self._available is not None:
            return self._available
        if not self.base_url:
            self.logger.log("WARNING", "DECIPHER_BASE_URL not set; DECIPHER integration disabled")
            self._available = False
            return False
        try:
            self._request("GET", self.HEALTH_ENDPOINT)
            self.logger.log("INFO", "DECIPHER health check passed", url=self.base_url)
            self._available = True
        except Exception as e:
            self.logger.log(
                "WARNING",
                "DECIPHER unavailable; continuing without CTI enrichment and case creation",
                error=str(e),
            )
            self._available = False
        return self._available

    def analyze(self, scenario_name: str, iocs: dict, alert: dict) -> dict:
        null_result = {
            "ok": False, "cti_score_T": 0.0, "labels": [],
            "misp_events": [],
            "case_id": None, "case_url": None, "raw": None,
        }
        endpoint = self.ANALYZE_ENDPOINTS.get(scenario_name)
        if not endpoint:
            self.logger.log(
                "WARNING",
                "No DECIPHER analyze endpoint defined for scenario; skipping CTI enrichment",
                scenario=scenario_name,
            )
            return null_result

        payload = self._build_analyze_payload(scenario_name, iocs, alert)
        try:
            raw = self._request("POST", endpoint, json_data=payload)
            cti_score_T = _to_float(raw.get("severity"), 0.0)
            report = raw.get("report") or {}
            labels = list(report.get("log_summary") or [])
            misp_events = list(report.get("misp_events_found") or [])
            created_case = raw.get("created_case") or {}
            case_id = _safe_str(created_case.get("id"))
            case_url = _safe_str(created_case.get("link"))
            self.logger.log(
                "INFO", "DECIPHER analyze completed",
                scenario=scenario_name, cti_score_T=cti_score_T,
                case_id=case_id, case_url=case_url,
            )
            return {
                "ok": True, "cti_score_T": cti_score_T, "labels": labels,
                "misp_events": misp_events,
                "case_id": case_id, "case_url": case_url, "raw": raw,
            }
        except Exception as e:
            self.logger.log(
                "ERROR", "DECIPHER analyze failed; using T=0.0, no case created",
                scenario=scenario_name, error=str(e),
            )
            return null_result

    def _build_analyze_payload(self, scenario_name: str, iocs: dict, alert: dict) -> dict:
        ts = _safe_str(alert.get("timestamp"))
        target_host = _safe_str((alert.get("agent") or {}).get("name")).strip()

        if scenario_name == "suspicious_login":
            users = iocs.get("user") or []
            return {
                "title":       "RADAR: suspicious login attempts",
                "username":    users[0] if users else None,
                "target_host": target_host,
                "src_ips":     iocs.get("ip") or [],
                "timestamp":   ts,
            }

        return {"target_host": target_host, "timestamp": ts}

    def create_incident(self, decision: dict) -> dict:
        null_result = {"ok": False, "case_id": None, "case_url": None, "raw": None}
        try:
            raw = self._request("POST", self.INCIDENT_ENDPOINT, json_data=self._build_incident_payload(decision))
            case_id = _safe_str(raw.get("id"))
            case_url = _safe_str(raw.get("link"))
            self.logger.log("INFO", "DECIPHER incident created", case_id=case_id, case_url=case_url)
            return {"ok": True, "case_id": case_id, "case_url": case_url, "raw": raw}
        except Exception as e:
            self.logger.log("ERROR", "DECIPHER incident creation failed", error=str(e))
            return null_result

    def _build_incident_payload(self, decision: dict) -> dict:
        scenario = decision["scenario"]
        alert = scenario["alert"]
        risk = decision["risk"]
        ctx = decision["context"]
        cti = decision["cti"]
        rule = alert.get("rule") or {}
        agent = alert.get("agent") or {}
        components = risk.get("components") or {}
        iocs = ctx.get("iocs") or {}

        tier = int(risk["tier"])
        priority_level = self.TIER_PRIORITY.get(tier, "priority-level:low")

        return {
            "priority_level": priority_level,
            "title": self._incident_title(scenario["name"]),
            "template_id": scenario["name"],
            "description": {
                "source": "RADAR",
                "decision_id": _safe_str(decision.get("decision_id")),
                "timestamp": _safe_str(alert.get("timestamp")),
                "scenario": {
                    "name": scenario["name"],
                    "detection_type": scenario["detection"],
                },
                "agent": {
                    "id": _safe_str(agent.get("id")),
                    "name": _safe_str(agent.get("name")),
                },
                "alert": {
                    "id": _safe_str(alert.get("id")),
                    "rule_id": _safe_str(rule.get("id")),
                    "rule_level": int(rule.get("level") or 0),
                    "rule_description": _safe_str(rule.get("description")),
                    "rule_groups": list(rule.get("groups") or []),
                },
                "risk": {
                    "score": round(risk["risk_score"], 6),
                    "tier": tier,
                    "components": {
                        "anomaly_component": components.get("anomaly_component", 0.0),
                        "anomaly_intensity_A": components.get("anomaly_intensity_A", 0.0),
                        "anomaly_grade_G": components.get("anomaly_grade", 0.0) or 0.0,
                        "anomaly_confidence_C": components.get("anomaly_confidence", 0.0) or 0.0,
                        "signature_component": components.get("signature_component", 0.0),
                        "signature_risk_S": components.get("signature_risk_S", 0.0),
                        "signature_likelihood_L": components.get("signature_likelihood", 0.0),
                        "signature_impact_I": components.get("signature_impact", 0.0),
                        "cti_component": components.get("cti_component", 0.0),
                        "cti_score_T": components.get("cti_score_T", 0.0),
                    },
                },
                "misp_events": list(cti.get("misp_events") or []),
                "iocs": {
                    "ip": list(iocs.get("ip") or []),
                    "user": list(iocs.get("user") or []),
                    "domain": list(iocs.get("domain") or []),
                    "hash": list(iocs.get("hash") or []),
                    "service": list(iocs.get("service") or []),
                    "asn": list(iocs.get("asn") or []),
                    "country": list(iocs.get("country") or []),
                    "agent": list(iocs.get("agent") or []),
                },
            },
        }

    def _incident_title(self, scenario_name: str) -> str:
        titles = {
            "suspicious_login": "RADAR: suspicious login attempts",
            "geoip_detection": "RADAR: suspicious geographic access",
            "log_volume": "RADAR: abnormal log volume",
            "default": "RADAR: security incident detected",
        }
        return titles.get(scenario_name, f"RADAR: {scenario_name}")


class RiskEngine:
    def __init__(self, logger: Logger):
        self.logger = logger

    def _signature_likelihood(self, cfg: dict, alert: dict) -> float:
        """Extract likelihood from config (scalar or rule-based list)."""
        likelihood_cfg = cfg.get("signature_likelihood", 0.0)

        if isinstance(likelihood_cfg, (int, float)):
            return _to_float(likelihood_cfg, 0.0)

        rule_id = _safe_str((alert.get("rule") or {}).get("id")).strip()
        if not rule_id:
            return 0.0

        if isinstance(likelihood_cfg, list):
            for item in likelihood_cfg:
                if not isinstance(item, dict):
                    continue
                rule_ids = item.get("rule_id")
                if isinstance(rule_ids, list):
                    rule_ids = [_safe_str(x).strip() for x in rule_ids]
                elif rule_ids is not None:
                    rule_ids = [_safe_str(rule_ids).strip()]
                else:
                    rule_ids = []

                if rule_id in rule_ids:
                    return _to_float(item.get("weight"), 0.0)

        return 0.0

    def compute(self, scenario: dict, cti_score_T: float, ad_grade: Optional[float], ad_conf: Optional[float]) -> dict:
        cfg = scenario.get("config")
        alert = scenario.get("alert")

        w_ad = _to_float(cfg.get("w_ad"), 0.0)
        w_sig = _to_float(cfg.get("w_sig"), 0.0)
        w_cti = _to_float(cfg.get("w_cti"), 0.0)

        # Compute A (anomaly intensity): A = G x C
        if ad_grade is not None and ad_conf is not None:
            A = ad_grade * ad_conf
            ad_component = A * w_ad
        else:
            A = 0.0
            ad_component = 0.0

        # Compute S (signature risk): S = L x I
        likelihood = self._signature_likelihood(cfg, alert)
        impact = _to_float(cfg.get("signature_impact"), 0.0)
        S = likelihood * impact
        sig_component = S * w_sig

        # Compute T (CTI score): T from DECIPHER analyze endpoint
        T = max(0.0, min(1.0, _to_float(cti_score_T, 0.0)))
        cti_component = T * w_cti

        # Final risk score: R = w_A x A + w_S x S + w_T x T
        risk_0_1 = max(0.0, min(1.0, ad_component + sig_component + cti_component))

        # Determine tier
        t1_min, t1_max, t2_max = _get_tier_boundaries(cfg)
        if risk_0_1 < t1_min:
            tier = 0
        elif risk_0_1 < t1_max:
            tier = 1
        elif risk_0_1 < t2_max:
            tier = 2
        else:
            tier = 3

        components = {
            "anomaly_component": round(ad_component, 6),
            "anomaly_intensity_A": round(A, 6),
            "anomaly_grade": None if ad_grade is None else round(ad_grade, 6),
            "anomaly_confidence": None if ad_conf  is None else round(ad_conf,  6),
            "signature_component": round(sig_component, 6),
            "signature_risk_S": round(S, 6),
            "signature_likelihood": round(likelihood, 6),
            "signature_impact": round(impact, 6),
            "cti_component": round(cti_component, 6),
            "cti_score_T": round(T, 6),
            "risk_score": round(risk_0_1, 6),
        }

        out = {"risk_score": risk_0_1, "tier": tier, "components": components}
        self.logger.log("INFO", "Risk computed", risk_score=risk_0_1, tier=tier)
        return out


class EmailNotifier:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.host = os.environ.get("SMTP_HOST", "smtp.office365.com")
        self.port = int(os.environ.get("SMTP_PORT", "587"))
        self.user = os.environ.get("SMTP_USER", "")
        self.password = os.environ.get("SMTP_PASS", "")
        self.mail_from = os.environ.get("EMAIL_FROM", self.user)
        self.mail_to = os.environ.get("EMAIL_TO", "")
        self.starttls = _parse_bool(os.environ.get("SMTP_STARTTLS", "yes"), True)

    def send(self, decision: dict) -> bool:
        if not self.user or not self.mail_to:
            self.logger.log("WARNING", "Email not configured")
            return False

        subject = self._build_subject(decision)
        body = self._build_body(decision)

        try:
            msg = MIMEMultipart()
            msg["From"] = self.mail_from
            msg["To"] = self.mail_to
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain", "utf-8"))

            server = smtplib.SMTP(self.host, self.port, timeout=30)
            server.ehlo()
            if self.starttls:
                ctx = ssl.create_default_context()
                server.starttls(context=ctx)
                server.ehlo()
            if self.user and self.password:
                server.login(self.user, self.password)
            server.send_message(msg)
            server.quit()

            self.logger.log("INFO", "Email sent", to=self.mail_to)
            return True
        except Exception as e:
            self.logger.log("ERROR", "Email failed", error=str(e))
            return False

    def _build_subject(self, decision: dict) -> str:
        scenario_name = decision["scenario"]["name"]
        return f"[RADAR] {scenario_name}"

    def _build_body(self, decision: dict) -> str:
        scenario = decision["scenario"]
        alert = scenario["alert"]
        rule = alert.get("rule") or {}
        agent = alert.get("agent") or {}
        risk = decision["risk"]
        ctx = decision["context"]
        cti = decision["cti"]

        lines = [
            f"Scenario: {scenario['name']}",
            f"Detection: {scenario['detection']}",
            "",
            f"Timestamp: {alert.get('timestamp', '')}",
            f"Effective agent: {ctx.get('effective_agent', '')}",
            f"Alert agent: {agent.get('name', '')} (id={agent.get('id', '')})",
            f"Rule: {rule.get('id', '')} - {rule.get('description', '')}",
            f"Level: {rule.get('level', '')}",
            "",
            f"Risk score: {risk['risk_score']}",
            f"Tier: {risk['tier']}",
            f"Threshold: {risk.get('threshold', '')}",
            f"Components: {json.dumps(risk.get('components', {}), ensure_ascii=False)}",
            "",
            f"CTI score (T): {(risk.get('components') or {}).get('cti_score_T', 0.0)}",
            f"CTI labels: {', '.join(cti.get('labels') or [])}",
            "",
            f"Context window: {json.dumps(ctx.get('window', {}), ensure_ascii=False)}",
            f"Context events: {ctx.get('event_count', 0)}",
            f"IOCs: {json.dumps(ctx.get('iocs', {}), ensure_ascii=False)}",
            "",
        ]

        incident = decision.get("incident") or {}
        case_id = _safe_str(incident.get("case_id"))
        case_url = _safe_str(incident.get("case_url"))
        if case_id and case_url:
            lines += [
                f"FlowIntel case: {case_id}",
                f"Case URL: {case_url}",
                "",
            ]

        lines.append(f"Decision id: {decision.get('decision_id', '')}")
        return "\n".join(lines)


class WazuhApiClient:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.base_url = os.environ.get("WAZUH_API_URL", "")
        self.user = os.environ.get("WAZUH_AUTH_USER", "")
        self.password = os.environ.get("WAZUH_AUTH_PASS", "")
        self.verify_ssl = _parse_bool(os.environ.get("WAZUH_VERIFY_SSL", "false"), False)
        self.timeout = int(os.environ.get("WAZUH_TIMEOUT_SEC", "30"))
        self._token = None

        try:
            import requests
            self._requests = requests
        except Exception:
            self._requests = None

    def _authenticate(self):
        if self._token:
            return self._token
        url = f"{self.base_url}/security/user/authenticate"
        params = {"raw": "true"}
        r = self._requests.post(url, auth=(self.user, self.password), params=params, verify=self.verify_ssl, timeout=self.timeout)
        r.raise_for_status()
        token = _safe_str(r.text).strip()
        if not token:
            raise ValueError("Wazuh API token empty")
        self._token = token
        self.logger.log("INFO", "Wazuh API authenticated")
        return token

    def send_active_response(self, agent_id: str, command: str, args: list, alert_data: dict):
        token = self._authenticate()
        url = f"{self.base_url}/active-response"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        params = {"agents_list": agent_id, "wait_for_complete": "true"}
        payload = {"command": command, "arguments": args, "alert": {"data": alert_data}}
        r = self._requests.put(url, headers=headers, params=params, data=json.dumps(payload), verify=self.verify_ssl, timeout=self.timeout)
        r.raise_for_status()
        resp = r.json()
        self.logger.log("INFO", "Wazuh Active Response dispatched", agent_id=agent_id, command=command, args=args)
        return resp

    def get_agent_id_by_name(self, agent_name: str):
        agent_name = _safe_str(agent_name).strip()
        if not agent_name:
            return None

        token = self._authenticate()
        url = f"{self.base_url}/agents"
        headers = {"Authorization": f"Bearer {token}"}
        params = {"search": agent_name}
        r = self._requests.get(url, headers=headers, params=params, verify=self.verify_ssl, timeout=self.timeout)
        r.raise_for_status()

        data = r.json().get("data")
        if isinstance(data, dict) and "affected_items" in data:
            items = data.get("affected_items") or []
        elif isinstance(data, list):
            items = data
        else:
            items = []

        if not items:
            return None

        first = items[0] or {}
        return _safe_str(first.get("id")).strip() or None


class ActionPlanner:
    def __init__(self, logger: Logger):
        self.logger = logger

    def plan(self, decision: dict) -> dict:
        scenario = decision["scenario"]
        risk = decision["risk"]
        scfg = scenario["config"] or {}
        tier = int(risk["tier"])
        allow_mitigation = bool(scfg.get("allow_mitigation", False))

        planned = {"notify_email": tier >= 1, "mitigations": []}

        would_be_mitigations = []
        if tier == 2:
            would_be_mitigations = [str(x) for x in (scfg.get("mitigations_tier2") or [])]
        elif tier == 3:
            would_be_mitigations = [str(x) for x in (scfg.get("mitigations_tier3") or [])]

        if allow_mitigation:
            planned["mitigations"] = would_be_mitigations

        self.logger.log("INFO", "Actions planned", tier=tier, allow_mitigation=allow_mitigation, mitigations=planned["mitigations"], would_be_mitigations=would_be_mitigations)
        return planned


class ActionExecutor:
    def __init__(self, logger: Logger, wazuh_api: WazuhApiClient):
        self.logger = logger
        self.wazuh_api = wazuh_api

    def execute(self, decision: dict, planned: dict) -> dict:
        results = {"mitigations": []}
        for cmd in planned.get("mitigations") or []:
            for res in self._execute_mitigation(decision, cmd):
                results["mitigations"].append(res)
        return results

    def _execute_mitigation(self, decision: dict, command: str) -> list:
        scenario = decision["scenario"]
        alert = scenario["alert"]
        context = decision["context"] or {}
        iocs = context.get("iocs") or {}

        agent_id = self._resolve_agent_id(scenario, context)
        if not agent_id:
            self.logger.log("ERROR", "Mitigation skipped, agent_id unresolved", command=command)
            return []

        args_list = self._build_args(command, scenario, iocs)
        if not args_list:
            self.logger.log("ERROR", "Mitigation skipped, args unresolved", command=command)
            return []

        out = []
        for args in args_list:
            try:
                resp = self.wazuh_api.send_active_response(agent_id, f"!{command}", args, alert.get("data") or {})
                out.append({"command": command, "agent_id": agent_id, "args": args, "result": resp})
            except Exception as e:
                self.logger.log("ERROR", "Mitigation execution failed", command=command, agent_id=agent_id, error=str(e))
                out.append({"command": command, "agent_id": agent_id, "args": args, "error": str(e)})
        return out

    def _resolve_agent_id(self, scenario: dict, context: dict):
        effective_agent = _safe_str(context.get("effective_agent")).strip()
        if effective_agent:
            try:
                resolved = self.wazuh_api.get_agent_id_by_name(effective_agent)
            except Exception as e:
                self.logger.log(
                    "WARNING",
                    "Wazuh API lookup failed; falling back to alert agent id",
                    effective_agent=effective_agent,
                    error=str(e),
                )
                resolved = None
            
            if resolved:
                return resolved
        alert_agent_id = _safe_str((scenario["alert"].get("agent") or {}).get("id")).strip()
        return alert_agent_id or None

    def _build_args(self, command: str, scenario: dict, iocs: dict) -> list:
        if command == "firewall-drop":
            ips = iocs.get("ip") or []
            return [[ips[0]]] if ips else []

        if command == "lock_user_linux.sh":
            return [[u] for u in (iocs.get("user") or []) if u and u.lower() != "root"]

        if command == "terminate_service.sh":
            services = iocs.get("service") or []
            if services:
                return [[services[0]]]
            ips = iocs.get("ip") or []
            if ips:
                return [[ips[0]]]
        return []



class DecisionId:
    @staticmethod
    def build(scenario: dict, context: dict) -> str:
        alert = scenario["alert"]
        base = {
            "alert_id": _safe_str(alert.get("id")),
            "timestamp": _safe_str(alert.get("timestamp")),
            "rule_id": _safe_str((alert.get("rule") or {}).get("id")),
            "agent_id": _safe_str((alert.get("agent") or {}).get("id")),
            "scenario": scenario["name"],
            "detection": scenario["detection"],
            "window": (context.get("window") or {}),
            "effective_agent": _safe_str(context.get("effective_agent")),
        }
        return _sha256_hex(json.dumps(base, sort_keys=True, ensure_ascii=False))


class RadarActiveResponse:
    def __init__(self):
        EnvLoader.load()
        self.logger = Logger(os.environ.get("AR_LOG_FILE", "/var/ossec/logs/active-responses.log"))
        self.config_path = Path(os.environ.get("AR_RISK_CONFIG", "/var/ossec/active-response/ar.yaml"))
        self.cfg_loader = ConfigLoader(self.logger, self.config_path)
        self.input_handler = WazuhInputHandler(self.logger)
        self.os = OpenSearchClient(self.logger)
        self.strategies = Registry(self.logger, self.os)
        self.decipher = DecipherClient(self.logger)
        self.risk_engine = RiskEngine(self.logger)
        self.email = EmailNotifier(self.logger)
        self.wazuh_api = WazuhApiClient(self.logger)
        self.planner = ActionPlanner(self.logger)
        self.executor = ActionExecutor(self.logger, self.wazuh_api)

    def run(self) -> int:
        self.logger.log("INFO", "RADAR Active Response started")
        cfg = self.cfg_loader.load()
        alert = self.input_handler.read_alert()
        if not alert:
            return 1

        scenario_identifier = ScenarioIdentifier(self.logger, cfg)
        scenario = scenario_identifier.identify(alert)
        if not scenario:
            self.logger.log("INFO", "No scenario match, exiting")
            return 0

        strategy = self.strategies.get(scenario["name"])
        context = strategy.collect_context(scenario)

        if self.decipher.health_check():
            cti = self.decipher.analyze(scenario["name"], context.get("iocs") or {}, alert)
        else:
            cti = {"ok": False, "cti_score_T": 0.0, "labels": [],
                   "case_id": None, "case_url": None, "raw": None}

        ad_grade = None
        ad_conf = None
        if scenario["detection"] == "ad":
            ad_grade, ad_conf = strategy.resolve_ad_scores(scenario)

        risk = self.risk_engine.compute(scenario, cti["cti_score_T"], ad_grade, ad_conf)

        decision_id = DecisionId.build(scenario, context)
        decision = {"decision_id": decision_id, "scenario": scenario, "context": context, "cti": cti, "risk": risk}

        if self.decipher.health_check() and risk["tier"] >= 1:
            incident = self.decipher.create_incident(decision)
            decision["incident"] = incident

        planned = self.planner.plan(decision)

        exec_results = self.executor.execute(decision, planned)
        decision["exec_results"] = exec_results

        if planned.get("notify_email"):
            self.email.send(decision)

        self.logger.log("INFO", "RADAR Active Response completed", decision_id=decision_id, exec_results=exec_results)
        return 0


def main():
    return RadarActiveResponse().run()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        try:
            EnvLoader.load()
            Logger(os.environ.get("AR_LOG_FILE", "/var/ossec/logs/active-responses.log")).log(
                "CRITICAL",
                "Unhandled exception",
                error=str(e),
                trace=traceback.format_exc(),
            )
        except Exception:
            pass
        sys.exit(2)