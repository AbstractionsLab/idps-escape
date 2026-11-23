#!/usr/bin/env python3
"""Off-hours activity detection for the suspicious_login scenario.

Working hours are declared per schedule group in config.yaml
(`scenarios.suspicious_login.off_hours`). An ingest pipeline marks each
user-attributed archive event with `radar.off_hours` (0 or 1),
`radar.schedule_group` and the normalised `radar.user`. Two consumers read the
flag, chosen per group by `mode`:

- `rule`: an Alerting query monitor reports each user's off-hours burst once
  (webhook line -> rule 210041).
- `model`: a per-user AD detector learns each user's usual count of off-hours
  events per interval and flags an unusual one (webhook line -> rule 210040).

This module validates the block, renders and deploys the pipeline, and manages
both consumers (`monitors`), retiring the detectors this design replaces. The Painless script
and `OffHoursConfig.classify` implement the same decision; the shared case table
(tests/py/fixtures/off_hours_cases.yaml) is run against the Python version in
the unit tests and against the Painless version on a live cluster
(radar-test-framework/checks/off_hours_simulate.py).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
import zoneinfo
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import detector as detector_mod
import monitor as monitor_mod
import requests
import urllib3
import yaml
from detector import load_env, make_session
from webhook import ensure_webhook, webhook_headers

logger = logging.getLogger(__name__)

SCENARIO = "suspicious_login"
CONFIG_PATH = f"scenarios.{SCENARIO}.off_hours"
MODES = ("rule", "model")
# Fixed: the archives Filebeat pipeline calls it by this name
# (scenarios/pipelines/suspicious_login/radar-off-hours-step.json), and so does the synthetic ingest.
PIPELINE_NAME = "radar-off-hours"
TEMPLATE_NAME = "radar-off-hours"
TEMPLATE_ORDER = 10  # above Wazuh's legacy `wazuh` template (order 0); legacy templates merge by order
ARCHIVES_PATTERN = "wazuh-archives-*"
DEFAULT_USER_FIELDS = ("data.user", "data.srcuser", "data.dstuser")
DEFAULT_BACKFILL_DAYS = 45

# Fields written by the pipeline. One object, so nothing collides with Wazuh's own fields.
FIELD_ROOT = "radar"
FIELD_USER = f"{FIELD_ROOT}.user"
FIELD_OFF_HOURS = f"{FIELD_ROOT}.off_hours"
FIELD_GROUP = f"{FIELD_ROOT}.schedule_group"
FIELD_ERROR = f"{FIELD_ROOT}.off_hours_error"

_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")

# Keep in step with OffHoursConfig.classify and parse_timestamp below.
# No regex operators: Painless regexes may be disabled or limited on the cluster.
PAINLESS_SOURCE = """
String user = null;
for (def path : params.user_fields) {
  def cur = ctx;
  for (def seg : path) {
    if (cur instanceof Map) { cur = cur.get(seg); } else { cur = null; }
    if (cur == null) { break; }
  }
  if (cur != null && !(cur instanceof Map) && !(cur instanceof List)) {
    String s = cur.toString().trim();
    if (s.length() > 0) { user = s.toLowerCase(); break; }
  }
}
if (user == null || params.ignore_users.contains(user)) { return; }
String g = params.users.containsKey(user) ? params.users.get(user) : params.default_group;
if (g == null) { return; }
def cfg = params.groups.get(g);

def ts = ctx['@timestamp'];
if (ts == null) { throw new IllegalArgumentException('missing @timestamp'); }
ZonedDateTime t;
if (ts instanceof Number) {
  t = Instant.ofEpochMilli(((Number) ts).longValue()).atZone(ZoneId.of('UTC'));
} else {
  String s = ts.toString().trim();
  int n = s.length();
  if (n > 5) {
    char sign = s.charAt(n - 5);
    boolean digits = true;
    for (int i = n - 4; i < n; i++) {
      char d = s.charAt(i);
      if (d < (char) '0' || d > (char) '9') { digits = false; }
    }
    if ((sign == (char) '+' || sign == (char) '-') && digits) {
      s = s.substring(0, n - 2) + ':' + s.substring(n - 2);
    }
  }
  t = ZonedDateTime.parse(s);
}
t = t.withZoneSameInstant(ZoneId.of(cfg.tz));

int m = t.getHour() * 60 + t.getMinute();
int dow = t.getDayOfWeek().getValue();
int start = cfg.start;
int end = cfg.end;
boolean inHours;
int shiftDow = dow;
if (start < end) {
  inHours = m >= start && m < end;
} else {
  inHours = m >= start || m < end;
  if (m < end) { shiftDow = dow == 1 ? 7 : dow - 1; }
}
boolean onShift = inHours && cfg.workdays.contains(shiftDow);

if (!(ctx.radar instanceof Map)) { ctx.radar = new HashMap(); }
ctx.radar.user = user;
ctx.radar.schedule_group = g;
ctx.radar.off_hours = onShift ? 0 : 1;
""".strip()


class OffHoursConfigError(ValueError):
    """The off_hours block is invalid. The message lists every problem found."""


class OffHoursEventError(ValueError):
    """An event's timestamp cannot be read. The pipeline records this in radar.off_hours_error."""


@dataclass(frozen=True)
class ScheduleGroup:
    name: str
    timezone: str
    workdays: frozenset[int]
    start: int  # minutes after local midnight, 0..1439
    end: int  # minutes after local midnight, 1..1440; end < start means the shift crosses midnight
    mode: str

    def is_off_hours(self, when: datetime) -> bool:
        local = when.astimezone(zoneinfo.ZoneInfo(self.timezone))
        minute = local.hour * 60 + local.minute
        dow = local.isoweekday()
        if self.start < self.end:
            in_hours = self.start <= minute < self.end
            shift_dow = dow
        else:
            in_hours = minute >= self.start or minute < self.end
            shift_dow = (7 if dow == 1 else dow - 1) if minute < self.end else dow
        return not (in_hours and shift_dow in self.workdays)


@dataclass(frozen=True)
class EventFilter:
    field: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class RuleModeSettings:
    interval_minutes: int  # monitor schedule and width of each window
    delay_minutes: int  # windows end this far in the past, so events indexed late are still counted
    quiet_minutes: int  # a user notifies again only after this long without off-hours events
    min_events: int
    anomaly_grade: float
    anomaly_confidence: float


@dataclass(frozen=True)
class ModelModeSettings:
    interval_minutes: int
    window_delay_minutes: int
    shingle_size: int
    anomaly_grade_threshold: float
    confidence_threshold: float
    min_events: int  # an anomaly is reported only when the user had at least this many off-hours events in the interval
    max_entities: int  # users reported per monitor run, highest grade first


@dataclass(frozen=True)
class OffHoursConfig:
    enabled: bool
    backfill_days: int
    user_fields: tuple[str, ...]
    default_group: str | None
    ignore_users: frozenset[str]
    groups: dict[str, ScheduleGroup]
    users: dict[str, str]
    event_filter: EventFilter | None
    rule_mode: RuleModeSettings
    model_mode: ModelModeSettings

    def groups_in_mode(self, mode: str) -> list[str]:
        return sorted(name for name, g in self.groups.items() if g.mode == mode)

    def group_for(self, user: str) -> str | None:
        key = user.strip().lower()
        if not key or key in self.ignore_users:
            return None
        return self.users.get(key, self.default_group)

    def event_user(self, event: dict[str, Any]) -> str | None:
        for path in self.user_fields:
            cur: Any = event
            for seg in path.split("."):
                cur = cur.get(seg) if isinstance(cur, dict) else None
                if cur is None:
                    break
            if cur is not None and not isinstance(cur, (dict, list)):
                text = str(cur).strip()
                if text:
                    return text.lower()
        return None

    def classify(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Python twin of PAINLESS_SOURCE: the radar.* fields the pipeline adds, or None when it leaves the event alone."""
        user = self.event_user(event)
        if user is None:
            return None
        group = self.group_for(user)
        if group is None:
            return None
        when = parse_timestamp(event.get("@timestamp"))
        off = self.groups[group].is_off_hours(when)
        return {"user": user, "schedule_group": group, "off_hours": 1 if off else 0}


def parse_timestamp(value: Any) -> datetime:
    """Read @timestamp the way the Painless script does: epoch milliseconds or ISO 8601 with an offset (`+0000` accepted)."""
    if value is None:
        raise OffHoursEventError("missing @timestamp")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc)
    text = str(value).strip()
    if len(text) > 5 and text[-5] in "+-" and text[-4:].isdigit():
        text = f"{text[:-2]}:{text[-2:]}"
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise OffHoursEventError(f"cannot parse @timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        raise OffHoursEventError(f"@timestamp {value!r} has no offset")
    return parsed


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class _Errors:
    def __init__(self) -> None:
        self.items: list[str] = []

    def add(self, where: str, msg: str) -> None:
        self.items.append(f"{CONFIG_PATH}.{where}: {msg}")


def _parse_hhmm(value: Any, where: str, errors: _Errors, *, allow_24: bool) -> int | None:
    if not isinstance(value, str):
        errors.add(where, f'must be a quoted "HH:MM" string, got {value!r} (YAML reads unquoted 16:00 as the number 960)')
        return None
    if allow_24 and value == "24:00":
        return 1440
    m = _HHMM_RE.match(value)
    if not m:
        errors.add(where, f"{value!r} is not a time from 00:00 to {'24:00' if allow_24 else '23:59'}")
        return None
    return int(m.group(1)) * 60 + int(m.group(2))


def _known_timezone(name: Any) -> bool:
    if not isinstance(name, str) or not name:
        return False
    try:
        zoneinfo.ZoneInfo(name)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return False
    return True


def _int(raw: dict[str, Any], key: str, default: int, minimum: int, where: str, errors: _Errors) -> int:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        errors.add(f"{where}.{key}" if where else key, f"must be an integer >= {minimum}, got {value!r}")
        return default
    return value


def _unit(raw: dict[str, Any], key: str, default: float, where: str, errors: _Errors) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.0 < float(value) <= 1.0:
        errors.add(f"{where}.{key}", f"must be a number in (0, 1], got {value!r}")
        return default
    return float(value)


def _group(name: str, raw: Any, errors: _Errors) -> ScheduleGroup | None:
    where = f"groups.{name}"
    if not isinstance(raw, dict):
        errors.add(where, "must be a mapping")
        return None
    ok = True
    tz = raw.get("timezone")
    if not _known_timezone(tz):
        hint = " (no time zone database found: install the tzdata package)" if not zoneinfo.available_timezones() else ""
        errors.add(f"{where}.timezone", f"unknown IANA time zone {tz!r}{hint}")
        ok = False
    start = _parse_hhmm(raw.get("start"), f"{where}.start", errors, allow_24=False)
    end = _parse_hhmm(raw.get("end"), f"{where}.end", errors, allow_24=True)
    if start is None or end is None:
        ok = False
    elif start == end:
        errors.add(where, "start and end must differ")
        ok = False
    workdays = raw.get("workdays")
    if not isinstance(workdays, list) or any(isinstance(d, bool) or not isinstance(d, int) or not 1 <= d <= 7 for d in workdays):
        errors.add(f"{where}.workdays", f"must be a list of ISO weekdays 1 (Monday) to 7, got {workdays!r}")
        ok = False
    mode = raw.get("mode")
    if mode not in MODES:
        errors.add(f"{where}.mode", f"must be one of {', '.join(MODES)}, got {mode!r}")
        ok = False
    unknown = sorted(set(raw) - {"timezone", "start", "end", "workdays", "mode"})
    if unknown:
        errors.add(where, f"unknown keys {unknown}")
        ok = False
    if not ok:
        return None
    return ScheduleGroup(name=name, timezone=tz, workdays=frozenset(workdays), start=start, end=end, mode=mode)


def parse_config(raw: Any) -> OffHoursConfig:
    """Validate the off_hours block and return it typed. Raises OffHoursConfigError listing every problem."""
    errors = _Errors()
    if not isinstance(raw, dict):
        raise OffHoursConfigError(f"{CONFIG_PATH}: must be a mapping")

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        errors.add("enabled", f"must be true or false, got {enabled!r}")

    backfill_days = _int(raw, "backfill_days", DEFAULT_BACKFILL_DAYS, 1, "", errors)

    user_fields = raw.get("user_fields", list(DEFAULT_USER_FIELDS))
    if not isinstance(user_fields, list) or not user_fields or not all(isinstance(f, str) and f and ".." not in f for f in user_fields):
        errors.add("user_fields", f"must be a non-empty list of dotted field paths, got {user_fields!r}")
        user_fields = list(DEFAULT_USER_FIELDS)

    groups: dict[str, ScheduleGroup] = {}
    raw_groups = raw.get("groups")
    if not isinstance(raw_groups, dict) or not raw_groups:
        errors.add("groups", "must define at least one schedule group")
    else:
        for name, graw in raw_groups.items():
            group = _group(str(name), graw, errors)
            if group:
                groups[str(name)] = group
    group_names = set(raw_groups) if isinstance(raw_groups, dict) else set()

    default_group = raw.get("default_group")
    if default_group is not None and default_group not in group_names:
        errors.add("default_group", f"{default_group!r} is not a defined group")

    ignore_raw = raw.get("ignore_users") or []
    if not isinstance(ignore_raw, list) or not all(isinstance(u, str) and u.strip() for u in ignore_raw):
        errors.add("ignore_users", f"must be a list of user names, got {ignore_raw!r}")
        ignore_raw = []
    ignore_users = frozenset(u.strip().lower() for u in ignore_raw)

    users: dict[str, str] = {}
    users_raw = raw.get("users") or {}
    if not isinstance(users_raw, dict):
        errors.add("users", "must map user names to group names")
        users_raw = {}
    for name, group in users_raw.items():
        key = str(name).strip().lower()
        if not key:
            errors.add("users", "empty user name")
        elif key in users:
            errors.add(f"users.{name}", f"duplicates {key!r} (user names are matched in lower case)")
        elif group not in group_names:
            errors.add(f"users.{name}", f"group {group!r} is not defined")
        elif key in ignore_users:
            errors.add(f"users.{name}", "is also listed in ignore_users")
        else:
            users[key] = group

    event_filter = None
    ef = raw.get("event_filter")
    if ef is not None:
        values = ef.get("values", []) if isinstance(ef, dict) else None
        if not isinstance(ef, dict) or not isinstance(ef.get("field"), str) or not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            errors.add("event_filter", "must be {field: <keyword field>, values: [<string>, ...]}")
        elif values:
            event_filter = EventFilter(field=ef["field"], values=tuple(values))

    rm_raw = raw.get("rule_mode") or {}
    mm_raw = raw.get("model_mode") or {}
    if not isinstance(rm_raw, dict):
        errors.add("rule_mode", "must be a mapping")
        rm_raw = {}
    if not isinstance(mm_raw, dict):
        errors.add("model_mode", "must be a mapping")
        mm_raw = {}
    rule_mode = RuleModeSettings(
        interval_minutes=_int(rm_raw, "interval_minutes", 5, 1, "rule_mode", errors),
        delay_minutes=_int(rm_raw, "delay_minutes", 1, 0, "rule_mode", errors),
        quiet_minutes=_int(rm_raw, "quiet_minutes", 30, 0, "rule_mode", errors),
        min_events=_int(rm_raw, "min_events", 1, 1, "rule_mode", errors),
        anomaly_grade=_unit(rm_raw, "anomaly_grade", 1.0, "rule_mode", errors),
        anomaly_confidence=_unit(rm_raw, "anomaly_confidence", 1.0, "rule_mode", errors),
    )
    for name, block, keys in (("rule_mode", rm_raw, RuleModeSettings.__dataclass_fields__), ("model_mode", mm_raw, ModelModeSettings.__dataclass_fields__)):
        extra = sorted(set(block) - set(keys))
        if extra:
            errors.add(name, f"unknown keys {extra}")
    model_mode = ModelModeSettings(
        interval_minutes=_int(mm_raw, "interval_minutes", 30, 1, "model_mode", errors),
        window_delay_minutes=_int(mm_raw, "window_delay_minutes", 10, 0, "model_mode", errors),
        shingle_size=_int(mm_raw, "shingle_size", 1, 1, "model_mode", errors),
        anomaly_grade_threshold=_unit(mm_raw, "anomaly_grade_threshold", 0.01, "model_mode", errors),
        confidence_threshold=_unit(mm_raw, "confidence_threshold", 0.01, "model_mode", errors),
        min_events=_int(mm_raw, "min_events", 1, 1, "model_mode", errors),
        max_entities=_int(mm_raw, "max_entities", 10, 1, "model_mode", errors),
    )
    if model_mode.max_entities > 50:
        errors.add("model_mode.max_entities", f"must be at most 50 (the webhook writes at most 50 lines), got {model_mode.max_entities}")

    known = {"enabled", "backfill_days", "user_fields", "default_group", "ignore_users", "groups", "users", "event_filter", "rule_mode", "model_mode"}
    unknown = sorted(set(raw) - known)
    if unknown:
        errors.add("", f"unknown keys {unknown}")

    if errors.items:
        raise OffHoursConfigError("invalid off_hours configuration:\n  - " + "\n  - ".join(errors.items))

    return OffHoursConfig(
        enabled=enabled,
        backfill_days=backfill_days,
        user_fields=tuple(user_fields),
        default_group=default_group,
        ignore_users=ignore_users,
        groups=groups,
        users=users,
        event_filter=event_filter,
        rule_mode=rule_mode,
        model_mode=model_mode,
    )


def load_config(cfg: dict[str, Any]) -> OffHoursConfig | None:
    """The validated block from a parsed config.yaml, or None when it is absent or disabled."""
    raw = ((cfg.get("scenarios") or {}).get(SCENARIO) or {}).get("off_hours")
    if raw is None:
        return None
    parsed = parse_config(raw)
    return parsed if parsed.enabled else None


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def pipeline_params(cfg: OffHoursConfig) -> dict[str, Any]:
    return {
        "user_fields": [path.split(".") for path in cfg.user_fields],
        "ignore_users": sorted(cfg.ignore_users),
        "default_group": cfg.default_group,
        "users": dict(sorted(cfg.users.items())),
        "groups": {name: {"tz": g.timezone, "start": g.start, "end": g.end, "workdays": sorted(g.workdays)} for name, g in sorted(cfg.groups.items())},
    }


def pipeline_body(cfg: OffHoursConfig) -> dict[str, Any]:
    """Ingest pipeline that flags off-hours events. Never drops an event: on error it records radar.off_hours_error instead."""
    return {
        "description": f"RADAR off-hours flag. Generated from config.yaml {CONFIG_PATH}; do not edit by hand.",
        "processors": [
            {
                "script": {
                    "tag": "radar_off_hours",
                    "lang": "painless",
                    "source": PAINLESS_SOURCE,
                    "params": pipeline_params(cfg),
                    "on_failure": [{"set": {"field": FIELD_ERROR, "value": "{{ _ingest.on_failure_message }}"}}],
                }
            }
        ],
    }


# ---------------------------------------------------------------------------
# OpenSearch: deploy, backfill, undeploy
# ---------------------------------------------------------------------------


class OpenSearchError(RuntimeError):
    """An OpenSearch call failed or returned an unexpected result."""


def radar_mapping() -> dict[str, Any]:
    return {
        "properties": {
            FIELD_ROOT: {
                "properties": {
                    "user": {"type": "keyword"},
                    "off_hours": {"type": "byte"},
                    "schedule_group": {"type": "keyword"},
                    "off_hours_error": {"type": "keyword", "ignore_above": 1024},
                }
            }
        }
    }


def template_body() -> dict[str, Any]:
    """A legacy (_template) template on purpose. A composable (_index_template) one
    matching these indices would make OpenSearch ignore Wazuh's legacy `wazuh`
    template, and new archive indices would lose all of Wazuh's mappings. Legacy
    templates merge by order instead. No index.final_pipeline: it does not run for
    Filebeat events (date_index_name reroutes them), and a deleted pipeline would
    then block every direct write to wazuh-archives-*."""
    return {"index_patterns": [ARCHIVES_PATTERN], "order": TEMPLATE_ORDER, "mappings": radar_mapping()}


def backfill_query(cfg: OffHoursConfig, days: int) -> dict[str, Any]:
    """Events in the last `days` days that have a user and no flag yet. Without a
    default group only listed users can be flagged, so only their events are touched."""
    if cfg.default_group is None and cfg.users and len(cfg.users) * len(cfg.user_fields) <= 900:
        who = [{"term": {field: {"value": user, "case_insensitive": True}}} for field in cfg.user_fields for user in sorted(cfg.users)]
    else:
        who = [{"exists": {"field": field}} for field in cfg.user_fields]
    return {
        "bool": {
            "filter": [{"range": {"@timestamp": {"gte": f"now-{days}d"}}}],
            "should": who,
            "minimum_should_match": 1,
            "must_not": [{"exists": {"field": FIELD_OFF_HOURS}}, {"exists": {"field": FIELD_ERROR}}],
        }
    }


@dataclass(frozen=True)
class Cluster:
    session: requests.Session
    base: str
    verify: bool
    timeout: float

    def call(self, method: str, path: str, body: dict[str, Any] | None = None, allow: tuple[int, ...] = ()) -> tuple[int, Any]:
        r = self.session.request(method, f"{self.base}/{path}", json=body, verify=self.verify, timeout=self.timeout)
        if r.status_code in (200, 201) or r.status_code in allow:
            return r.status_code, (r.json() if r.content else {})
        raise OpenSearchError(f"{method} /{path} -> HTTP {r.status_code}: {r.text[:500]}")


def deploy(cluster: Cluster, cfg: OffHoursConfig) -> None:
    """Create or replace the pipeline and template, and add the mapping to existing archive indices. Safe to repeat."""
    cluster.call("PUT", f"_ingest/pipeline/{PIPELINE_NAME}", pipeline_body(cfg))
    logger.info("ingest pipeline %s: %d groups, %d users", PIPELINE_NAME, len(cfg.groups), len(cfg.users))
    cluster.call("PUT", f"_template/{TEMPLATE_NAME}", template_body())
    logger.info("legacy index template %s (order %d) on %s", TEMPLATE_NAME, TEMPLATE_ORDER, ARCHIVES_PATTERN)
    code, _ = cluster.call("PUT", f"{ARCHIVES_PATTERN}/_mapping", radar_mapping(), allow=(404,))
    logger.info("radar.* mapping on existing archive indices: %s", "no archive indices yet" if code == 404 else "applied")


def backfill(cluster: Cluster, cfg: OffHoursConfig, days: int, poll_seconds: float = 5.0, max_wait_seconds: float = 3600.0, sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Run the pipeline over existing archive events (background task, polled). Returns the task's response."""
    params = f"pipeline={PIPELINE_NAME}&wait_for_completion=false&conflicts=proceed&refresh=true&allow_no_indices=true&ignore_unavailable=true"
    code, started = cluster.call("POST", f"{ARCHIVES_PATTERN}/_update_by_query?{params}", {"query": backfill_query(cfg, days)}, allow=(404,))
    if code == 404 or "task" not in started:
        logger.info("backfill: no archive indices to update")
        return {"total": 0, "updated": 0}
    task = started["task"]
    logger.info("backfill over the last %d days started as task %s", days, task)
    waited = 0.0
    while True:
        _, status = cluster.call("GET", f"_tasks/{task}")
        if status.get("completed"):
            result = status.get("response") or {}
            if status.get("error") or result.get("failures"):
                raise OpenSearchError(f"backfill task {task} failed: {status.get('error') or result.get('failures')}")
            logger.info("backfill done: %s of %s matching events updated", result.get("updated", 0), result.get("total", 0))
            return result
        if waited >= max_wait_seconds:
            raise OpenSearchError(f"backfill task {task} still running after {max_wait_seconds:.0f}s; follow it with GET _tasks/{task}")
        sleep(poll_seconds)
        waited += poll_seconds


def undeploy(cluster: Cluster) -> None:
    """Remove the pipeline and template. Flags already written stay in the indices, and the
    Filebeat step stays (it has ignore_failure, so a missing pipeline only skips the flag)."""
    for path in (f"_template/{TEMPLATE_NAME}", f"_ingest/pipeline/{PIPELINE_NAME}"):
        code, _ = cluster.call("DELETE", path, allow=(404,))
        logger.info("DELETE %s: %s", path, "not found" if code == 404 else "removed")


# ---------------------------------------------------------------------------
# Rule mode: query-level monitor that reports the start of each off-hours burst
# ---------------------------------------------------------------------------
#
# Why not a bucket-level monitor: its actions only see each alert's bucket_keys,
# and ctx.results holds the last (empty) page of the composite aggregation, so
# the message can't carry the count, times or group (checked on OpenSearch 2.19.3).
# A query-level monitor's ctx.results is the one search response, and the query
# itself keeps only users whose burst is new, so each burst notifies once.

# Fixed names: rule 210041 (a3-suspicious-login.xml) matches the trigger name in the webhook line.
RULE_MONITOR_NAME = "SuspiciousLogin-OffHours-RuleMode-Monitor"
RULE_TRIGGER_NAME = "SuspiciousLogin-OffHours-Rule-Detected"
RULE_MAX_USERS = 200  # users with off-hours events per window considered; the webhook writes at most 50 lines


def _event_filter_clauses(cfg: OffHoursConfig, mode: str) -> list[dict[str, Any]]:
    clauses: list[dict[str, Any]] = [{"terms": {FIELD_GROUP: cfg.groups_in_mode(mode)}}]
    if cfg.event_filter:
        clauses.append({"terms": {cfg.event_filter.field: list(cfg.event_filter.values)}})
    return clauses


def _ago(minutes: int) -> str:
    return f"{{{{period_end}}}}||-{minutes}m" if minutes else "{{period_end}}"


def rule_monitor_query(cfg: OffHoursConfig) -> dict[str, Any]:
    """Per user: off-hours events in the current window (the last interval, shifted back by
    delay_minutes so late-indexed events are still seen) and in the quiet period before it.
    A bucket_selector keeps users with at least min_events now and none before: the start
    of a burst. Consecutive windows abut, so each event is in exactly one current window."""
    rm = cfg.rule_mode
    now_from, now_to = _ago(rm.interval_minutes + rm.delay_minutes), _ago(rm.delay_minutes)
    since = _ago(rm.interval_minutes + rm.delay_minutes + rm.quiet_minutes)
    epoch = {"format": "epoch_millis"}
    return {
        "size": 0,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gt": since, "lte": now_to, **epoch}}}, {"term": {FIELD_OFF_HOURS: 1}}] + _event_filter_clauses(cfg, "rule")}},
        "aggregations": {
            "users": {
                "terms": {"field": FIELD_USER, "size": RULE_MAX_USERS},
                "aggs": {
                    "now": {
                        "filter": {"range": {"@timestamp": {"gt": now_from, "lte": now_to, **epoch}}},
                        "aggs": {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}},
                    },
                    "before": {"filter": {"range": {"@timestamp": {"lte": now_from, **epoch}}}},
                    "group": {"terms": {"field": FIELD_GROUP, "size": 1}},
                    "new_burst": {
                        "bucket_selector": {
                            "buckets_path": {"now": "now._count", "before": "before._count"},
                            "script": f"params.now >= {rm.min_events} && params.before == 0",
                        }
                    },
                },
            }
        },
    }


def rule_message_template(cfg: OffHoursConfig) -> str:
    """Webhook body in the format the AD monitors use: an `anomalies` list, closed by a
    null so the mustache loop's trailing comma stays valid JSON. One item per user whose
    burst starts in this window. Grade and confidence are fixed (a declared schedule is
    either broken or not); dataStart/dataEnd are the first and last off-hours event in the
    window, and off_hours_count is their number."""
    item = json.dumps(
        {
            "entity": "{{key}}",
            "anomaly_grade": repr(cfg.rule_mode.anomaly_grade),
            "anomaly_confidence": repr(cfg.rule_mode.anomaly_confidence),
            "dataStart": "{{now.first.value_as_string}}",
            "dataEnd": "{{now.last.value_as_string}}",
            "off_hours_count": "{{now.doc_count}}",
            "schedule_group": "{{group.buckets.0.key}}",
        }
    )
    head = json.dumps({"monitor": {"name": "{{ctx.monitor.name}}"}, "trigger": {"name": "{{ctx.trigger.name}}"}, "periodStart": "{{ctx.periodStart}}", "periodEnd": "{{ctx.periodEnd}}"})
    buckets = "ctx.results.0.aggregations.users.buckets"
    return head[:-1] + ', "anomalies": [{{#' + buckets + "}}" + item + ",{{/" + buckets + "}}null]}"


RULE_CONDITION = "return ctx.results != null && ctx.results.size() > 0 && ctx.results[0].aggregations != null && " "ctx.results[0].aggregations.users != null && ctx.results[0].aggregations.users.buckets.size() > 0"


def rule_monitor_payload(cfg: OffHoursConfig, destination_id: str) -> dict[str, Any]:
    interval = cfg.rule_mode.interval_minutes
    return {
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "name": RULE_MONITOR_NAME,
        "enabled": True,
        "schedule": {"period": {"interval": interval, "unit": "MINUTES"}},
        "inputs": [{"search": {"indices": [ARCHIVES_PATTERN], "query": rule_monitor_query(cfg)}}],
        "triggers": [
            {
                "name": RULE_TRIGGER_NAME,
                "severity": "1",
                "condition": {"script": {"lang": "painless", "source": RULE_CONDITION}},
                "actions": [
                    {
                        "name": RULE_MONITOR_NAME,
                        "destination_id": destination_id,
                        "subject_template": {"lang": "mustache", "source": "Alerting Notification action"},
                        "message_template": {"lang": "mustache", "source": rule_message_template(cfg)},
                        "throttle_enabled": False,
                    }
                ],
            }
        ],
        "ui_metadata": {"monitor_type": "query_level_monitor", "search": {"searchType": "query"}},
    }


def ensure_rule_monitor(cluster: Cluster, cfg: OffHoursConfig | None, destination_id: str) -> str | None:
    """Create, update or (with no rule-mode group) delete the rule-mode monitor. Returns its id.
    A monitor of another type under the same name (the first, bucket-level design) is replaced."""
    wanted = bool(_groups(cfg, "rule"))
    existing = monitor_mod.find_monitor(cluster.session, cluster.base, RULE_MONITOR_NAME, cluster.verify)
    if existing:
        _, current = cluster.call("GET", f"_plugins/_alerting/monitors/{existing[0]}", allow=(404,))
        current_type = ((current or {}).get("monitor") or {}).get("monitor_type")
        if not wanted or (current_type and current_type != "query_level_monitor"):
            cluster.call("DELETE", f"_plugins/_alerting/monitors/{existing[0]}", allow=(404,))
            logger.info("rule mode: deleted monitor %s (%s)", RULE_MONITOR_NAME, "no group uses rule mode" if not wanted else f"was a {current_type}")
            existing = None
    if not wanted:
        return None
    payload = rule_monitor_payload(cfg, destination_id)
    payload["ui_metadata"][monitor_mod.PAYLOAD_HASH_KEY] = monitor_mod.payload_hash(payload)
    if not existing:
        monitor_id = monitor_mod.create_monitor(cluster.session, cluster.base, payload, cluster.verify)
        logger.info("rule mode: created monitor %s (%s)", RULE_MONITOR_NAME, monitor_id)
        return monitor_id
    monitor_id, _, stored_hash = existing
    if stored_hash != payload["ui_metadata"][monitor_mod.PAYLOAD_HASH_KEY]:
        monitor_mod.update_monitor(cluster.session, cluster.base, monitor_id, payload, cluster.verify)
        logger.info("rule mode: updated monitor %s (%s)", RULE_MONITOR_NAME, monitor_id)
    else:
        logger.info("rule mode: monitor %s (%s) is up to date", RULE_MONITOR_NAME, monitor_id)
    return monitor_id


def _messages(node: Any) -> list[str]:
    """Every rendered action message in an _execute response."""
    if isinstance(node, dict):
        out = [node["message"]] if isinstance(node.get("message"), str) else []
        for value in node.values():
            out += _messages(value)
        return out
    if isinstance(node, list):
        return [m for value in node for m in _messages(value)]
    return []


def _parsed_messages(execute_response: dict[str, Any]) -> list[Any]:
    out: list[Any] = []
    for raw in _messages(execute_response.get("trigger_results") or {}):
        try:
            out.append(json.loads(raw))
        except ValueError:
            out.append({"unparseable": raw})
    return out


def dry_run_rule_monitor(cluster: Cluster) -> dict[str, Any]:
    """Run the rule-mode monitor now without sending anything; return the new bursts it found and the rendered messages."""
    existing = monitor_mod.find_monitor(cluster.session, cluster.base, RULE_MONITOR_NAME, cluster.verify)
    if not existing:
        raise OpenSearchError(f"monitor {RULE_MONITOR_NAME} not found; run `off_hours.py monitors` first")
    _, res = cluster.call("POST", f"_plugins/_alerting/monitors/{existing[0]}/_execute?dryrun=true")
    inputs = res.get("input_results") or {}
    results = inputs.get("results") or [{}]
    buckets = ((results[0].get("aggregations") or {}).get("users") or {}).get("buckets", []) if results else []
    triggered = [t.get("triggered") for t in (res.get("trigger_results") or {}).values()]
    return {"input_error": inputs.get("error"), "triggered": triggered, "new_bursts": buckets, "messages": _parsed_messages(res)}


def _monitor_status(cluster: Cluster, name: str, limit: int) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """The monitor's id and state, and its newest alerts (with action errors)."""
    existing = monitor_mod.find_monitor(cluster.session, cluster.base, name, cluster.verify)
    if not existing:
        return None, []
    mid = existing[0]
    _, mon = cluster.call("GET", f"_plugins/_alerting/monitors/{mid}", allow=(404,))
    m = (mon or {}).get("monitor") or {}
    info = {"id": mid, "enabled": m.get("enabled"), "last_update_time": m.get("last_update_time")}
    _, al = cluster.call("GET", f"_plugins/_alerting/monitors/alerts?monitorId={mid}&alertState=ALL&sortString=start_time&sortOrder=desc&size={limit}", allow=(404,))
    alerts = [
        {
            "state": a.get("state"),
            "start_time": a.get("start_time"),
            "last_notification_time": a.get("last_notification_time"),
            "error_message": a.get("error_message"),
            "alert_history": [h.get("message") for h in a.get("alert_history") or []][-3:],
            "action_execution_results": a.get("action_execution_results"),
        }
        for a in (al or {}).get("alerts", [])
    ]
    return info, alerts


def _webhook_lines(cluster: Cluster, trigger_name: str, limit: int) -> list[dict[str, Any]]:
    """The webhook's lines for this trigger as Wazuh archived them (decoded fields and matched rule)."""
    query = {
        "size": limit,
        "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp", "agent.name", "location", "full_log", "data", "rule.id", "rule.description"],
        "query": {"bool": {"should": [{"term": {"data.detector_name": trigger_name}}, {"match_phrase": {"full_log": trigger_name}}], "minimum_should_match": 1}},
    }
    _, lines = cluster.call("POST", f"{ARCHIVES_PATTERN}/_search", query, allow=(400, 404))
    return [h.get("_source") for h in ((lines or {}).get("hits") or {}).get("hits", [])]


def _wazuh_alerts(cluster: Cluster, rule_id: str, limit: int) -> list[dict[str, Any]]:
    query = {"size": limit, "sort": [{"timestamp": "desc"}], "_source": ["timestamp", "agent.name", "data", "rule.id", "rule.description"], "query": {"term": {"rule.id": rule_id}}}
    _, alerts = cluster.call("POST", "wazuh-alerts-*/_search", query, allow=(400, 404))
    return [h.get("_source") for h in ((alerts or {}).get("hits") or {}).get("hits", [])]


def rule_mode_status(cluster: Cluster, limit: int = 5) -> dict[str, Any]:
    """Each hop of a rule-mode alert, newest first: the monitor's alerts (with action errors),
    the webhook's line as Wazuh archived it (decoded fields and matched rule), and 210041 alerts."""
    monitor, alerts = _monitor_status(cluster, RULE_MONITOR_NAME, limit)
    return {
        "monitor": monitor,
        "monitor_alerts": alerts,
        "webhook_lines": _webhook_lines(cluster, RULE_TRIGGER_NAME, limit),
        "wazuh_alerts": _wazuh_alerts(cluster, RULE_ALERT_ID, limit),
    }


# ---------------------------------------------------------------------------
# Model mode: per-user AD detector on the count of off-hours events
# ---------------------------------------------------------------------------
#
# One feature, sum(radar.off_hours), over every flagged event of model-mode users.
# On-shift intervals give 0, so the model learns each user's usual off-hours count
# per interval. Default imputation (none): an interval without events is skipped,
# not scored as 0. The monitor reports an anomaly only when the user had at least
# min_events off-hours events in that interval, so a drop in off-hours work
# (fewer events than usual, or none) is not reported.

MODEL_DETECTOR_NAME = "SUSPICIOUS_LOGIN_OFF_HOURS_DETECTOR"
MODEL_MONITOR_NAME = "SuspiciousLogin-OffHours-ModelMode-Monitor"
# Rule 210040 (a3-suspicious-login.xml) matches this trigger name; kept from the detector this one replaces.
MODEL_TRIGGER_NAME = "SuspiciousLogin-OffHour-Detected"
MODEL_RESULT_INDEX = "opensearch-ad-plugin-result-suspicious-login-off-hours"
MODEL_FEATURE = "off_hours_events"
RULE_ALERT_ID, MODEL_ALERT_ID = "210041", "210040"
SPEC_HASH_MARK = "radar_spec_sha256="

# (detector, monitor) pairs of the designs this one replaces: the scenario's
# sin/cos time-of-day detector and the never-wired off_hour_login stanza.
# Redeploying stops the detector and disables the monitor; both are kept for inspection.
LEGACY = (
    ("SUSPICIOUS_LOGIN_DETECTOR", "SuspiciousLogin-OffHour-Monitor"),
    ("OFF_HOUR_LOGIN_DETECTOR", "OffHourActivity-PerUser-Monitor"),
)


def model_detector_spec(cfg: OffHoursConfig) -> dict[str, Any]:
    """The AD detector, built by detector.py's detector_spec like every other RADAR detector.
    Its description carries a hash of the rest, so a redeploy can tell when it is stale."""
    mm = cfg.model_mode
    scn = {
        "log_index_pattern": ARCHIVES_PATTERN,
        "time_field": "@timestamp",
        "shingle_size": mm.shingle_size,
        "filter_query": {"bool": {"filter": [{"exists": {"field": FIELD_OFF_HOURS}}] + _event_filter_clauses(cfg, "model")}},
        "features": [{"feature_name": MODEL_FEATURE, "feature_enabled": True, "aggregation_query": {MODEL_FEATURE: {"sum": {"field": FIELD_OFF_HOURS}}}}],
        "detector_interval": mm.interval_minutes,
        "delay_minutes": mm.window_delay_minutes,
        "categorical_field": FIELD_USER,
        "result_index": MODEL_RESULT_INDEX,
    }
    spec = detector_mod.detector_spec(SCENARIO, scn)
    spec.pop("imputation_option")  # AD default: intervals without data are skipped
    spec.pop("description")
    spec["name"] = MODEL_DETECTOR_NAME
    digest = hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()
    spec["description"] = f"RADAR off-hours model mode, generated from config.yaml {CONFIG_PATH}. {SPEC_HASH_MARK}{digest}"
    return spec


def model_monitor_payload(cfg: OffHoursConfig, detector_id: str, destination_id: str) -> dict[str, Any]:
    """monitor.py's AD monitor, plus a filter on the interval's actual off-hours count."""
    mm = cfg.model_mode
    scn = {
        "monitor_interval": mm.interval_minutes,
        "anomaly_grade_threshold": mm.anomaly_grade_threshold,
        "confidence_threshold": mm.confidence_threshold,
        "result_index": MODEL_RESULT_INDEX,
        "trigger_name": MODEL_TRIGGER_NAME,
        "monitor_name": MODEL_MONITOR_NAME,
        "monitor_max_entities": mm.max_entities,
    }
    payload = monitor_mod.monitor_payload(SCENARIO, scn, detector_id, destination_id)
    actual = {"nested": {"path": "feature_data", "query": {"range": {"feature_data.data": {"gte": mm.min_events}}}}}
    payload["inputs"][0]["search"]["query"]["query"]["bool"]["filter"].append(actual)
    return payload


def _groups(cfg: OffHoursConfig | None, mode: str) -> list[str]:
    return cfg.groups_in_mode(mode) if cfg else []


def _detector_state(cluster: Cluster, det_id: str) -> tuple[dict[str, Any], bool]:
    """The stored detector and whether its real-time job is running."""
    _, res = cluster.call("GET", f"_plugins/_anomaly_detection/detectors/{det_id}?job=true")
    return res.get("anomaly_detector") or {}, bool((res.get("anomaly_detector_job") or {}).get("enabled"))


def _find_detector(cluster: Cluster, name: str) -> str | None:
    return detector_mod.find_detector_id(cluster.session, cluster.base, name, cluster.verify, cluster.timeout)


def _stop_detector(cluster: Cluster, det_id: str) -> None:
    cluster.call("POST", f"_plugins/_anomaly_detection/detectors/{det_id}/_stop", allow=(400, 404))


def ensure_model_detector(cluster: Cluster, cfg: OffHoursConfig | None) -> str | None:
    """Create, update or (with no model-mode group) delete the model-mode detector, and keep it running. Returns its id.
    AD refuses to update a running detector, so a stale one is stopped, updated and started again."""
    det_id = _find_detector(cluster, MODEL_DETECTOR_NAME)
    if not _groups(cfg, "model"):
        if det_id:
            _, running = _detector_state(cluster, det_id)
            if running:
                _stop_detector(cluster, det_id)
            cluster.call("DELETE", f"_plugins/_anomaly_detection/detectors/{det_id}", allow=(404,))
            logger.info("model mode: deleted detector %s (%s): no group uses model mode", MODEL_DETECTOR_NAME, det_id)
        return None
    spec = model_detector_spec(cfg)
    if det_id is None:
        _, res = cluster.call("POST", "_plugins/_anomaly_detection/detectors", spec)
        det_id, running = res["_id"], False
        logger.info("model mode: created detector %s (%s)", MODEL_DETECTOR_NAME, det_id)
    else:
        current, running = _detector_state(cluster, det_id)
        if current.get("description") != spec["description"]:
            if running:
                _stop_detector(cluster, det_id)
                running = False
            cluster.call("PUT", f"_plugins/_anomaly_detection/detectors/{det_id}", spec)
            logger.info("model mode: updated detector %s (%s)", MODEL_DETECTOR_NAME, det_id)
        else:
            logger.info("model mode: detector %s (%s) is up to date", MODEL_DETECTOR_NAME, det_id)
    if not running:
        cluster.call("POST", f"_plugins/_anomaly_detection/detectors/{det_id}/_start")
        logger.info("model mode: started detector %s (%s)", MODEL_DETECTOR_NAME, det_id)
    return det_id


def ensure_model_monitor(cluster: Cluster, cfg: OffHoursConfig | None, detector_id: str | None, destination_id: str) -> str | None:
    """Create or update the model-mode monitor for detector_id, or delete it when there is no detector. Returns its id."""
    existing = monitor_mod.find_monitor(cluster.session, cluster.base, MODEL_MONITOR_NAME, cluster.verify)
    if cfg is None or detector_id is None:
        if existing:
            cluster.call("DELETE", f"_plugins/_alerting/monitors/{existing[0]}", allow=(404,))
            logger.info("model mode: deleted monitor %s (%s)", MODEL_MONITOR_NAME, existing[0])
        return None
    payload = model_monitor_payload(cfg, detector_id, destination_id)
    payload["ui_metadata"][monitor_mod.PAYLOAD_HASH_KEY] = monitor_mod.payload_hash(payload)
    if not existing:
        monitor_id = monitor_mod.create_monitor(cluster.session, cluster.base, payload, cluster.verify)
        logger.info("model mode: created monitor %s (%s)", MODEL_MONITOR_NAME, monitor_id)
        return monitor_id
    monitor_id, linked, stored_hash = existing
    if linked != detector_id or stored_hash != payload["ui_metadata"][monitor_mod.PAYLOAD_HASH_KEY]:
        monitor_mod.update_monitor(cluster.session, cluster.base, monitor_id, payload, cluster.verify)
        logger.info("model mode: updated monitor %s (%s)", MODEL_MONITOR_NAME, monitor_id)
    else:
        logger.info("model mode: monitor %s (%s) is up to date", MODEL_MONITOR_NAME, monitor_id)
    return monitor_id


def retire_legacy(cluster: Cluster) -> list[str]:
    """Stop the detectors this design replaces and disable their monitors. Returns what changed."""
    done: list[str] = []
    for det_name, mon_name in LEGACY:
        existing = monitor_mod.find_monitor(cluster.session, cluster.base, mon_name, cluster.verify)
        if existing:
            _, res = cluster.call("GET", f"_plugins/_alerting/monitors/{existing[0]}", allow=(404,))
            mon = (res or {}).get("monitor") or {}
            if mon.get("enabled"):
                body = {k: mon[k] for k in ("type", "monitor_type", "name", "schedule", "inputs", "triggers", "ui_metadata") if k in mon}
                body["enabled"] = False
                cluster.call("PUT", f"_plugins/_alerting/monitors/{existing[0]}", body)
                done.append(f"disabled monitor {mon_name} ({existing[0]})")
        det_id = _find_detector(cluster, det_name)
        if det_id and _detector_state(cluster, det_id)[1]:
            _stop_detector(cluster, det_id)
            done.append(f"stopped detector {det_name} ({det_id})")
    for item in done:
        logger.info("replaced design: %s", item)
    return done


def sync(cluster: Cluster, cfg: OffHoursConfig | None, destination: Callable[[], str]) -> dict[str, str | None]:
    """Bring both consumers in line with the config (None = absent or disabled: remove them)
    and retire the legacy detectors. The webhook channel is only looked up when a monitor needs it."""
    retire_legacy(cluster)
    dest = destination() if _groups(cfg, "rule") or _groups(cfg, "model") else ""
    if _groups(cfg, "model"):
        det_id = ensure_model_detector(cluster, cfg)
        model_monitor = ensure_model_monitor(cluster, cfg, det_id, dest)
    else:
        model_monitor = ensure_model_monitor(cluster, cfg, None, dest)  # the monitor goes before its detector
        det_id = ensure_model_detector(cluster, cfg)
    rule_monitor = ensure_rule_monitor(cluster, cfg, dest)
    return {"rule_monitor": rule_monitor, "model_detector": det_id, "model_monitor": model_monitor}


def dry_run_model_monitor(cluster: Cluster) -> dict[str, Any]:
    """Run the model-mode monitor now without sending anything; return the anomalies it found and the rendered messages."""
    existing = monitor_mod.find_monitor(cluster.session, cluster.base, MODEL_MONITOR_NAME, cluster.verify)
    if not existing:
        raise OpenSearchError(f"monitor {MODEL_MONITOR_NAME} not found; run `off_hours.py monitors` first")
    _, res = cluster.call("POST", f"_plugins/_alerting/monitors/{existing[0]}/_execute?dryrun=true")
    inputs = res.get("input_results") or {}
    results = inputs.get("results") or [{}]
    hits = [h.get("_source") for h in ((results[0].get("hits") or {}).get("hits") or [])] if results else []
    return {"input_error": inputs.get("error"), "triggered": [t.get("triggered") for t in (res.get("trigger_results") or {}).values()], "anomalies": hits, "messages": _parsed_messages(res)}


def model_mode_status(cluster: Cluster, limit: int = 5) -> dict[str, Any]:
    """The detector's state, its newest anomalies, the monitor's alerts, the webhook lines and 210040 alerts."""
    out: dict[str, Any] = {"detector": None, "anomalies": []}
    det_id = _find_detector(cluster, MODEL_DETECTOR_NAME)
    if det_id:
        _, running = _detector_state(cluster, det_id)
        _, profile = cluster.call("GET", f"_plugins/_anomaly_detection/detectors/{det_id}/_profile/state,error,total_entities,active_entities", allow=(400, 404))
        out["detector"] = {"id": det_id, "running": running, "profile": profile}
        query = {
            "size": limit,
            "sort": [{"data_end_time": "desc"}],
            "_source": ["entity", "anomaly_grade", "confidence", "data_start_time", "data_end_time", "feature_data", "task_id"],
            "query": {"bool": {"filter": [{"term": {"detector_id": det_id}}, {"range": {"anomaly_grade": {"gt": 0}}}]}},
        }
        _, res = cluster.call("POST", f"{MODEL_RESULT_INDEX}*/_search", query, allow=(400, 404))
        out["anomalies"] = [h.get("_source") for h in ((res or {}).get("hits") or {}).get("hits", [])]
    out["monitor"], out["monitor_alerts"] = _monitor_status(cluster, MODEL_MONITOR_NAME, limit)
    out["webhook_lines"] = _webhook_lines(cluster, MODEL_TRIGGER_NAME, limit)
    out["wazuh_alerts"] = _wazuh_alerts(cluster, MODEL_ALERT_ID, limit)
    return out


def summary(cluster: Cluster, days: int) -> dict[str, Any]:
    """Flagged archive events per user over the last `days` days, to check the pipeline on live data."""
    since = {"range": {"@timestamp": {"gte": f"now-{days}d"}}}
    body = {
        "size": 0,
        "query": {"bool": {"filter": [since, {"exists": {"field": FIELD_GROUP}}]}},
        "aggs": {
            "users": {
                "terms": {"field": FIELD_USER, "size": 100},
                "aggs": {
                    "group": {"terms": {"field": FIELD_GROUP, "size": 1}},
                    "off_hours": {"sum": {"field": FIELD_OFF_HOURS}},
                    "last_off": {"filter": {"term": {FIELD_OFF_HOURS: 1}}, "aggs": {"at": {"max": {"field": "@timestamp"}}}},
                },
            }
        },
    }
    code, res = cluster.call("POST", f"{ARCHIVES_PATTERN}/_search", body, allow=(404,))
    _, err = cluster.call("POST", f"{ARCHIVES_PATTERN}/_count", {"query": {"bool": {"filter": [since, {"exists": {"field": FIELD_ERROR}}]}}}, allow=(404,))
    rows = []
    for b in ((res.get("aggregations") or {}).get("users") or {}).get("buckets", []) if code != 404 else []:
        groups = b["group"]["buckets"]
        rows.append(
            {
                "user": b["key"],
                "group": groups[0]["key"] if groups else None,
                "events": b["doc_count"],
                "off_hours": int(b["off_hours"]["value"] or 0),
                "last_off_hours": b["last_off"]["at"].get("value_as_string"),
            }
        )
    return {"days": days, "users": rows, "errors": int(err.get("count", 0))}


def webhook_destination(cluster: Cluster, cfg_yaml: dict[str, Any]) -> str:
    """The RADAR webhook's notification channel id, created if needed (same settings as monitor.py)."""
    wb_cfg = cfg_yaml.get("webhook") or {}
    name = wb_cfg.get("name") or os.environ.get("WEBHOOK_NAME", "RADAR Webhook")
    url = wb_cfg.get("url") or os.environ.get("WEBHOOK_URL", "")
    if not url:
        raise OpenSearchError("set webhook.url in config.yaml or WEBHOOK_URL in .env")
    auth = cluster.session.auth or ("", "")
    return ensure_webhook(cluster.base, auth[0], auth[1], cluster.verify, name, url, headers=webhook_headers())


def cluster_from_env() -> Cluster:
    load_env(Path(".env"))
    base = os.environ.get("OS_URL", "").rstrip("/")
    if not base:
        raise OpenSearchError("OS_URL is required in .env")
    verify = os.environ.get("OS_VERIFY_SSL", "true").lower() in ("1", "true", "yes", "on")
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        logger.warning("TLS certificate verification is off (OS_VERIFY_SSL=false)")
    session = make_session(os.environ.get("OS_USER", ""), os.environ.get("OS_PASS", ""))
    return Cluster(session=session, base=base, verify=verify, timeout=float(os.environ.get("OS_TIMEOUT", "30")))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Off-hours detection: validate the config block, render and deploy the pipeline, backfill history, " "and manage the rule-mode monitor and the model-mode detector and monitor (`monitors`).")
    ap.add_argument("command", choices=("validate", "pipeline", "template", "deploy", "backfill", "monitors", "dry-run", "status", "summary", "undeploy"))
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--days", type=int, default=None, help="window in days for backfill and summary (default: backfill_days from config.yaml; summary: 1)")
    ap.add_argument("--mode", choices=MODES, default=None, help="dry-run: which monitor (default: rule); status: only this mode (default: both)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="[off_hours] %(levelname)s %(message)s")
    try:
        if args.command == "undeploy":
            undeploy(cluster_from_env())
            return 0
        if args.command == "status":
            cluster = cluster_from_env()
            report = {f"{mode}_mode": (rule_mode_status if mode == "rule" else model_mode_status)(cluster) for mode in ([args.mode] if args.mode else MODES)}
            sys.stdout.write(json.dumps(report, indent=2, default=str) + "\n")
            return 0
        if args.command == "dry-run":
            run = dry_run_model_monitor if args.mode == "model" else dry_run_rule_monitor
            sys.stdout.write(json.dumps(run(cluster_from_env()), indent=2) + "\n")
            return 0
        if args.command == "summary":
            report = summary(cluster_from_env(), args.days or 1)
            sys.stdout.write(f"{'user':<20} {'group':<20} {'events':>7} {'off-hours':>9}  last off-hours event\n")
            for row in report["users"]:
                sys.stdout.write(f"{row['user']:<20} {row['group'] or '-':<20} {row['events']:>7} {row['off_hours']:>9}  {row['last_off_hours'] or '-'}\n")
            sys.stdout.write(f"{len(report['users'])} users flagged in the last {report['days']} day(s); {report['errors']} events with radar.off_hours_error\n")
            return 0
        if args.command == "template":
            sys.stdout.write(json.dumps(template_body(), indent=2) + "\n")
            return 0
        with Path(args.config).open(encoding="utf-8") as f:
            cfg_yaml = yaml.safe_load(f) or {}
        cfg = load_config(cfg_yaml)
        if args.command == "monitors":
            # Also with the block absent or disabled: then the off-hours monitors and detector are removed.
            cluster = cluster_from_env()
            sync(cluster, cfg, lambda: webhook_destination(cluster, cfg_yaml))
            return 0
        if cfg is None:
            logger.info("%s is absent or disabled; nothing to do", CONFIG_PATH)
            return 0
        if args.command == "validate":
            logger.info("valid: %d groups (rule mode: %s; model mode: %s), %d users", len(cfg.groups), cfg.groups_in_mode("rule"), cfg.groups_in_mode("model"), len(cfg.users))
        elif args.command == "pipeline":
            sys.stdout.write(json.dumps(pipeline_body(cfg), indent=2) + "\n")
        elif args.command == "deploy":
            deploy(cluster_from_env(), cfg)
        else:
            backfill(cluster_from_env(), cfg, args.days or cfg.backfill_days)
    except OffHoursConfigError as exc:
        logger.error("%s", exc)
        return 1
    except (OpenSearchError, requests.RequestException) as exc:
        logger.error("%s", exc)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
