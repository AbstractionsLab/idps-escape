"""
Small labelled alert streams for the end-to-end tests (fixed seeds, one alert per minute and host).

Not a test module: ``test_e2e_detection.py`` and ``test_evaluation.py`` import it.
"""

import json
import math
import random
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import pandas as pd

Interval = Tuple[int, int]  # minutes from the start, [first, last)


def _inside(minute: int, intervals: Iterable[Interval]) -> bool:
    return any(a <= minute < b for a, b in intervals)


def _alert(ts: pd.Timestamp, host: str, groups: Sequence[str], level: int = 3, data: Dict[str, Any] = None) -> Dict[str, Any]:
    return {
        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "rule": {"id": "100", "level": level, "groups": list(groups)},
        "agent": {"id": host[-3:], "name": host},
        "data": data or {},
    }


def metric_alerts(start: pd.Timestamp, minutes: int, rng: random.Random, spikes: Sequence[Interval] = (), hosts: Sequence[str] = ("host-001", "host-002")) -> List[Dict[str, Any]]:
    """A CPU gauge per host and minute around 30 % (a slow cycle plus noise), 95 % inside ``spikes``."""
    alerts = []
    for m in range(minutes):
        ts = start + pd.Timedelta(minutes=m, seconds=rng.randint(0, 50))
        for host in hosts:
            cpu = 95.0 + rng.uniform(-2, 2) if _inside(m, spikes) else 30.0 + 5 * math.sin(2 * math.pi * m / 90) + rng.uniform(-2, 2)
            alerts.append(_alert(ts, host, ["performance_metric"], data={"cpu_usage_%": round(cpu, 2)}))
    return alerts


def event_alerts(
    start: pd.Timestamp,
    minutes: int,
    rng: random.Random,
    rate: int = 6,
    bursts: Sequence[Interval] = (),
    silences: Sequence[Interval] = (),
    new_category: Sequence[Interval] = (),
) -> List[Dict[str, Any]]:
    """
    An event stream of about ``rate`` alerts per minute in two groups (``sshd``, ``pam``).

    Ten times the rate inside ``bursts``, nothing inside ``silences``, and inside
    ``new_category`` half the alerts in a group never seen before (``web_attack``).
    """
    alerts = []
    for m in range(minutes):
        if _inside(m, silences):
            continue
        n = rate + rng.randint(-1, 1)
        if _inside(m, bursts):
            n *= 10
        for _ in range(n):
            ts = start + pd.Timedelta(minutes=m, seconds=rng.randint(0, 59))
            group = "web_attack" if _inside(m, new_category) and rng.random() < 0.5 else rng.choice(("sshd", "pam"))
            alerts.append(_alert(ts, f"host-00{rng.randint(1, 3)}", [group]))
    return alerts


def write_alerts(path: Path, alerts: List[Dict[str, Any]]) -> None:
    Path(path).write_text(json.dumps(alerts))
