"""
Shared helpers of the data generators for labelled evaluation splits (``sonar evaluate``).

A split is ``context_hours`` of normal data (the context the detector needs before it scores)
followed by an evaluation period into which events are injected at random, non-overlapping
times. Its label file lists each event's type and interval in the ``sonar-labels/1`` format
read by ``sonar.evaluation.Labels``.
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Sequence, Tuple

LABELS_FORMAT = "sonar-labels/1"

# An injector adds the alerts of one event starting at a time and returns its duration in minutes.
Injector = Callable[[List[Dict[str, Any]], datetime, random.Random], float]


def iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def place_events(rng: random.Random, kinds: Sequence[str], start: datetime, end: datetime, max_minutes: float, gap_minutes: float = 60) -> List[Tuple[str, datetime]]:
    """
    Random start times for ``kinds`` in ``[start, end)``: one per equal slot, in shuffled order,
    so that events never overlap and are at least ``gap_minutes`` apart.
    """
    kinds = list(kinds)
    rng.shuffle(kinds)
    slot = (end - start) / len(kinds)
    room = slot - timedelta(minutes=max_minutes + gap_minutes)
    if room.total_seconds() < 0:
        raise ValueError(f"{len(kinds)} events of up to {max_minutes} minutes do not fit between {start} and {end}")
    placed = []
    for i, kind in enumerate(kinds):
        offset = timedelta(minutes=rng.randint(0, int(room.total_seconds() // 60)))
        placed.append((kind, (start + slot * i + offset).replace(second=0, microsecond=0)))
    return placed


def labelled_split(
    normal: Callable[[datetime, int], List[Dict[str, Any]]],
    injectors: Dict[str, Injector],
    kinds: Sequence[str],
    start: datetime,
    context_hours: int,
    evaluation_hours: int,
    seed: int,
    dataset: str,
    max_minutes: float,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    Generate one split: normal data for the whole span, then the events.

    Args:
        normal: ``normal(start, hours)`` returns the normal alerts (uses the global ``random``,
            which is seeded with ``seed`` first).
        injectors: Event type -> injector.
        kinds: Event types to inject, one entry per event.

    Returns:
        The alerts sorted by timestamp, and the label document.
    """
    random.seed(seed)
    rng = random.Random(seed + 1)
    alerts = normal(start, context_hours + evaluation_hours)
    eval_start = start + timedelta(hours=context_hours)
    end = start + timedelta(hours=context_hours + evaluation_hours)
    events = []
    counts: Dict[str, int] = {}
    for kind, at in sorted(place_events(rng, kinds, eval_start, end, max_minutes), key=lambda e: e[1]):
        minutes = injectors[kind](alerts, at, rng)
        counts[kind] = counts.get(kind, 0) + 1
        events.append({"id": f"{kind}_{counts[kind]}", "type": kind, "start": iso(at), "end": iso(at + timedelta(minutes=minutes))})
    alerts.sort(key=lambda a: a["timestamp"])
    labels = {"format": LABELS_FORMAT, "dataset": dataset, "span": {"start": iso(start), "end": iso(end)}, "seed": seed, "context_hours": context_hours, "events": events}
    return alerts, labels


def write_json(path: Path, data: Any) -> None:
    with open(path, "w") as f:
        json.dump(data, f, indent=1 if isinstance(data, dict) else None)
        f.write("\n")
