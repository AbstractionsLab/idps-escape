#!/usr/bin/env python3
"""
Rewrite synthetic resource alerts as the events of RADAR's linux_resource_utilization scenario.

RADAR's collector (``radar/radar-agent/collectors/linux_resource_utilization``) logs
``resource_usage_metric: cpu=<pct> mem=<pct>``; its decoder stores the two values as strings
in ``data.cpu_usage_pct`` and ``data.mem_usage_pct``. No rule matches these events, so they
reach the indexer only through the archives (``wazuh-archives-*``) and carry no ``rule`` block.

This keeps every timestamp and agent of the input, so the label files of the evaluation
splits (``generate_resource_data.py --evaluation``) stay valid for the converted files.

Usage:
    python radar_format.py IN.json OUT.json [--agent NAME]
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

PROGRAM = "resource_usage_metric"
LOG_PATH = "/var/log/radar/resource_usage_metric.log"


def to_radar_event(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    The archived event RADAR's decoder would produce for the same CPU and memory sample.

    Only the fields RADAR's own seed documents carry (``radar/scenarios/ingest_scripts``), which
    are all the scenario reads; the archives also hold ``full_log``, ``manager`` and ``decoder``.
    """
    data = alert.get("data") or {}
    agent = alert.get("agent") or {}
    cpu, mem = float(data["cpu_usage_%"]), float(data["memory_usage_%"])
    return {
        "timestamp": alert["timestamp"],
        "location": LOG_PATH,
        "agent": {"id": agent.get("id", ""), "name": agent.get("name", "")},
        "predecoder": {"program_name": PROGRAM},
        "data": {"cpu_usage_pct": f"{cpu:.2f}", "mem_usage_pct": f"{mem:.2f}"},
    }


def convert(alerts: List[Dict[str, Any]], agent: Optional[str] = None) -> List[Dict[str, Any]]:
    """Convert the resource alerts (those with CPU and memory values), optionally of one agent only."""
    events = []
    for alert in alerts:
        data = alert.get("data") or {}
        if "cpu_usage_%" not in data or "memory_usage_%" not in data:
            continue
        if agent is not None and (alert.get("agent") or {}).get("name") != agent:
            continue
        events.append(to_radar_event(alert))
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Rewrite synthetic resource alerts as RADAR linux_resource_utilization events")
    parser.add_argument("input", type=Path, help="Alert file written by generate_resource_data.py")
    parser.add_argument("output", type=Path, help="Event file to write")
    parser.add_argument("--agent", type=str, default=None, help="Keep only this agent's events")
    args = parser.parse_args()
    events = convert(json.loads(args.input.read_text(encoding="utf-8")), args.agent)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(events) + "\n", encoding="utf-8")
    print(f"{args.output}: {len(events)} events")


if __name__ == "__main__":
    main()
