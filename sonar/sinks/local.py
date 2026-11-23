"""
Local sinks: the SONAR events (the same lines the ``wazuh`` sink sends) on standard output
or appended to a JSON-lines file. ``--debug`` uses them, so debug runs exercise the output
path; ``--dry-run`` writes to a JSON-lines file instead of the configured sinks.
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO

from sonar.sinks.base import DeliveryResult
from sonar.sinks.events import event_line, wazuh_event


class StdoutSink:
    """Print one SONAR event per line."""

    name = "stdout"

    def __init__(self, medium: float = 0.5, high: float = 0.8, stream: Optional[TextIO] = None):
        self.medium, self.high = medium, high
        self.stream = stream

    def emit(self, docs: List[Dict[str, Any]]) -> DeliveryResult:
        out = self.stream or sys.stdout
        for doc in docs:
            out.write(event_line(wazuh_event(doc, self.medium, self.high)) + "\n")
        out.flush()
        return DeliveryResult(len(docs), len(docs))


class JsonlSink:
    """Append one SONAR event per line to a file."""

    name = "jsonl"

    def __init__(self, path: str, medium: float = 0.5, high: float = 0.8):
        self.path = Path(path)
        self.medium, self.high = medium, high

    def emit(self, docs: List[Dict[str, Any]]) -> DeliveryResult:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                for doc in docs:
                    fh.write(event_line(wazuh_event(doc, self.medium, self.high)) + "\n")
        except OSError as e:
            return DeliveryResult(0, len(docs), f"cannot write {self.path}: {e}")
        return DeliveryResult(len(docs), len(docs))
