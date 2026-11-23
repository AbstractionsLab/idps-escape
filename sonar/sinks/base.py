"""
The sink contract: where anomaly documents go, and how a sink reports what it accepted.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol


@dataclass
class DeliveryResult:
    """
    Outcome of one ``emit`` call.

    ``accepted`` counts the documents accepted **from the start of the batch, in order**:
    documents after the first failure count as not accepted even if some of them arrived.
    The delivery watermark advances over exactly these, so the rest are offered again next run.
    """

    accepted: int
    total: int
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.accepted >= self.total


class AnomalySink(Protocol):
    """A destination for anomaly documents (as built by ``sonar/pipeline.py``)."""

    name: str
    """Configuration name of the sink, also its key in the delivery watermark."""

    def emit(self, docs: List[Dict[str, Any]]) -> DeliveryResult:
        """Deliver ``docs`` (oldest bucket first). Must not raise for delivery failures; report them."""
        ...
