"""Unbounded consumption detector — reads BehaviorEngine limits + raw event."""
from __future__ import annotations

from firewall.core.events import Detection, SecurityEvent


class ConsumptionDetector:
    NAME = "consumption"

    def __init__(self,
                 max_input_chars: int = 200_000,
                 max_output_chars: int = 200_000,
                 max_docs: int = 50):
        self.max_input_chars = max_input_chars
        self.max_output_chars = max_output_chars
        self.max_docs = max_docs

    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        if event.input_text and len(event.input_text) > self.max_input_chars:
            out.append(Detection(
                detector=self.NAME, category="unbounded_consumption",
                subcategory="oversize_input",
                severity="medium", confidence=1.0,
                message=f"input length {len(event.input_text)} > {self.max_input_chars}",
            ))
        if event.output_text and len(event.output_text) > self.max_output_chars:
            out.append(Detection(
                detector=self.NAME, category="unbounded_consumption",
                subcategory="oversize_output",
                severity="medium", confidence=1.0,
                message=f"output length {len(event.output_text)} > {self.max_output_chars}",
            ))
        if len(event.context_docs) > self.max_docs:
            out.append(Detection(
                detector=self.NAME, category="unbounded_consumption",
                subcategory="excessive_retrieval",
                severity="medium", confidence=1.0,
                message=f"context_docs {len(event.context_docs)} > {self.max_docs}",
            ))
        return out
