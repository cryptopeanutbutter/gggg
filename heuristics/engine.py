"""Heuristics engine for WHOIS Watching."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Tuple

import math


@dataclass
class HeuristicSignal:
    name: str
    weight: float
    score: float
    rationale: str


class HeuristicEngine:
    """Lightweight, explainable heuristic scoring."""

    def __init__(self, weights: Dict[str, float] | None = None) -> None:
        self.weights = weights or {
            "unsigned_binary": 1.2,
            "suspicious_command": 1.0,
            "network_activity": 1.1,
            "dll_anomaly": 0.8,
            "timestamp_gap": 0.6,
        }

    def evaluate(self, signals: Iterable[HeuristicSignal]) -> Tuple[int, str]:
        total_weight = 0.0
        weighted_score = 0.0
        rationales = []
        for signal in signals:
            weight = self.weights.get(signal.name, signal.weight)
            total_weight += weight
            weighted_score += weight * signal.score
            rationales.append(f"{signal.name}: {signal.rationale} ({signal.score:.2f})")
        if total_weight == 0:
            return 0, "No signals"
        normalized = min(100, max(0, int(math.ceil((weighted_score / total_weight) * 100))))
        probable_cause = "; ".join(rationales[:5])
        return normalized, probable_cause
