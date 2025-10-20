from heuristics.engine import HeuristicEngine, HeuristicSignal


def test_heuristics_scoring_balanced() -> None:
    engine = HeuristicEngine()
    signals = [
        HeuristicSignal(name="unsigned_binary", weight=1.0, score=0.5, rationale="Unsigned"),
        HeuristicSignal(name="network_activity", weight=1.0, score=0.8, rationale="Network"),
    ]
    confidence, cause = engine.evaluate(signals)
    assert 50 <= confidence <= 100
    assert "Unsigned" in cause


def test_heuristics_no_signals() -> None:
    engine = HeuristicEngine()
    confidence, cause = engine.evaluate([])
    assert confidence == 0
    assert cause == "No signals"
