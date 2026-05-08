import unittest
from python_orchestrator.agents.scoring import RiskScoringEngine

class TestScoring(unittest.TestCase):
    def test_score_increases_when_not_detected(self):
        engine = RiskScoringEngine({"severity":0.4,"asset_criticality":0.25,"detectability_gap":0.2,"reproducibility":0.15})
        detected = engine.score(3, True, True, "medium")
        gap = engine.score(3, False, True, "medium")
        self.assertGreater(gap, detected)

if __name__ == "__main__":
    unittest.main()
