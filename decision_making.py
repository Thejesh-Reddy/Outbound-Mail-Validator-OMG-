"""Central OMG decision-making entry point.

The orchestration and verdict policy are implemented in the decision_engine
package; this module exposes the stable public entry point.
"""
from decision_engine.orchestrator import analyze_email
from decision_engine.decision_aggregator import decide_verdict
from decision_engine.finding_policy import action_for_finding, FindingAction, is_hard_block_finding
from decision_engine.scoring import calculate_safety_score

__all__ = [
    "analyze_email", "decide_verdict", "action_for_finding",
    "FindingAction", "is_hard_block_finding", "calculate_safety_score",
]
