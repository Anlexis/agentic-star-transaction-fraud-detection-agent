"""AgentCore Platform v1.0"""

# FIN-C2-064 — ScoreFraudRiskNode.
#
# Second inner domain node: collapse the raised signal flags into one risk score
# in [0.0, 1.0]. The scoring is a deterministic weighted sum so the same event
# always produces the same score and the whole pipeline is testable offline.
#
# Weights come from config/config.yaml. Each declared weight is put through the
# same finite-and-bounded check the caller's numbers get: a weight that parses
# but is not finite would make every comparison downstream False, and the agent
# would report a clean transaction with no signal that anything went wrong.

import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.runtime_config import domain_config
from src.schemas.state import from_json

logger = logging.getLogger(__name__)

# Fallback weights, used per-signal only where config/config.yaml declares none.
# They sum to 1.0 so an all-signals event scores exactly 1.0.
_DEFAULT_WEIGHTS: Dict[str, float] = {
    "velocity_exceeded": 0.30,
    "geo_mismatch": 0.30,
    "new_device": 0.20,
    "high_amount": 0.20,
}


def _declared_weights() -> Dict[str, float]:
    """Merge the declared per-signal weights over the fallbacks."""
    weights = dict(_DEFAULT_WEIGHTS)
    declared = domain_config().get("signal_weights", {})
    if not isinstance(declared, dict):
        return weights
    for signal, value in declared.items():
        if signal not in weights or isinstance(value, bool):
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if number != number or number in (float("inf"), float("-inf")):
            continue
        if 0.0 <= number <= 1.0:
            weights[signal] = number
    return weights


class ScoreFraudRiskNode(FunctionNode):
    """Score fraud risk from the raised signal flags.

    Input state keys:
        fraud_signals: JSON string of the derived signals (ExtractFraudSignalsNode)

    Output state keys (partial dict):
        fraud_score: float in [0.0, 1.0], rounded to four decimal places
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: AgentState) -> Dict[str, Any]:
        signals = from_json(state.get("fraud_signals"), {})
        raw_flags = signals.get("flags", []) if isinstance(signals, dict) else []
        flags: List[str] = [f for f in raw_flags if isinstance(f, str)]

        weights = _declared_weights()
        score = 0.0
        for flag in flags:
            score += weights.get(flag, 0.0)

        fraud_score = round(max(0.0, min(1.0, score)), 4)

        emit_trace_event(
            "fraud_score_computed",
            {"fraud_score": fraud_score, "contributing_flags": list(flags)},
            state,
        )

        logger.info("ScoreFraudRiskNode: fraud_score=%.4f from %d flag(s)", fraud_score, len(flags))

        return {
            "fraud_score": fraud_score,
        }
