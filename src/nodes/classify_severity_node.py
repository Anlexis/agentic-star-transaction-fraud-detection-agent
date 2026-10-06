"""AgentCore Platform v1.0"""

# FIN-C2-064 — ClassifySeverityNode.
#
# Third inner domain node: map the risk score onto one of four severity bands.
# The banding is deterministic and threshold-based; the bands are declared in
# config/config.yaml so an operator can retune escalation without a code change.
#
# Bands are read through the same finite-and-bounded check as every other
# number. A declared band that is not finite would make `score >= band` False for
# every score, so a CRITICAL transaction would come out LOW — the one outcome
# this agent exists to prevent.

import logging
from typing import Any, ClassVar, Dict

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.runtime_config import domain_config

logger = logging.getLogger(__name__)

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

# Ordered high to low; the first band whose lower bound the score reaches wins.
SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW)

# Fallbacks used per band only where config/config.yaml declares none.
_DEFAULT_THRESHOLDS: Dict[str, float] = {
    CRITICAL: 0.85,
    HIGH: 0.60,
    MEDIUM: 0.30,
}


def _declared_thresholds() -> Dict[str, float]:
    """Merge the declared severity bands over the fallbacks."""
    thresholds = dict(_DEFAULT_THRESHOLDS)
    declared = domain_config().get("severity_thresholds", {})
    if not isinstance(declared, dict):
        return thresholds
    for band, value in declared.items():
        if band not in thresholds or isinstance(value, bool):
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if number != number or number in (float("inf"), float("-inf")):
            continue
        if 0.0 <= number <= 1.0:
            thresholds[band] = number
    return thresholds


def band_for(score: float, thresholds: Dict[str, float]) -> str:
    """Return the severity band for *score* using inclusive lower bounds."""
    if score >= thresholds[CRITICAL]:
        return CRITICAL
    if score >= thresholds[HIGH]:
        return HIGH
    if score >= thresholds[MEDIUM]:
        return MEDIUM
    return LOW


class ClassifySeverityNode(FunctionNode):
    """Classify alert severity from the fraud score.

    Input state keys:
        fraud_score: risk score in [0.0, 1.0] (ScoreFraudRiskNode)

    Output state keys (partial dict):
        severity: one of CRITICAL / HIGH / MEDIUM / LOW
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: AgentState) -> Dict[str, Any]:
        raw_score = state.get("fraud_score", 0.0)
        try:
            fraud_score = float(raw_score)
        except (TypeError, ValueError):
            fraud_score = 0.0
        if fraud_score != fraud_score or fraud_score in (float("inf"), float("-inf")):
            fraud_score = 0.0

        severity = band_for(fraud_score, _declared_thresholds())

        emit_trace_event(
            "fraud_severity_classified",
            {"fraud_score": fraud_score, "severity": severity},
            state,
        )

        logger.info("ClassifySeverityNode: score=%.4f -> severity=%s", fraud_score, severity)

        return {
            "severity": severity,
        }
