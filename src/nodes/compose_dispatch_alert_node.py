"""AgentCore Platform v1.0"""

# FIN-C2-064 — ComposeDispatchAlertNode.
#
# Terminal inner domain node: assemble the alert the dispatch channel receives.
# The agent does not deliver the alert itself; delivery belongs to the customer
# integration, and this node produces the payload it is given.
#
# What the alert may contain is a closed set: a reference, a severity label, a
# score, reasons drawn from a fixed table, a recommended action drawn from a
# fixed table, a timestamp, and the caller's channel. Nothing a caller wrote is
# rendered as text — the transaction identifier appears only as a digest of
# itself, so an account number sent as an identifier cannot reach a reader even
# though it is a well-formed identifier.
#
# The reference is derived from the caller's transaction id where one was
# supplied. It used to be a digest of severity plus flags, which meant two
# unrelated transactions with the same signals shared one alert id and an
# analyst could not tell them apart.

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.graph.context_bridge import UNKNOWN_CHANNEL
from src.schemas.state import from_json, to_json

logger = logging.getLogger(__name__)

# Reason text per signal flag. Closed set — the alert never renders caller text.
FLAG_REASONS: Dict[str, str] = {
    "velocity_exceeded": "Transaction velocity exceeded the allowed window.",
    "geo_mismatch": "Transaction country differs from the cardholder home country.",
    "new_device": "Transaction originated from an unrecognized device.",
    "high_amount": "Transaction amount exceeded the high-value threshold.",
}
NO_SIGNAL_REASON = "No individual fraud signals were triggered."

# Recommended action per severity band. Closed set.
SEVERITY_ACTION: Dict[str, str] = {
    "CRITICAL": "Block transaction and open a fraud case immediately.",
    "HIGH": "Hold transaction for manual review and notify the cardholder.",
    "MEDIUM": "Flag transaction for monitoring and step-up authentication.",
    "LOW": "Allow transaction; record for trend analysis.",
}

ALERT_REF_PREFIX = "TXN-"
_REF_DIGEST_CHARS = 12
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M UTC"


def masked_reference(txn_id: str, severity: str, flags: List[str]) -> str:
    """Return a stable, non-reversible reference for the transaction.

    Hashing rather than truncating is deliberate: a truncated identifier still
    carries part of whatever the caller sent, and part of an account number is
    still account data.
    """
    basis = "|".join([txn_id, severity, *sorted(flags)])
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:_REF_DIGEST_CHARS]
    return f"{ALERT_REF_PREFIX}{digest.upper()}"


class ComposeDispatchAlertNode(FunctionNode):
    """Compose the fraud-alert payload for dispatch.

    Input state keys:
        validated_input / user_input: canonical JSON of the accepted fields
        fraud_signals: JSON string of the derived signals
        fraud_score:   risk score in [0.0, 1.0]
        severity:      severity band
        caller_channel: caller channel carried across the subgraph boundary

    Output state keys (partial dict):
        alert_payload: JSON string of the composed alert
        status:        SUCCESS
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: AgentState) -> Dict[str, Any]:
        signals = from_json(state.get("fraud_signals"), {})
        raw_flags = signals.get("flags", []) if isinstance(signals, dict) else []
        flags: List[str] = [f for f in raw_flags if isinstance(f, str)]

        raw_score = state.get("fraud_score", 0.0)
        try:
            fraud_score = float(raw_score)
        except (TypeError, ValueError):
            fraud_score = 0.0
        if fraud_score != fraud_score or fraud_score in (float("inf"), float("-inf")):
            fraud_score = 0.0

        severity = str(state.get("severity", "LOW")).upper()
        if severity not in SEVERITY_ACTION:
            severity = "LOW"

        event = from_json(state.get("validated_input") or state.get("user_input"), {})
        txn_id = event.get("txn_id", "") if isinstance(event, dict) else ""
        reference = masked_reference(str(txn_id), severity, flags)

        channel = str(state.get("caller_channel") or UNKNOWN_CHANNEL)

        reasons: List[str] = [FLAG_REASONS[f] for f in flags if f in FLAG_REASONS]
        if not reasons:
            reasons.append(NO_SIGNAL_REASON)

        alert_payload: Dict[str, Any] = {
            "alert_id": reference,
            "txn_ref_masked": reference,
            "severity": severity,
            "fraud_score": fraud_score,
            "reasons": reasons,
            "recommended_action": SEVERITY_ACTION[severity],
            "channel": channel,
            "generated_at": datetime.now(tz=timezone.utc).strftime(TIMESTAMP_FORMAT),
        }

        emit_trace_event(
            "fraud_alert_composed",
            {
                "alert_id": reference,
                "severity": severity,
                "reason_count": len(reasons),
            },
            state,
        )

        logger.info(
            "ComposeDispatchAlertNode: alert %s composed (severity=%s, score=%.4f)",
            reference,
            severity,
            fraud_score,
        )

        return {
            "alert_payload": to_json(alert_payload),
            "status": AgentStatus.SUCCESS.value,
        }
