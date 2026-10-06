"""AgentCore Platform v1.0"""

# FIN-C2-064 — ExtractFraudSignalsNode.
#
# First inner domain node: turn the validated transaction event into the four
# fraud signals the rest of the pipeline scores. Everything it reads has already
# cleared the caller contract, so this node does no re-validation and no
# rewriting — it derives.
#
# Thresholds come from config/config.yaml. They used to be read from a `config`
# argument on execute(), which the node runner never supplies, so every declared
# threshold was dead and the in-code fallback was always what ran.

import json
import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.runtime_config import domain_config
from src.schemas.state import to_json

logger = logging.getLogger(__name__)

# Fallbacks used only when config/config.yaml declares no value.
_DEFAULT_VELOCITY_WINDOW_MAX = 5.0
_DEFAULT_HIGH_AMOUNT = 1000.0

VELOCITY_EXCEEDED = "velocity_exceeded"
GEO_MISMATCH = "geo_mismatch"
NEW_DEVICE = "new_device"
HIGH_AMOUNT = "high_amount"


def _declared_float(key: str, fallback: float) -> float:
    """Read a declared threshold, falling back only when it is absent or unusable."""
    value = domain_config().get(key, fallback)
    if isinstance(value, bool):
        return fallback
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    if number != number or number in (float("inf"), float("-inf")):
        return fallback
    return number


class ExtractFraudSignalsNode(FunctionNode):
    """Derive fraud signals from the validated transaction event.

    Input state keys:
        validated_input / user_input: canonical JSON of the accepted fields

    Output state keys (partial dict):
        fraud_signals: JSON string of the derived signals and raised flags
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: AgentState) -> Dict[str, Any]:
        payload = state.get("validated_input") or state.get("user_input", "")
        try:
            event = json.loads(payload) if isinstance(payload, str) else {}
        except (json.JSONDecodeError, ValueError):
            event = {}
        if not isinstance(event, dict):
            event = {}

        velocity_max = _declared_float("velocity_window_max", _DEFAULT_VELOCITY_WINDOW_MAX)
        high_amount = _declared_float("high_amount_threshold", _DEFAULT_HIGH_AMOUNT)

        flags: List[str] = []

        txn_count = float(event.get("recent_txn_count", 0.0) or 0.0)
        velocity = {
            "recent_txn_count": txn_count,
            "window_max": velocity_max,
            "exceeded": txn_count > velocity_max,
        }
        if velocity["exceeded"]:
            flags.append(VELOCITY_EXCEEDED)

        txn_country = str(event.get("txn_country", "")).strip().upper()
        home_country = str(event.get("home_country", "")).strip().upper()
        geo_mismatch = {
            "txn_country": txn_country,
            "home_country": home_country,
            "mismatch": bool(txn_country and home_country and txn_country != home_country),
        }
        if geo_mismatch["mismatch"]:
            flags.append(GEO_MISMATCH)

        device_id = str(event.get("device_id", "")).strip()
        device_known = bool(event.get("device_known", False))
        device = {
            "device_id_present": bool(device_id),
            "device_known": device_known,
            "new_device": bool(device_id) and not device_known,
        }
        if device["new_device"]:
            flags.append(NEW_DEVICE)

        amount_value = float(event.get("amount", 0.0) or 0.0)
        amount = {
            "value": amount_value,
            "high_amount_threshold": high_amount,
            "is_high": amount_value > high_amount,
        }
        if amount["is_high"]:
            flags.append(HIGH_AMOUNT)

        fraud_signals: Dict[str, Any] = {
            "velocity": velocity,
            "geo_mismatch": geo_mismatch,
            "device": device,
            "amount": amount,
            "flags": flags,
        }

        emit_trace_event(
            "fraud_signals_extracted",
            {"flag_count": len(flags), "flags": flags},
            state,
        )

        logger.info(
            "ExtractFraudSignalsNode: %d flag(s) raised (%s)",
            len(flags),
            ", ".join(flags) if flags else "none",
        )

        return {
            "fraud_signals": to_json(fraud_signals),
        }
