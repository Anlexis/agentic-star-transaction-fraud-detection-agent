"""AgentCore Platform v1.0"""

# FIN-C2-064 — PostProcessNode (outer post_process slot): the output boundary.
#
# The alert this agent emits is a closed shape, so the boundary check is
# structural rather than a search for bad substrings: the payload must carry
# exactly the declared keys, and every value must be drawn from the set that key
# is allowed to hold. A pattern scan can only refuse what somebody thought of;
# an allow-list refuses everything nobody did. The credential and account-number
# scans still run underneath it, because a shape check alone would pass a value
# that is well-formed and still must not be released.
#
# On refusal the node returns ERROR *and blanks the output-bearing fields*.
# Raising is not enough and neither is an error status on its own: the agent's
# output is resolved as `formatted_output or result`, with no status check, so an
# error that leaves `result` populated ships the ungated payload inside the error
# envelope, and an empty string in `formatted_output` re-opens the same fallback.
# The replacement notice is therefore non-empty, and every field that could carry
# payload text is written back as empty — present in the returned mapping, not
# merely omitted from it, because partial state updates are merged and an omitted
# key leaves the previous value in place.
#
# The refusal reason names a category and a location. It never carries the value
# that produced it, nor any substring of it.

import json
import logging
import re
from typing import Any, ClassVar, Dict, Final, Optional, Tuple

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from framework.security.credential_detector import detect_credentials
from shared.utils.audit_logger import emit_trace_event

from src.nodes.compose_dispatch_alert_node import (
    ALERT_REF_PREFIX,
    FLAG_REASONS,
    NO_SIGNAL_REASON,
    SEVERITY_ACTION,
)

logger = logging.getLogger(__name__)

# The alert's declared shape.
_REQUIRED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "alert_id",
        "txn_ref_masked",
        "severity",
        "fraud_score",
        "reasons",
        "recommended_action",
        "channel",
        "generated_at",
    }
)
_REFERENCE = re.compile(rf"^{re.escape(ALERT_REF_PREFIX)}[0-9A-F]{{12}}$")
_CHANNEL = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$")
_ALLOWED_REASONS: Final[frozenset[str]] = frozenset({*FLAG_REASONS.values(), NO_SIGNAL_REASON})
_MAX_REASONS: Final[int] = len(FLAG_REASONS)

# An account-number-shaped run must never appear in a dispatched alert.
_ACCOUNT_NUMBER = re.compile(r"(?<![0-9])(?:[0-9][ -]?){13,19}(?![0-9])")

# Closed set of refusal reasons.
REASON_UNSUPPORTED_SHAPE: Final[str] = "unsupported_payload_shape"
REASON_UNDECLARED_FIELD: Final[str] = "undeclared_field"
REASON_MISSING_FIELD: Final[str] = "missing_field"
REASON_FIELD_OUT_OF_CONTRACT: Final[str] = "field_outside_declared_values"
REASON_ACCOUNT_NUMBER: Final[str] = "account_number_present"
REASON_CREDENTIAL_SHAPE: Final[str] = "credential_shaped_value"
REASON_UNEXPECTED_FAILURE: Final[str] = "boundary_check_failed"

WITHHELD_NOTICE: Final[str] = (
    "Alert withheld: the composed alert did not satisfy the output contract and "
    "was not released. No alert content is included in this response."
)

# Fields that can carry alert text. Every one is written back empty on refusal.
_OUTPUT_BEARING_FIELDS: Final[Tuple[str, ...]] = ("result", "alert_payload")


def _check_alert(payload: str) -> Optional[str]:
    """Return a refusal reason for *payload*, or None when it satisfies the contract."""
    try:
        alert = json.loads(payload)
    except (json.JSONDecodeError, ValueError):
        return REASON_UNSUPPORTED_SHAPE
    if not isinstance(alert, dict):
        return REASON_UNSUPPORTED_SHAPE

    keys = set(alert)
    if keys - _REQUIRED_KEYS:
        return REASON_UNDECLARED_FIELD
    if _REQUIRED_KEYS - keys:
        return REASON_MISSING_FIELD

    reference = alert["alert_id"]
    if not isinstance(reference, str) or not _REFERENCE.match(reference):
        return REASON_FIELD_OUT_OF_CONTRACT
    if alert["txn_ref_masked"] != reference:
        return REASON_FIELD_OUT_OF_CONTRACT
    if alert["severity"] not in SEVERITY_ACTION:
        return REASON_FIELD_OUT_OF_CONTRACT
    if alert["recommended_action"] != SEVERITY_ACTION[alert["severity"]]:
        return REASON_FIELD_OUT_OF_CONTRACT

    score = alert["fraud_score"]
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return REASON_FIELD_OUT_OF_CONTRACT
    score = float(score)
    if score != score or score in (float("inf"), float("-inf")) or not 0.0 <= score <= 1.0:
        return REASON_FIELD_OUT_OF_CONTRACT

    reasons = alert["reasons"]
    if not isinstance(reasons, list) or not 1 <= len(reasons) <= _MAX_REASONS:
        return REASON_FIELD_OUT_OF_CONTRACT
    if any(reason not in _ALLOWED_REASONS for reason in reasons):
        return REASON_FIELD_OUT_OF_CONTRACT

    channel = alert["channel"]
    if not isinstance(channel, str) or not _CHANNEL.match(channel):
        return REASON_FIELD_OUT_OF_CONTRACT

    generated_at = alert["generated_at"]
    if not isinstance(generated_at, str) or not _TIMESTAMP.match(generated_at):
        return REASON_FIELD_OUT_OF_CONTRACT

    # Independent of the shape check: the same scan the framework runs at every
    # node boundary, so a value it would catch cannot pass here and then make the
    # framework raise afterwards — which would discard this node's blanking.
    if detect_credentials(payload):
        return REASON_CREDENTIAL_SHAPE
    if _ACCOUNT_NUMBER.search(payload):
        return REASON_ACCOUNT_NUMBER
    return None


class PostProcessNode(FunctionNode):
    """Enforce the alert's output contract before the response leaves the agent.

    Input state keys:
        result: composed alert, mapped from the inner graph's alert_payload

    Output state keys (partial dict):
        formatted_output: the alert when it satisfies the contract, otherwise a
                          non-empty withheld notice
        result / alert_payload: blanked on refusal
        status:           SUCCESS or ERROR
        error_log:        (on refusal) the category and location, never the value
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def _withhold(self, reason: str, state: AgentState) -> Dict[str, Any]:
        logger.error("PostProcessNode: alert withheld at the output boundary (%s)", reason)
        emit_trace_event("fraud_alert_withheld", {"reason": reason}, state)
        cleared: Dict[str, Any] = {field: "" for field in _OUTPUT_BEARING_FIELDS}
        return {
            **cleared,
            "formatted_output": WITHHELD_NOTICE,
            "status": AgentStatus.ERROR.value,
            "error_log": [f"output boundary: alert withheld — {reason}"],
        }

    def execute(self, state: AgentState) -> Dict[str, Any]:
        try:
            result = state.get("result")
            if not isinstance(result, str) or not result.strip():
                return self._withhold(REASON_UNSUPPORTED_SHAPE, state)

            reason = _check_alert(result)
            if reason is not None:
                return self._withhold(reason, state)

            emit_trace_event(
                "fraud_alert_emitted",
                {"alert_chars": len(result)},
                state,
            )

            return {
                "formatted_output": result,
                "status": AgentStatus.SUCCESS.value,
            }
        except Exception:  # noqa: BLE001 — a boundary that raises releases the payload
            # An exception here would be turned into a bare error update that
            # blanks nothing, and the ungated payload would be surfaced by the
            # `formatted_output or result` fallback. Withholding is the only safe
            # outcome for a check that could not complete.
            logger.exception("PostProcessNode: output boundary check failed")
            return self._withhold(REASON_UNEXPECTED_FAILURE, state)
