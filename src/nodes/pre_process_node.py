"""AgentCore Platform v1.0"""

# FIN-C2-064 — PreProcessNode (outer pre_process slot).
#
# This node owns the caller contract. It is the only place a caller's bytes are
# turned into something the fraud pipeline is allowed to read, so refusal is
# enforced here rather than being left to the framework's own screens: those
# screens are configuration, and a template that depends on them is only as safe
# as the deployment it lands in.
#
# What it guarantees for everything downstream:
#   - the payload is a transaction event of the declared shape, within bounds;
#   - every number is finite and inside its range, so no threshold comparison
#     can silently evaluate False against a non-finite value;
#   - every string is an inert identifier — no free text, so nothing a caller
#     writes can be rendered as prose in the dispatched alert;
#   - no account-number-shaped value survives into state;
#   - no chat-template control marker survives, in a value or in a field name.
#
# Node contract: extend FunctionNode, implement execute(state) -> dict, return
# only the fields this node changes, and return AgentStatus enum values.

from typing import Any, ClassVar, Dict

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from shared.utils.audit_logger import emit_trace_event

from src.schemas.state import to_json
from src.services.service import (
    EventContractError,
    canonical_event,
    validate_event,
    validated_context,
)

_AGENT_SOURCE = "RealTimeTransactionFraudDetectionAlertAgent"


class PreProcessNode(FunctionNode):
    """Validate the caller's transaction event and admit only the declared fields.

    Input state keys:
        user_input:     raw transaction event, expected to be a JSON object
        input_context:  caller context, read-only; only declared keys are used

    Output state keys (partial dict):
        validated_input:  canonical JSON of the accepted fields
        enriched_context: provenance and caller channel, as a JSON string
        status:           SUCCESS, or ERROR with error_log on refusal
    """

    # The manifest publishes VERIFIED_EXTERNAL as this agent's trust contract, so
    # the entry node enforces exactly that: an anonymous caller is refused here,
    # at the boundary that can say why.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: AgentState) -> Dict[str, Any]:
        raw_context = state.get("input_context", {})  # read-only

        try:
            accepted = validate_event(state.get("user_input", ""))
            validated_input = canonical_event(accepted)
        except EventContractError as exc:
            # The field is named; the value that failed is never echoed.
            emit_trace_event(
                "fraud_evaluation_request_refused",
                {"field": exc.field, "reason": exc.reason},
                state,
            )
            _error_lines = [exc.as_message()]
            # The runner surfaces `formatted_output or result` as `output`. A reason left only in
            # error_log reaches no one: the terminal result carries just `status`, and get_output()
            # does not copy error_log out of the graph -- the caller sees a blank spinner.
            # The list is bound once: repeating the expression inline would evaluate it twice.
            return {
                "status": AgentStatus.ERROR.value,
                "error_log": _error_lines,
                "formatted_output": "Request could not be completed. "
                + "; ".join(str(_line) for _line in _error_lines),
            }

        emit_trace_event(
            "fraud_evaluation_request_accepted",
            {"field_count": len(accepted), "fields": sorted(accepted)},
            state,
        )

        # Provenance and routing only. Structured state fields are stored as JSON
        # strings because checkpoint serialization does not round-trip bare
        # containers; consumers read them back with from_json().
        context: Dict[str, Any] = validated_context(raw_context if isinstance(raw_context, dict) else {})
        enriched_context = {
            "source": _AGENT_SOURCE,
            "channel": context.get("channel", "unknown"),
        }

        return {
            "validated_input": validated_input,
            "enriched_context": to_json(enriched_context),
            "status": AgentStatus.SUCCESS.value,
        }
