"""AgentCore Platform v1.0"""

# FIN-C2-064 — agent state.
#
# State is a flat TypedDict, never a model object: checkpoints are serialized
# with msgpack, and a model instance does not survive that round trip intact.
# For the same reason a structured field (a mapping or a list of mappings) is
# stored as a JSON STRING rather than as a bare container — producers write with
# to_json(), consumers read with from_json().
#
# No credentials and no secrets belong in any field here.
#
# Account data: the entry node accepts only the declared transaction-event
# fields, each of them an inert identifier, a bounded number or a boolean, and
# drops everything else. Nothing a caller sends under an undeclared name reaches
# any field below, and no free text is stored anywhere in this schema.

import json
from typing import Any, Optional

from framework.schemas.agent_state import AgentState


def to_json(value: Any) -> Optional[str]:
    """Serialize a structured state field to a JSON string.

    None passes through unchanged, so an unset field stays distinguishable from
    an empty container.
    """
    if value is None:
        return None
    return json.dumps(value, ensure_ascii=False)


def from_json(value: Optional[str], default: Any = None) -> Any:
    """Read a JSON-string state field back to its container.

    A missing, empty or malformed value yields *default*, so a corrupt field is
    non-fatal for the consumer.
    """
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


class State(AgentState):
    """Flat state for FIN-C2-064.

    Shared fields (user_input, status, session_id, node_history, error_log and
    the rest) are inherited.
    """

    # ── Outer layer — written by PreProcessNode / the subgraph node ──────────

    # Canonical JSON of the accepted transaction-event fields. The caller's raw
    # payload is not stored: only fields that cleared the contract survive here.
    validated_input: Optional[str]

    # Provenance and routing, as a JSON string: {"source": str, "channel": str}.
    # Written after validation and carries no transaction data.
    enriched_context: Optional[str]

    # ── Inner layer — written by the domain nodes ────────────────────────────

    # Caller channel, seeded into the inner graph across the subgraph boundary.
    caller_channel: Optional[str]

    # Derived fraud signals, as a JSON string:
    # {"velocity": {...}, "geo_mismatch": {...}, "device": {...},
    #  "amount": {...}, "flags": [str]}
    fraud_signals: Optional[str]

    # Aggregate risk score in [0.0, 1.0].
    fraud_score: Optional[float]

    # Severity band: CRITICAL / HIGH / MEDIUM / LOW.
    severity: Optional[str]

    # Composed alert, as a JSON string. Carries a non-reversible reference, the
    # severity, the score, reasons from a fixed table, the recommended action,
    # the caller channel and a timestamp — and nothing else.
    alert_payload: Optional[str]

    # ── Tracing — framework-managed; not written by node code ────────────────

    trace_id: Optional[str]
    correlation_id: Optional[str]
