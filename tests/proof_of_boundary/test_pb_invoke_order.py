# Invoke-order boundary: a full invocation runs the backbone in order.
#
# The backbone is fixed by the framework and is not overridden by this template:
#
#     START -> initialize -> pre_process -> main -> {route} -> post_process
#           -> finalize -> END
#
# Every executed node is recorded in node_history by class name, in execution
# order. The `main` slot here is a subgraph node, and the inner pipeline runs
# with its own state, so the inner steps do not appear in the outer history.
#
# The run is driven at the trust level the manifest publishes, not at the
# highest level available. Driving it at the highest level would prove the
# pipeline can run for an in-platform caller while saying nothing about whether
# it can run for the callers it is published for — which is exactly the gap that
# lets an agent ship unable to answer anything.

import json

from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import Graph

# The subgraph node filling the `main` slot for this template. The other four
# slot names are framework-fixed.
MAIN_SLOT_NODE = "FraudDetectionGraphNode"

# A conforming transaction event that drives the pipeline to a terminal success.
# Kept identical to deploy/invoke_payload.json so the shape proven here is the
# shape a deployment is exercised with.
VALID_PAYLOAD = json.dumps(
    {
        "txn_id": "TXN-20260904-001",
        "amount": 25000,
        "recent_txn_count": 9,
        "txn_country": "US",
        "home_country": "JP",
        "device_id": "dev-77",
        "device_known": False,
    }
)

EXPECTED_ORDER = [
    "InitializeNode",
    "PreProcessNode",
    MAIN_SLOT_NODE,
    "PostProcessNode",
    "FinalizeNode",
]


def _run() -> dict:
    """Run a full invocation at the published trust level."""
    agent = Graph()
    agent.compile()
    return agent.invoke(
        VALID_PAYLOAD,
        ctx=InvocationContext(session_id="invoke-order", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL),
    )


class TestInvokeOrderBoundary:
    def test_invoke_reaches_success(self):
        """A non-success status routes the run straight to finalize and skips
        the output boundary, which is itself an ordering violation."""
        result = _run()
        assert result.get("status") == AgentStatus.SUCCESS.value, result

    def test_output_is_non_empty(self):
        assert _run().get("output")

    def test_node_history_is_populated(self):
        history = _run().get("node_history")
        assert isinstance(history, list) and history
        assert all(isinstance(entry, str) for entry in history)

    def test_backbone_slot_order(self):
        history = _run().get("node_history", [])
        slots = ["PreProcessNode", MAIN_SLOT_NODE, "PostProcessNode"]
        for name in slots:
            assert name in history, history
        positions = [history.index(name) for name in slots]
        assert positions == sorted(positions), history

    def test_full_backbone_sequence(self):
        assert _run().get("node_history", []) == EXPECTED_ORDER

    def test_inner_steps_stay_inside_the_subgraph(self):
        history = _run().get("node_history", [])
        assert "ExtractFraudSignalsNode" not in history
        assert "ComposeDispatchAlertNode" not in history
