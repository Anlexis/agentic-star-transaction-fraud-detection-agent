"""AgentCore Platform v1.0"""

# FIN-C2-064 — outer graph.
#
# Real-time transaction fraud detection and alert agent.
#
# The outer backbone is fixed by the framework and is not overridden here:
#
#   START -> initialize -> pre_process -> main -> {route} -> post_process
#         -> finalize -> END
#
# The `main` slot is a subgraph node that delegates the whole fraud-detection
# workflow to DomainWorkflowGraph, so the domain topology lives in one place and
# the backbone stays untouched.
#
#   src/graph/graph.py                 - outer graph (this file)
#   src/graph/domain_workflow_graph.py - inner graph (the domain topology)

from typing import Any, ClassVar, Dict

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.trust_level import TrustLevel
from framework.schemas.agent_state import AgentState

from src.graph.context_bridge import stash_caller_context
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.schemas.state import State, from_json


class FraudDetectionGraphNode(GraphNode):
    """Subgraph node in the `main` slot; runs DomainWorkflowGraph.

    Contracts:
      get_subgraph()  - build the inner graph
      extract_input() - the single string handed to the inner graph
      merge_output()  - map the inner result into the outer state delta
      error_strategy  - "propagate": an inner failure re-raises here, so no
                        partial inner result is merged into outer state
    """

    # S-1 declared on the wrapper too: the CI gate only AST-scans FunctionNode
    # subclasses, so a GraphNode main slot passes the pipeline without one and is
    # flagged at review. Same level the nodes in this repo already declare.
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    error_strategy: ClassVar[str] = "propagate"

    # Interrupts are handled inside the inner graph; none is surfaced outward.
    propagate_hitl: ClassVar[bool] = False

    def get_subgraph(self) -> Any:
        """Build the inner domain workflow graph.

        Imported inside the method to keep module import order independent of
        the inner graph. The inner graph takes no constructor arguments — its
        nodes read declared values from the runtime configuration.
        """
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        return DomainWorkflowGraph()

    def extract_input(self, state: AgentState) -> str:
        """Return the payload string the inner graph runs on.

        The inner graph receives a string and a fresh invocation context, so the
        caller's channel is stashed on the way past — otherwise the alert cannot
        report where the transaction came from.
        """
        context = from_json(state.get("enriched_context"), {})
        channel = context.get("channel", "") if isinstance(context, dict) else ""
        stash_caller_context({"channel": str(channel)} if channel else {})
        return str(state.get("validated_input") or state.get("user_input") or "")

    def merge_output(self, state: AgentState, sub_result: Dict[str, Any]) -> Dict[str, Any]:
        """Map the inner result into the outer state delta (changed keys only).

        The inner graph emits the composed alert under `alert_payload`; the
        output boundary in the post_process slot reads `result`, so the same
        value is mapped to both. This method runs on the inner success path
        only — an inner failure raises before it is reached.
        """
        return {
            "alert_payload": sub_result.get("alert_payload"),
            "result": sub_result.get("alert_payload"),
            "status": sub_result.get("status"),
        }


class FinC2064Agent(AgentBaseGraph):
    """Outer graph for FIN-C2-064.

    register_nodes() is the only override: the framework fills the initialize and
    finalize slots, this fills the three in between. Backbone wiring belongs to
    the framework and add_edges() is not overridden.
    """

    @property
    def name(self) -> str:
        """Agent identifier under which this graph is registered."""
        return "RealTimeTransactionFraudDetectionAlertAgent"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        """Fill the five backbone slots."""
        super().register_nodes()  # initialize + finalize

        self._nodes["pre_process"] = PreProcessNode()
        self._nodes["main"] = FraudDetectionGraphNode()
        self._nodes["post_process"] = PostProcessNode()


# Referred to by config/agent.yaml and imported by src/api/server.py.
Graph = FinC2064Agent
