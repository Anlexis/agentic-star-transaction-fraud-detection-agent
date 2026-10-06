"""AgentCore Platform v1.0"""

# FIN-C2-064 — inner domain workflow graph.
#
# The whole fraud-detection pipeline, as a graph of its own:
#
#   START -> extract_fraud_signals -> score_fraud_risk -> classify_severity
#         -> compose_dispatch_alert -> END
#
# Built by FraudDetectionGraphNode.get_subgraph(). get_output() shapes the dict
# that node's merge_output() consumes; the two are written together.

from typing import Any, Dict

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus

from src.graph.context_bridge import caller_channel
from src.nodes.classify_severity_node import ClassifySeverityNode
from src.nodes.compose_dispatch_alert_node import ComposeDispatchAlertNode
from src.nodes.extract_fraud_signals_node import ExtractFraudSignalsNode
from src.nodes.score_fraud_risk_node import ScoreFraudRiskNode
from src.schemas.state import State


class DomainWorkflowGraph(BaseGraph):
    """Inner graph carrying the fraud-detection topology.

    Every node is a function node returning a partial state update. The
    initialize and finalize slots belong to the outer backbone and are not
    registered here.
    """

    @property
    def name(self) -> str:
        """Unique identifier for this inner graph."""
        return "fin_c2_064_fraud_detection_workflow"

    @property
    def state_schema(self) -> type:
        """State shape, shared with the outer graph."""
        return State

    def _validate_config(self) -> None:
        """No inner-graph configuration to validate.

        Every declared threshold is read from the runtime configuration by the
        node that owns it, and each one falls back to a documented default, so
        there is nothing this graph must hold before it can compile.
        """

    def _extra_initial_state(self) -> Dict[str, Any]:
        """Seed the caller context the subgraph boundary does not carry across.

        A subgraph is invoked with a payload string and a fresh invocation
        context; the parent's caller context does not travel with it. The parent
        stashes it on the way past and it is read back here.
        """
        return {"caller_channel": caller_channel()}

    def register_nodes(self) -> None:
        """Register the four domain nodes.

        No super() call — the base method is abstract. Every key registered here
        appears in add_edges().
        """
        self._nodes["extract_fraud_signals"] = ExtractFraudSignalsNode()
        self._nodes["score_fraud_risk"] = ScoreFraudRiskNode()
        self._nodes["classify_severity"] = ClassifySeverityNode()
        self._nodes["compose_dispatch_alert"] = ComposeDispatchAlertNode()

    def add_edges(self) -> None:
        """Wire the pipeline.

        The topology is linear by design: every event goes through all four
        steps, so there is no conditional edge and route() is never consulted.
        """
        self._sg.add_edge(START, "extract_fraud_signals")
        self._sg.add_edge("extract_fraud_signals", "score_fraud_risk")
        self._sg.add_edge("score_fraud_risk", "classify_severity")
        self._sg.add_edge("classify_severity", "compose_dispatch_alert")
        self._sg.add_edge("compose_dispatch_alert", END)

    def route(self, state: State) -> str:
        """Required by the base contract; unused with a linear topology.

        Annotated with this graph's own State: a path callable's annotation is
        read as its input schema and fields outside it are projected away, so an
        annotation naming a wider type would hide the very fields a route needs.
        Returns END on error so an unexpected call cannot re-enter a node.
        """
        if state.get("status") == AgentStatus.ERROR.value:
            return END
        return "compose_dispatch_alert"

    def get_output(self, state: AgentState) -> Dict[str, Any]:
        """Shape the dict returned to the outer graph.

        Read by FraudDetectionGraphNode.merge_output(). Values are surfaced as
        they are — there is no `or` fallback between fields here, because that
        shape lets a blanked field be replaced by an earlier, ungated one.
        """
        return {
            "alert_payload": state.get("alert_payload"),
            "status": state.get("status"),
            "fraud_score": state.get("fraud_score"),
            "severity": state.get("severity"),
            "fraud_signals": state.get("fraud_signals"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }
