# Graph composition: the backbone slots, the subgraph boundary, and the trust
# floor the manifest publishes.

import json

import pytest

from framework.graph.agent_base_graph import AgentBaseGraph
from framework.graph.base_graph import BaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.context_bridge import UNKNOWN_CHANNEL, caller_channel, stash_caller_context
from src.graph.domain_workflow_graph import DomainWorkflowGraph
from src.graph.graph import FinC2064Agent, FraudDetectionGraphNode, Graph
from src.nodes.classify_severity_node import ClassifySeverityNode
from src.nodes.compose_dispatch_alert_node import ComposeDispatchAlertNode
from src.nodes.extract_fraud_signals_node import ExtractFraudSignalsNode
from src.nodes.post_process_node import PostProcessNode
from src.nodes.pre_process_node import PreProcessNode
from src.nodes.score_fraud_risk_node import ScoreFraudRiskNode
from src.schemas.state import State, to_json

VALID_EVENT = json.dumps(
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


class TestOuterGraph:
    def test_inherits_the_framework_base_directly(self):
        assert issubclass(FinC2064Agent, AgentBaseGraph)

    def test_alias_points_at_the_agent(self):
        assert Graph is FinC2064Agent

    def test_state_schema_is_the_template_state(self):
        assert FinC2064Agent().state_schema is State

    def test_backbone_slots_are_filled(self):
        agent = FinC2064Agent()
        agent.register_nodes()
        assert isinstance(agent._nodes["pre_process"], PreProcessNode)
        assert isinstance(agent._nodes["main"], FraudDetectionGraphNode)
        assert isinstance(agent._nodes["post_process"], PostProcessNode)
        assert agent._nodes["initialize"] is not None
        assert agent._nodes["finalize"] is not None

    def test_backbone_wiring_is_not_overridden(self):
        assert "add_edges" not in FinC2064Agent.__dict__

    def test_compiles(self):
        agent = FinC2064Agent()
        agent.compile()
        assert agent._compiled is not None


class TestInnerGraph:
    def test_inherits_the_base_graph(self):
        assert issubclass(DomainWorkflowGraph, BaseGraph)

    def test_registers_the_four_domain_steps(self):
        inner = DomainWorkflowGraph()
        inner.register_nodes()
        assert isinstance(inner._nodes["extract_fraud_signals"], ExtractFraudSignalsNode)
        assert isinstance(inner._nodes["score_fraud_risk"], ScoreFraudRiskNode)
        assert isinstance(inner._nodes["classify_severity"], ClassifySeverityNode)
        assert isinstance(inner._nodes["compose_dispatch_alert"], ComposeDispatchAlertNode)

    def test_does_not_register_backbone_slots(self):
        inner = DomainWorkflowGraph()
        inner.register_nodes()
        assert "initialize" not in inner._nodes
        assert "finalize" not in inner._nodes

    def test_compiles(self):
        inner = DomainWorkflowGraph()
        inner.compile()
        assert inner._compiled is not None

    def test_output_shape_has_no_fallback_between_fields(self):
        """A field blanked at the boundary must stay blank. An `or` between two
        output fields lets the blanked one be replaced by an earlier, ungated
        one — the same shape as the framework-level fallback, recreated a level
        down."""
        source = DomainWorkflowGraph.get_output.__doc__ or ""
        assert "or" not in DomainWorkflowGraph.get_output.__code__.co_names
        assert source

    def test_output_surfaces_the_alert(self):
        out = DomainWorkflowGraph().get_output({"alert_payload": "x", "status": "success"})
        assert out["alert_payload"] == "x"

    def test_route_is_annotated_with_this_graphs_state(self):
        """A path callable's annotation is read as its input schema and fields
        outside it are projected away, so a wider annotation would hide the
        fields a route depends on."""
        assert DomainWorkflowGraph.route.__annotations__["state"] is State

    def test_route_stops_on_error(self):
        assert DomainWorkflowGraph().route({"status": AgentStatus.ERROR.value}) == "__end__"


class TestSubgraphBoundary:
    def test_is_a_subgraph_node(self):
        assert issubclass(FraudDetectionGraphNode, GraphNode)

    def test_builds_the_inner_graph(self):
        assert isinstance(FraudDetectionGraphNode().get_subgraph(), DomainWorkflowGraph)

    def test_inner_failure_propagates_rather_than_merging(self):
        assert FraudDetectionGraphNode.error_strategy == "propagate"

    def test_extract_prefers_the_validated_payload(self):
        node = FraudDetectionGraphNode()
        assert node.extract_input({"validated_input": "v", "user_input": "u"}) == "v"

    def test_merge_maps_the_alert_to_both_fields(self):
        node = FraudDetectionGraphNode()
        merged = node.merge_output({}, {"alert_payload": "a", "status": "success"})
        assert merged["alert_payload"] == "a"
        assert merged["result"] == "a"

    def test_caller_channel_crosses_the_boundary(self):
        """The subgraph is invoked with a payload string and a fresh invocation
        context; the parent's caller context does not travel with it, so it is
        carried across deliberately."""
        node = FraudDetectionGraphNode()
        node.extract_input(
            {
                "validated_input": VALID_EVENT,
                "enriched_context": to_json({"source": "x", "channel": "mobile_app"}),
            }
        )
        assert caller_channel() == "mobile_app"

    def test_absent_channel_reads_as_unknown(self):
        stash_caller_context({})
        assert caller_channel() == UNKNOWN_CHANNEL

    def test_inner_graph_seeds_the_channel_into_state(self):
        stash_caller_context({"channel": "atm"})
        assert DomainWorkflowGraph()._extra_initial_state()["caller_channel"] == "atm"


class TestTrustFloor:
    """Every node requires at least the trust level the manifest publishes."""

    NODES = [
        PreProcessNode,
        PostProcessNode,
        ExtractFraudSignalsNode,
        ScoreFraudRiskNode,
        ClassifySeverityNode,
        ComposeDispatchAlertNode,
    ]

    @pytest.mark.parametrize("node", NODES)
    def test_node_declares_the_published_trust_level(self, node):
        assert node.required_trust_level is TrustLevel.VERIFIED_EXTERNAL

    def test_anonymous_caller_is_denied(self):
        agent = Graph()
        agent.compile()
        out = agent.invoke(
            VALID_EVENT,
            ctx=InvocationContext(session_id="s", caller_trust_level=TrustLevel.ANONYMOUS),
        )
        assert out["status"] == AgentStatus.ERROR.value
        assert not out["output"]

    def test_published_trust_level_is_served(self):
        """The manifest publishes this level, so a caller holding it must get an
        answer. A pipeline that demands more than the manifest publishes cannot
        serve any external caller at all."""
        agent = Graph()
        agent.compile()
        out = agent.invoke(
            VALID_EVENT,
            ctx=InvocationContext(session_id="s", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL),
        )
        assert out["status"] == AgentStatus.SUCCESS.value
        assert out["output"]
