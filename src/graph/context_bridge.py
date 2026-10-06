"""AgentCore Platform v1.0"""

# FIN-C2-064 — caller-context bridge between the outer graph and the inner one.
#
# A subgraph node hands its child graph a single string and a fresh invocation
# context; the parent's state fields do not travel with it, and neither does the
# caller context the parent was invoked with. Anything the inner pipeline needs
# beyond the payload string therefore has to be carried across deliberately.
#
# The carrier is a context variable rather than a module global: it is scoped to
# the executing task, so two concurrent invocations cannot read each other's
# caller context.
#
# Outer side: FraudDetectionGraphNode.extract_input() stashes the context.
# Inner side: DomainWorkflowGraph._extra_initial_state() seeds it into state.

from contextvars import ContextVar
from typing import Dict

_caller_context: ContextVar[Dict[str, str]] = ContextVar("fin_c2_064_caller_context", default={})

# What an alert reports when no caller channel was supplied.
UNKNOWN_CHANNEL = "unknown"


def stash_caller_context(context: Dict[str, str]) -> None:
    """Record the caller context for the inner graph invocation that follows."""
    _caller_context.set(dict(context))


def caller_context() -> Dict[str, str]:
    """Return the caller context recorded for the current invocation."""
    return dict(_caller_context.get())


def caller_channel() -> str:
    """Return the caller channel, or the placeholder when none was supplied."""
    channel = caller_context().get("channel", "")
    return channel or UNKNOWN_CHANNEL
